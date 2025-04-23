#include <Common/Logger.h>
#include <Common/logger_useful.h>

#include <Server/HTTP/HTTP2/HTTP2ServerConnection.h>
#include <Server/HTTP/HTTP2/HTTP2ServerParams.h>
#include "config.h"

#include <Server/HTTP/HTTP2/ReadBufferFromHTTP2Stream.h>
#include <Server/HTTP/HTTPServerRequest.h>
#include <Server/HTTP/HTTPServerResponse.h>
#include <IO/ReadBufferFromPocoSocket.h>

#include <Poco/Net/SecureServerSocket.h>
#include <Poco/Net/SecureServerSocketImpl.h>

namespace DB
{

namespace ErrorCodes
{
    extern const int NETWORK_ERROR;
}

static const std::string HTTP2_ALPN = "h2";

static unsigned char ALPN_PROTOCOLS[] = { 2, 'h', '2',};

// HTTP/2 connection preface
static const std::string HTTP2_CONNECTION_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

bool setHTTP2Alpn(const Poco::Net::SecureServerSocket & socket, HTTP2ServerParams::Ptr http2_params)
{
    if (!http2_params)
        return false;
    Poco::Net::Context::Ptr context = socket.context();
    if (!context)
        return false;
    SSL_CTX * ssl_ctx = context->sslContext();
    if (!ssl_ctx)
        return false;

    SSL_CTX_set_alpn_protos(ssl_ctx, ALPN_PROTOCOLS, sizeof(ALPN_PROTOCOLS));

    auto alpn_select_cb = [](
        SSL* /*ssl*/,
        const unsigned char** out,
        unsigned char* outlen,
        const unsigned char* in,
        unsigned int inlen,
        void* /*arg*/) -> int
    {
        int res = SSL_select_next_proto(
            const_cast<unsigned char**>(out),
            outlen,
            ALPN_PROTOCOLS,
            sizeof(ALPN_PROTOCOLS), 
            in, inlen);
        if (res == OPENSSL_NPN_NEGOTIATED)
            return SSL_TLSEXT_ERR_OK;
        return SSL_TLSEXT_ERR_NOACK;
    };
    SSL_CTX_set_alpn_select_cb(ssl_ctx, std::move(alpn_select_cb), nullptr);
    return true;
}

/// TODO:
/// Currently we only look at ALPN to determine the HTTP version
/// It would be nice to support HTTP/2 prior knowledge mechanism for non-TLS connections
/// But it will require to read some data from the socket (to check HTTP/2 preface)
/// So we will need to make HTTPServerConnection work with some buffer insted of raw socket
/// So it can process already received data
bool isHTTP2Connection(const Poco::Net::StreamSocket & socket, HTTP2ServerParams::Ptr http2_params)
{
    if (!http2_params)
        return false;
    if (!socket.secure())
        return false;
    // dynamic_cast looks like a hack but can't think of a better way
    const Poco::Net::SecureServerSocketImpl * ssocket = dynamic_cast<const Poco::Net::SecureServerSocketImpl *>(socket.impl());
    chassert(ssocket != nullptr);  // If this happens then somethinh has changed in Poco internals
    if (ssocket == nullptr)
        return false;
    std::string alpn_selected = ssocket->getAlpnSelected();
    return alpn_selected == HTTP2_ALPN;
}

// nghttp2 callbacks
namespace
{
    // Callback for sending data to the client
    ssize_t sendCallback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data)
    {
        auto *conn = static_cast<HTTP2ServerConnection *>(user_data);
        return conn->onSendCallback(data, length, flags);
    }

    // Callback for handling HTTP/2 DATA frame
    int onDataChunkRecvCallback(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data)
    {
        auto *conn = static_cast<HTTP2ServerConnection *>(user_data);
        return conn->onDataChunkRecv(flags, stream_id, data, len);
    }

    // Callback for handling HTTP/2 frame reception
    int onFrameRecvCallback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
    {
        auto *conn = static_cast<HTTP2ServerConnection *>(user_data);
        return conn->onFrameRecv(frame);
    }

    // Callback for handling HTTP/2 stream close
    int onStreamCloseCallback(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data)
    {
        auto *conn = static_cast<HTTP2ServerConnection *>(user_data);
        return conn->onStreamClose(stream_id, error_code);
    }

    // Callback for handling HTTP/2 HEADERS frame
    int onBeginHeadersCallback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
    {
        auto *conn = static_cast<HTTP2ServerConnection *>(user_data);
        return conn->onBeginHeaders(frame);
    }

    // Callback for handling header fields
    int onHeaderCallback(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data)
    {
        auto *conn = static_cast<HTTP2ServerConnection *>(user_data);
        return conn->onHeader(frame, name, namelen, value, valuelen, flags);
    }
}

HTTP2ServerConnection::HTTP2ServerConnection(
    HTTPContextPtr context_,
    TCPServer & tcp_server_,
    const Poco::Net::StreamSocket & socket_,
    HTTP2ServerParams::Ptr params_,
    HTTPRequestHandlerFactoryPtr factory_,
    const ProfileEvents::Event & read_event_,
    const ProfileEvents::Event & write_event_)
    : TCPServerConnection(socket_), context(std::move(context_)), tcp_server(tcp_server_), params(params_), factory(factory_), read_event(read_event_), write_event(write_event_), stopped(false)
{
    poco_check_ptr(factory);
    log = getLogger("HTTP2ServerConnection");
}

HTTP2ServerConnection::~HTTP2ServerConnection()
{
    if (session)
    {
        nghttp2_session_del(session);
        session = nullptr;
    }
}

void HTTP2ServerConnection::run()
{
    LOG_INFO(log, "Starting HTTP/2 connection");
    
    try
    {
        // Initialize nghttp2 session
        nghttp2_session_callbacks *callbacks;
        if (nghttp2_session_callbacks_new(&callbacks) != 0)
        {
            LOG_ERROR(log, "Failed to create nghttp2 callbacks");
            return;
        }

        // Set up callbacks
        nghttp2_session_callbacks_set_send_callback(callbacks, sendCallback);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, onDataChunkRecvCallback);
        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, onFrameRecvCallback);
        nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, onStreamCloseCallback);
        nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, onBeginHeadersCallback);
        nghttp2_session_callbacks_set_on_header_callback(callbacks, onHeaderCallback);

        // Create session
        if (nghttp2_session_server_new(&session, callbacks, this) != 0)
        {
            LOG_ERROR(log, "Failed to create nghttp2 session");
            nghttp2_session_callbacks_del(callbacks);
            return;
        }

        // Delete callbacks as they're no longer needed after session creation
        nghttp2_session_callbacks_del(callbacks);

        // Set initial settings
        nghttp2_settings_entry settings[] = {
            {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100},
            {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 1024 * 1024}, // 1MB
            {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, 16384}
        };
        
        // Submit SETTINGS frame
        if (nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, settings, sizeof(settings) / sizeof(settings[0])) != 0)
        {
            LOG_ERROR(log, "Failed to submit SETTINGS");
            return;
        }

        // Send initial SETTINGS frame
        if (nghttp2_session_send(session) != 0)
        {
            LOG_ERROR(log, "Failed to send initial SETTINGS");
            return;
        }

        // Create socket buffer
        ReadBufferFromPocoSocket socket_buffer(socket(), read_event);
        
        // Check for client preface (for HTTP/2 over clear text)
        char preface_buf[HTTP2_CONNECTION_PREFACE.length()];
        if (!socket.secure())
        {
            size_t bytes_read = socket_buffer.read(preface_buf, HTTP2_CONNECTION_PREFACE.length());
            if (bytes_read != HTTP2_CONNECTION_PREFACE.length() || 
                memcmp(preface_buf, HTTP2_CONNECTION_PREFACE.data(), HTTP2_CONNECTION_PREFACE.length()) != 0)
            {
                LOG_ERROR(log, "Invalid HTTP/2 connection preface");
                return;
            }
        }

        // Main connection loop
        while (!stopped && tcp_server.isOpen() && socket.impl()->initialized())
        {
            // Read and process data from the socket
            char buf[16384];
            size_t bytes_read = socket_buffer.read(buf, sizeof(buf));
            
            if (bytes_read == 0)
            {
                // Connection closed
                LOG_INFO(log, "HTTP/2 connection closed by client");
                break;
            }
            
            // Feed data to nghttp2
            ssize_t result = nghttp2_session_mem_recv(session, reinterpret_cast<const uint8_t *>(buf), bytes_read);
            if (result < 0)
            {
                LOG_ERROR(log, "Error processing HTTP/2 frame: {}", nghttp2_strerror(static_cast<int>(result)));
                break;
            }
            
            // Send any pending frames
            if (nghttp2_session_send(session) != 0)
            {
                LOG_ERROR(log, "Error sending HTTP/2 frames");
                break;
            }
            
            // Check if we need to terminate the session
            if (nghttp2_session_want_read(session) == 0 && nghttp2_session_want_write(session) == 0)
            {
                LOG_INFO(log, "HTTP/2 session has no more streams, terminating");
                break;
            }
            
            // Process any pending requests
            processRequests();
        }
    }
    catch (const Poco::Exception & e)
    {
        LOG_ERROR(log, "Error in HTTP/2 connection: {}", e.displayText());
    }
    catch (const std::exception & e)
    {
        LOG_ERROR(log, "Error in HTTP/2 connection: {}", e.what());
    }
    
    // Cleanup
    {
        std::lock_guard lock(mutex);
        stopped = true;
        
        // Wait for all stream threads to complete
        for (auto & [stream_id, info] : stream_info)
        {
            if (info.thread.joinable())
                info.thread.join();
        }
        
        stream_info.clear();
    }
    
    LOG_INFO(log, "HTTP/2 connection terminated");
}

ssize_t HTTP2ServerConnection::onSendCallback(const uint8_t *data, size_t length, int /*flags*/)
{
    try
    {
        socket().sendBytes(data, static_cast<int>(length));
        return static_cast<ssize_t>(length);
    }
    catch (const Poco::Exception & e)
    {
        LOG_ERROR(log, "Error sending HTTP/2 data: {}", e.displayText());
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
}

int HTTP2ServerConnection::onDataChunkRecv(uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len)
{
    LOG_TRACE(log, "Received DATA frame for stream {}, length {}, flags {:x}", stream_id, len, flags);
    
    std::lock_guard lock(mutex);
    
    auto it = stream_info.find(stream_id);
    if (it == stream_info.end())
    {
        LOG_WARNING(log, "Received DATA for unknown stream {}", stream_id);
        return 0;  // Ignore data for unknown streams
    }
    
    bool end_stream = (flags & NGHTTP2_FLAG_END_STREAM) != 0;
    
    // Add the data to the stream's buffer
    if (it->second.buffer)
        it->second.buffer->addDataFrame(data, len, end_stream);
    
    return 0;
}

int HTTP2ServerConnection::onFrameRecv(const nghttp2_frame *frame)
{
    LOG_TRACE(log, "Received frame type={} stream_id={}", frame->hd.type, frame->hd.stream_id);
    
    // Handle different frame types
    switch (frame->hd.type)
    {
        case NGHTTP2_SETTINGS:
            if (frame->hd.flags & NGHTTP2_FLAG_ACK)
                LOG_DEBUG(log, "Received SETTINGS ACK");
            break;
            
        case NGHTTP2_HEADERS:
            // Headers are handled in onHeaderCallback
            if (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS)
            {
                LOG_DEBUG(log, "End of HEADERS for stream {}", frame->hd.stream_id);
                
                // If this is also the end of the stream, process the request immediately
                if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
                {
                    std::lock_guard lock(mutex);
                    auto it = stream_info.find(frame->hd.stream_id);
                    if (it != stream_info.end() && it->second.request && !it->second.processing)
                    {
                        it->second.processing = true;
                        LOG_INFO(log, "Processing request for stream {} with no body", frame->hd.stream_id);
                        startRequestProcessing(frame->hd.stream_id);
                    }
                }
            }
            break;
            
        case NGHTTP2_RST_STREAM:
            LOG_INFO(log, "Received RST_STREAM for stream {}, error_code={}", frame->hd.stream_id, frame->rst_stream.error_code);
            break;
            
        case NGHTTP2_GOAWAY:
            LOG_INFO(log, "Received GOAWAY, last_stream_id={}, error_code={}", frame->goaway.last_stream_id, frame->goaway.error_code);
            break;
            
        case NGHTTP2_WINDOW_UPDATE:
            LOG_TRACE(log, "Received WINDOW_UPDATE for stream {}, increment={}", frame->hd.stream_id, frame->window_update.window_size_increment);
            break;
            
        default:
            LOG_TRACE(log, "Received frame of type {}", frame->hd.type);
            break;
    }
    
    return 0;
}

int HTTP2ServerConnection::onStreamClose(int32_t stream_id, uint32_t error_code)
{
    LOG_INFO(log, "Stream {} closed with error_code={}", stream_id, error_code);
    
    std::lock_guard lock(mutex);
    
    auto it = stream_info.find(stream_id);
    if (it != stream_info.end())
    {
        // Wait for the processing thread to finish
        if (it->second.thread.joinable())
            it->second.thread.join();
        
        // Remove the stream info
        stream_info.erase(it);
    }
    
    return 0;
}

int HTTP2ServerConnection::onBeginHeaders(const nghttp2_frame *frame)
{
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST)
        return 0;
    
    int32_t stream_id = frame->hd.stream_id;
    LOG_DEBUG(log, "Beginning of HEADERS for stream {}", stream_id);
    
    std::lock_guard lock(mutex);
    
    // Create a new stream info entry
    auto [it, inserted] = stream_info.emplace(stream_id, StreamInfo{});
    if (!inserted)
    {
        LOG_WARNING(log, "Stream {} already exists", stream_id);
        return 0;
    }
    
    // Create a new request
    it->second.request = std::make_unique<HTTPServerRequest>(context, it->second.response, socket());
    
    return 0;
}

int HTTP2ServerConnection::onHeader(const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, uint8_t /*flags*/)
{
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST)
        return 0;
    
    int32_t stream_id = frame->hd.stream_id;
    
    std::string header_name(reinterpret_cast<const char *>(name), namelen);
    std::string header_value(reinterpret_cast<const char *>(value), valuelen);
    
    LOG_TRACE(log, "Header for stream {}: {}={}", stream_id, header_name, header_value);
    
    std::lock_guard lock(mutex);
    
    auto it = stream_info.find(stream_id);
    if (it == stream_info.end() || !it->second.request)
    {
        LOG_WARNING(log, "Received header for unknown stream {}", stream_id);
        return 0;
    }
    
    // Special handling for pseudo-headers
    if (header_name == ":method")
    {
        it->second.request->setMethod(header_value);
    }
    else if (header_name == ":path")
    {
        it->second.request->setURI(header_value);
    }
    else if (header_name == ":scheme")
    {
        // Store for later use
        it->second.http_scheme = header_value;
    }
    else if (header_name == ":authority")
    {
        it->second.request->set("Host", header_value);
    }
    else
    {
        // Regular header
        it->second.request->add(header_name, header_value);
    }
    
    return 0;
}

void HTTP2ServerConnection::processRequests()
{
    std::lock_guard lock(mutex);
    
    for (auto & [stream_id, info] : stream_info)
    {
        // Skip streams that are already being processed
        if (info.processing)
            continue;
        
        // Check if the request is ready to be processed
        if (info.request)
        {
            bool data_complete = false;
            
            // If the stream has a buffer, check if it has received all data
            if (info.buffer)
            {
                data_complete = !info.buffer->needMoreData();
            }
            else
            {
                // No buffer means no request body, so it's complete
                data_complete = true;
            }
            
            if (data_complete)
            {
                info.processing = true;
                LOG_INFO(log, "Processing request for stream {}", stream_id);
                startRequestProcessing(stream_id);
            }
        }
    }
}

void HTTP2ServerConnection::startRequestProcessing(int32_t stream_id)
{
    std::lock_guard lock(mutex);
    
    auto it = stream_info.find(stream_id);
    if (it == stream_info.end() || !it->second.request)
    {
        LOG_WARNING(log, "Cannot start processing for unknown stream {}", stream_id);
        return;
    }
    
    // Create a buffer if needed for the request body
    if (!it->second.buffer)
    {
        it->second.buffer = std::make_unique<ReadBufferFromHTTP2Stream>(session, stream_id, 64 * 1024, read_event);
    }
    
    // Create a response object
    it->second.response = HTTPServerResponse(socket());
    
    // Get references to avoid using iterator that might be invalidated
    auto & request = it->second.request;
    auto & buffer = it->second.buffer;
    
    // Create a thread to process the request
    it->second.thread = std::thread([this, stream_id, &request, &buffer]() {
        try
        {
            LOG_DEBUG(log, "Request thread started for stream {}", stream_id);
            
            // Create a request handler for this request
            std::unique_ptr<HTTPRequestHandler> handler;
            {
                std::lock_guard lock(mutex);
                handler.reset(factory->createRequestHandler(*request));
            }
            
            if (handler)
            {
                // Set up the request body buffer
                request->setStream(buffer.get());
                
                // Handle the request
                handler->handleRequest(*request, request->response(), write_event);
            }
            else
            {
                request->response().setStatus(Poco::Net::HTTPResponse::HTTP_NOT_IMPLEMENTED);
                request->response().send();
            }
            
            LOG_DEBUG(log, "Request processing completed for stream {}", stream_id);
        }
        catch (const std::exception & e)
        {
            LOG_ERROR(log, "Error processing request for stream {}: {}", stream_id, e.what());
            
            // Try to send an error response if possible
            try
            {
                if (!request->response().sent())
                {
                    request->response().setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
                    request->response().send();
                }
            }
            catch (...)
            {
                // Ignore any errors in error handling
            }
        }
        
        // Signal nghttp2 to close the stream if it's not already closed
        {
            std::lock_guard lock(mutex);
            auto it = stream_info.find(stream_id);
            if (it != stream_info.end())
            {
                // Reset the stream to clean up resources on the client
                nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, stream_id, NGHTTP2_NO_ERROR);
                nghttp2_session_send(session);
            }
        }
    });
}

}
