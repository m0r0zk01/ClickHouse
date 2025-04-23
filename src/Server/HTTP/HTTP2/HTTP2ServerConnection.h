#pragma once

#include <Common/ProfileEvents.h>

#include <Server/HTTP/HTTP2/HTTP2ServerParams.h>
#include <Server/HTTP/HTTPContext.h>
#include <Server/HTTP/HTTPRequestHandlerFactory.h>
#include <Server/TCPServer.h>
#include "config.h"

#include <Poco/Net/SecureServerSocket.h>
#include <Poco/Net/TCPServerConnection.h>

#include <nghttp2/nghttp2.h>
#include <unordered_map>
#include <thread>
#include <memory>

namespace DB
{

// Forward declaration
class ReadBufferFromHTTP2Stream;
class HTTPServerRequest;
class HTTPServerResponse;

bool setHTTP2Alpn(const Poco::Net::SecureServerSocket & socket, HTTP2ServerParams::Ptr http2_params);

bool isHTTP2Connection(const Poco::Net::StreamSocket & socket, HTTP2ServerParams::Ptr http2_params);

class HTTP2ServerConnection : public Poco::Net::TCPServerConnection
{
public:
    HTTP2ServerConnection(
        HTTPContextPtr context,
        TCPServer & tcp_server,
        const Poco::Net::StreamSocket & socket,
        HTTP2ServerParams::Ptr params,
        HTTPRequestHandlerFactoryPtr factory,
        const ProfileEvents::Event & read_event_ = ProfileEvents::end(),
        const ProfileEvents::Event & write_event_ = ProfileEvents::end());

    HTTP2ServerConnection(
        HTTPContextPtr context_,
        TCPServer & tcp_server_,
        const Poco::Net::StreamSocket & socket_,
        HTTP2ServerParams::Ptr params_,
        HTTPRequestHandlerFactoryPtr factory_,
        const String & forwarded_for_,
        const ProfileEvents::Event & read_event_ = ProfileEvents::end(),
        const ProfileEvents::Event & write_event_ = ProfileEvents::end())
    : HTTP2ServerConnection(context_, tcp_server_, socket_, params_, factory_, read_event_, write_event_)
    {
        forwarded_for = forwarded_for_;
    }

    ~HTTP2ServerConnection() override;

    void run() override;

    // nghttp2 callbacks
    ssize_t onSendCallback(const uint8_t *data, size_t length, int flags);
    int onDataChunkRecv(uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len);
    int onFrameRecv(const nghttp2_frame *frame);
    int onStreamClose(int32_t stream_id, uint32_t error_code);
    int onBeginHeaders(const nghttp2_frame *frame);
    int onHeader(const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags);

private:
    // Stream information structure
    struct StreamInfo
    {
        std::unique_ptr<HTTPServerRequest> request;
        HTTPServerResponse response;
        std::unique_ptr<ReadBufferFromHTTP2Stream> buffer;
        std::thread thread;
        std::string http_scheme;
        bool processing = false;
    };

    // Check for requests that are ready to be processed
    void processRequests();

    // Start processing a request on a new thread
    void startRequestProcessing(int32_t stream_id);

    HTTPContextPtr context;
    TCPServer & tcp_server;
    HTTP2ServerParams::Ptr params;
    HTTPRequestHandlerFactoryPtr factory;
    String forwarded_for;
    ProfileEvents::Event read_event;
    ProfileEvents::Event write_event;
    bool stopped;
    std::mutex mutex;  // guards the |factory| with assumption that creating handlers is not thread-safe.
    
    // nghttp2 session
    nghttp2_session *session = nullptr;
    
    // Logger
    LoggerPtr log;
    
    // Map of stream IDs to their information
    std::unordered_map<int32_t, StreamInfo> stream_info;
};

}
