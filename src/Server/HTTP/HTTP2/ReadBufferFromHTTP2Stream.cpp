#include <Server/HTTP/HTTP2/ReadBufferFromHTTP2Stream.h>

#include "config.h"

namespace DB
{

namespace ErrorCodes
{
    extern const int NETWORK_ERROR;
}

ReadBufferFromHTTP2Stream::ReadBufferFromHTTP2Stream(
    nghttp2_session * session_,
    int32_t stream_id_,
    size_t buf_size,
    const ProfileEvents::Event & read_event_)
    : BufferWithOwnMemory<ReadBuffer>(buf_size)
    , log(getLogger("ReadBufferFromHTTP2Stream"))
    , session(session_)
    , stream_id(stream_id_)
    , window_size(buf_size)  // Initial window size same as buffer size
    , read_event(read_event_)
{
    LOG_DEBUG(log, "Created ReadBufferFromHTTP2Stream for stream {}", stream_id);
}

ReadBufferFromHTTP2Stream::~ReadBufferFromHTTP2Stream()
{
    LOG_TRACE(log, "Destroying ReadBufferFromHTTP2Stream for stream {}", stream_id);
}

bool ReadBufferFromHTTP2Stream::needMoreData() const
{
    std::lock_guard<std::mutex> lock(data_frames_mutex);
    return !end_of_stream && data_frames.empty() && current_frame_pos >= current_frame.size();
}

void ReadBufferFromHTTP2Stream::addDataFrame(const uint8_t * data, size_t length, bool end_stream_)
{
    if (length == 0 && !end_stream_)
        return; // Skip empty non-terminating frames

    LOG_TRACE(log, "Adding DATA frame to stream {} with length {} and end_stream={}", stream_id, length, end_stream_);

    std::lock_guard<std::mutex> lock(data_frames_mutex);
    
    if (length > 0)
    {
        // Create a new data frame and copy the data
        std::vector<char> frame(length);
        memcpy(frame.data(), data, length);
        data_frames.push(std::move(frame));
    }
    
    if (end_stream_)
        end_of_stream = true;
}

bool ReadBufferFromHTTP2Stream::nextImpl()
{
    // If we've reached the end of the stream and no data left, return false
    if (end_of_stream && data_frames.empty() && current_frame_pos >= current_frame.size())
        return false;
    
    // If we're in the middle of processing a frame, continue with it
    if (current_frame_pos < current_frame.size())
    {
        // Calculate how much data we can copy from the current frame
        size_t bytes_to_copy = std::min(
            current_frame.size() - current_frame_pos,
            internal_buffer.size());
        
        // Copy data from current_frame to internal_buffer
        memcpy(internal_buffer.begin(), current_frame.data() + current_frame_pos, bytes_to_copy);
        current_frame_pos += bytes_to_copy;
        
        // Set the working buffer to the data we just copied
        working_buffer = Buffer(internal_buffer.begin(), internal_buffer.begin() + bytes_to_copy);
        
        // Update flow control window
        updateWindowSize(bytes_to_copy);
        
        if (read_event != ProfileEvents::end())
            ProfileEvents::increment(read_event, bytes_to_copy);
        
        return true;
    }
    
    // We've finished with the current frame, get the next one if available
    {
        std::lock_guard<std::mutex> lock(data_frames_mutex);
        
        if (data_frames.empty())
        {
            // No data available right now
            if (end_of_stream)
            {
                LOG_TRACE(log, "End of stream reached for stream {}", stream_id);
                return false;  // End of stream reached
            }
            
            // Signal that we need more data for this stream
            LOG_TRACE(log, "No more data frames available for stream {}, waiting for more", stream_id);
            working_buffer = Buffer(internal_buffer.begin(), internal_buffer.begin());
            return false;
        }
        
        // Get the next frame
        current_frame = std::move(data_frames.front());
        data_frames.pop();
        current_frame_pos = 0;
        
        LOG_TRACE(log, "Moving to next DATA frame for stream {}, size: {}", stream_id, current_frame.size());
    }
    
    // Recursively call nextImpl to process the new frame
    return nextImpl();
}

void ReadBufferFromHTTP2Stream::updateWindowSize(size_t consumed)
{
    if (consumed == 0)
        return;

    std::lock_guard<std::mutex> lock(window_mutex);
    
    // Every time we consume data, we need to update our window size and send WINDOW_UPDATE frames when needed
    window_size -= consumed;
    
    // If we've consumed enough data (half the window), send a WINDOW_UPDATE
    const size_t window_update_threshold = internal_buffer.size() / 2;
    
    if (window_size <= window_update_threshold)
    {
        LOG_TRACE(log, "Sending WINDOW_UPDATE for stream {} with increment {}", stream_id, consumed);
        
        // Update stream-level window
        int result = nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, stream_id, consumed);
        if (result != 0)
        {
            LOG_ERROR(log, "Error submitting stream WINDOW_UPDATE: {}", nghttp2_strerror(result));
            throw Exception(ErrorCodes::NETWORK_ERROR, "Error submitting HTTP/2 WINDOW_UPDATE: {}", nghttp2_strerror(result));
        }
        
        // Update connection-level window
        result = nghttp2_submit_window_update(session, NGHTTP2_FLAG_NONE, 0, consumed);
        if (result != 0)
        {
            LOG_ERROR(log, "Error submitting connection WINDOW_UPDATE: {}", nghttp2_strerror(result));
            throw Exception(ErrorCodes::NETWORK_ERROR, "Error submitting HTTP/2 WINDOW_UPDATE: {}", nghttp2_strerror(result));
        }
        
        window_size += consumed;
    }
}

} 