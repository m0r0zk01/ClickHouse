#pragma once

#include "config.h"

#include <IO/BufferWithOwnMemory.h>
#include <IO/ReadBuffer.h>
#include <Common/Exception.h>
#include <Common/logger_useful.h>
#include <Common/ProfileEvents.h>

#include <nghttp2/nghttp2.h>

#include <queue>
#include <mutex>
#include <vector>

namespace DB
{

/** Buffer for reading data from an HTTP/2 stream.
  * The HTTP/2 session thread feeds DATA frames to this buffer through addDataFrame(),
  * while the query execution thread consumes data through the standard ReadBuffer interface.
  * 
  * Flow control is managed automatically - as data is consumed, WINDOW_UPDATE frames
  * are sent to allow the client to send more data.
  */
class ReadBufferFromHTTP2Stream : public BufferWithOwnMemory<ReadBuffer>
{
public:
    ReadBufferFromHTTP2Stream(
        nghttp2_session * session,
        int32_t stream_id,
        size_t buf_size = DBMS_DEFAULT_BUFFER_SIZE,
        const ProfileEvents::Event & read_event = ProfileEvents::end());

    ~ReadBufferFromHTTP2Stream() override;

    /// Returns true if we need more DATA frames for this stream
    bool needMoreData() const;

    /// Add a DATA frame to the buffer
    void addDataFrame(const uint8_t * data, size_t length, bool end_stream);

protected:
    bool nextImpl() override;

private:
    LoggerPtr log;
    nghttp2_session * session;
    int32_t stream_id;
    
    /// Buffer for received DATA frames
    std::queue<std::vector<char>> data_frames;
    std::mutex data_frames_mutex;
    
    /// Current data frame being processed
    std::vector<char> current_frame;
    size_t current_frame_pos = 0;
    
    /// Indicates if end of stream was reached
    bool end_of_stream = false;
    
    /// Track window size to handle flow control
    ssize_t window_size = 0;
    std::mutex window_mutex;
    
    /// For profiling
    ProfileEvents::Event read_event;
    
    /// Update window size and send WINDOW_UPDATE if needed
    void updateWindowSize(size_t consumed);
};

} 