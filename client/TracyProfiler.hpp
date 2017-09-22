#ifndef __TRACYPROFILER_HPP__
#define __TRACYPROFILER_HPP__

#include <atomic>
#include <chrono>
#include <stdint.h>
#include <thread>

#include "../common/tracy_lz4.hpp"
#include "../common/TracyQueue.hpp"

namespace tracy
{

class Socket;

static inline int64_t GetTime()
{
    return std::chrono::duration_cast<std::chrono::nanoseconds>( std::chrono::high_resolution_clock::now().time_since_epoch() ).count();
}

class Profiler
{
public:
    Profiler();
    ~Profiler();

    static uint64_t GetNewId();

    static uint64_t ZoneBegin( QueueZoneBegin&& data );
    static void ZoneEnd( uint64_t id, QueueZoneEnd&& data );
    static void FrameMark();

    static bool ShouldExit();

private:
    void Worker();

    bool SendData( const char* data, size_t len );
    bool SendString( uint64_t ptr, const char* str, QueueType type );

    bool HandleServerQuery();

    int64_t m_timeBegin;
    uint64_t m_mainThread;
    std::thread m_thread;
    std::atomic<bool> m_shutdown;
    std::atomic<uint64_t> m_id;
    std::unique_ptr<Socket> m_sock;

    LZ4_stream_t* m_stream;
    char* m_buffer;
    int m_bufferOffset;
};

};

#endif
