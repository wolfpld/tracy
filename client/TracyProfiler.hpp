#ifndef __TRACYPROFILER_HPP__
#define __TRACYPROFILER_HPP__

#include <atomic>
#include <chrono>
#include <stdint.h>
#include <thread>

#include "../common/tracy_lz4.hpp"
#include "../common/TracyQueue.hpp"

#if defined _MSC_VER || defined __CYGWIN__
#  include <intrin.h>
#endif

namespace tracy
{

class Socket;

struct SourceLocation
{
    const char* function;
    const char* file;
    uint32_t line;
    uint32_t color;
};

class Profiler
{
public:
    Profiler();
    ~Profiler();

    static int64_t GetTime( int8_t& cpu )
    {
#if defined _MSC_VER || defined __CYGWIN__
        unsigned int ui;
        const auto t = int64_t( __rdtscp( &ui ) );
        cpu = (int8_t)ui;
        return t;
#else
        cpu = -1;
        return std::chrono::duration_cast<std::chrono::nanoseconds>( std::chrono::high_resolution_clock::now().time_since_epoch() ).count();
#endif
    }

    static QueueItem* StartItem();
    static void FinishItem();
    static uint64_t GetNewId();

    static void FrameMark();

    static bool ShouldExit();

private:
    void Worker();

    bool SendData( const char* data, size_t len );
    bool SendString( uint64_t ptr, const char* str, QueueType type );
    void SendSourceLocation( uint64_t ptr );

    bool HandleServerQuery();

    void CalibrateTimer();
    void CalibrateDelay();

    double m_timerMul;
    uint64_t m_resolution;
    uint64_t m_delay;
    int64_t m_timeBegin;
    uint64_t m_mainThread;
    std::thread m_thread;
    std::atomic<bool> m_shutdown;
    std::unique_ptr<Socket> m_sock;

    LZ4_stream_t* m_stream;
    char* m_buffer;
    int m_bufferOffset;
};

};

#endif
