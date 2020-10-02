#ifdef _WIN32
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <sys/socket.h>
#  include <netdb.h>
#endif

#include "ResolvService.hpp"

ResolvService::ResolvService( uint16_t port )
    : m_exit( false )
    , m_port( port )
    , m_thread( [this] { Worker(); } )
{
}

ResolvService::~ResolvService()
{
    m_exit.store( true, std::memory_order_relaxed );
    m_cv.notify_one();
    m_thread.join();
}

void ResolvService::Query( uint32_t ip, const std::function<void(std::string&&)>& callback )
{
    std::lock_guard<std::mutex> lock( m_lock );
    m_queue.emplace_back( QueueItem { ip, callback } );
    m_cv.notify_one();
}

void ResolvService::Worker()
{
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons( m_port );

    char buf[128];

    for(;;)
    {
        std::unique_lock<std::mutex> lock( m_lock );
        m_cv.wait( lock, [this] { return !m_queue.empty() || m_exit.load( std::memory_order_relaxed ); } );
        if( m_exit.load( std::memory_order_relaxed ) ) return;
        auto query = m_queue.back();
        m_queue.pop_back();
        lock.unlock();

        addr.sin_addr.s_addr = query.ip;
        if( getnameinfo( (const struct sockaddr*)&addr, sizeof( sockaddr_in ), buf, 128, nullptr, 0, NI_NOFQDN ) != 0 )
        {
            inet_ntop( AF_INET, &query.ip, buf, 17 );
        }
        query.callback( buf );
    }
}
