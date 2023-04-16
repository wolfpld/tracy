#include <limits>

#include "TracyFileRead.hpp"
#include "TracyFileWrite.hpp"
#include "TracyThreadCompress.hpp"

namespace tracy
{

ThreadCompress::ThreadCompress()
    : m_threadLast( std::numeric_limits<uint64_t>::max(), 0 )
{
}

void ThreadCompress::InitZero()
{
    assert( m_threadExpand.empty() );
    m_threadExpand.push_back( 0 );
}

void ThreadCompress::Load( FileRead& f )
{
    assert( m_threadExpand.empty() );
    assert( m_threadMap.empty() );

    uint64_t sz;
    f.Read( sz );
    if( sz != 0 )
    {
        m_threadExpand.reserve_and_use( sz );
        f.Read( m_threadExpand.data(), sizeof( uint64_t ) * sz );
        m_threadMap.reserve( sz );
        for( size_t i=0; i<sz; i++ )
        {
            m_threadMap.emplace( m_threadExpand[i], i );
        }
    }
}

void ThreadCompress::Save( FileWrite& f ) const
{
    uint64_t sz = m_threadExpand.size();
    f.Write( &sz, sizeof( sz ) );
    if( sz != 0 ) f.Write( m_threadExpand.data(), sz * sizeof( uint64_t ) );
}

uint16_t ThreadCompress::CompressThreadReal( uint64_t thread )
{
    auto it = m_threadMap.find( thread );
    if( it != m_threadMap.end() )
    {
        m_threadLast.first = thread;
        m_threadLast.second = it->second;
        return it->second;
    }
    else
    {
        return CompressThreadNew( thread );
    }
}

uint16_t ThreadCompress::CompressThreadNew( uint64_t thread )
{
    auto sz = m_threadExpand.size();
    m_threadExpand.push_back( thread );
    m_threadMap.emplace( thread, sz );
    m_threadLast.first = thread;
    m_threadLast.second = sz;
    return sz;
}

}
