#ifndef __TRACYSLAB_HPP__
#define __TRACYSLAB_HPP__

#include <assert.h>
#include <vector>

#include "TracyMemory.hpp"

namespace tracy
{

template<size_t BlockSize>
class Slab
{
public:
    Slab()
        : m_ptr( new char[BlockSize] )
        , m_offset( 0 )
        , m_buffer( { m_ptr } )
        , m_usage( BlockSize )
    {
        memUsage += BlockSize;
    }

    ~Slab()
    {
        memUsage -= m_usage;
        for( auto& v : m_buffer )
        {
            delete[] v;
        }
    }

    tracy_force_inline void* AllocRaw( size_t size )
    {
        assert( size <= BlockSize );
        if( m_offset + size > BlockSize )
        {
            DoAlloc();
        }
        void* ret = m_ptr + m_offset;
        m_offset += size;
        return ret;
    }

    template<typename T>
    tracy_force_inline T* AllocInit()
    {
        const auto size = sizeof( T );
        assert( size <= BlockSize );
        if( m_offset + size > BlockSize )
        {
            DoAlloc();
        }
        void* ret = m_ptr + m_offset;
        new( ret ) T;
        m_offset += size;
        return (T*)ret;
    }

    template<typename T>
    tracy_force_inline T* AllocInit( size_t sz )
    {
        const auto size = sizeof( T ) * sz;
        assert( size <= BlockSize );
        if( m_offset + size > BlockSize )
        {
            DoAlloc();
        }
        void* ret = m_ptr + m_offset;
        T* ptr = (T*)ret;
        for( size_t i=0; i<sz; i++ )
        {
            new( ptr ) T;
            ptr++;
        }
        m_offset += size;
        return (T*)ret;
    }

    template<typename T>
    tracy_force_inline T* Alloc()
    {
        return (T*)AllocRaw( sizeof( T ) );
    }

    template<typename T>
    tracy_force_inline T* Alloc( size_t size )
    {
        return (T*)AllocRaw( sizeof( T ) * size );
    }

    tracy_force_inline void Unalloc( size_t size )
    {
        assert( size <= m_offset );
        m_offset -= size;
    }

    tracy_force_inline void* AllocBig( size_t size )
    {
        if( m_offset + size <= BlockSize )
        {
            void* ret = m_ptr + m_offset;
            m_offset += size;
            return ret;
        }
        else if( size <= BlockSize && BlockSize - m_offset <= 1024 )
        {
            DoAlloc();
            void* ret = m_ptr + m_offset;
            m_offset += size;
            return ret;
        }
        else
        {
            memUsage += size;
            m_usage += size;
            auto ret = new char[size];
            m_buffer.emplace_back( ret );
            return ret;
        }
    }

    void Reset()
    {
        if( m_buffer.size() > 1 )
        {
            memUsage -= m_usage - BlockSize;
            m_usage = BlockSize;
            for( int i=1; i<m_buffer.size(); i++ )
            {
                delete[] m_buffer[i];
            }
            m_ptr = m_buffer[0];
            m_buffer.clear();
            m_buffer.emplace_back( m_ptr );
        }
        m_offset = 0;
    }

    Slab( const Slab& ) = delete;
    Slab( Slab&& ) = delete;

    Slab& operator=( const Slab& ) = delete;
    Slab& operator=( Slab&& ) = delete;

private:
    void DoAlloc()
    {
        m_ptr = new char[BlockSize];
        m_offset = 0;
        m_buffer.emplace_back( m_ptr );
        memUsage += BlockSize;
        m_usage += BlockSize;
    }

    char* m_ptr;
    uint32_t m_offset;
    std::vector<char*> m_buffer;
    size_t m_usage;
};

}

#endif
