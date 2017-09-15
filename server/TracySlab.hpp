#ifndef __TRACYSLAB_HPP__
#define __TRACYSLAB_HPP__

#include <assert.h>
#include <vector>

namespace tracy
{

template<size_t BlockSize>
class Slab
{
public:
    Slab()
        : m_ptr( new char[BlockSize] )
        , m_buffer( { m_ptr } )
        , m_offset( 0 )
    {}

    ~Slab()
    {
        for( auto& v : m_buffer )
        {
            delete[] v;
        }
    }

    void* Alloc( size_t size )
    {
        assert( size <= BlockSize );
        if( m_offset + size > BlockSize )
        {
            m_ptr = new char[BlockSize];
            m_offset = 0;
            m_buffer.emplace_back( m_ptr );
        }
        void* ret = m_ptr + m_offset;
        m_offset += size;
        return ret;
    }

    void Unalloc( size_t size )
    {
        assert( size <= m_offset );
        m_offset -= size;
    }

    void Reset()
    {
        if( m_buffer.size() > 1 )
        {
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
    char* m_ptr;
    size_t m_offset;
    std::vector<char*> m_buffer;
};

}

#endif
