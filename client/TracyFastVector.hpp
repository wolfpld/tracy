#ifndef __TRACYFASTVECTOR_HPP__
#define __TRACYFASTVECTOR_HPP__

#include <stddef.h>

#include "../common/TracyAlloc.hpp"
#include "../common/TracyForceInline.hpp"

namespace tracy
{

template<typename T>
class FastVector
{
public:
    using iterator = T*;
    using const_iterator = const T*;

    FastVector( size_t capacity )
        : m_ptr( (T*)tracy_malloc( sizeof( T ) * capacity ) )
        , m_size( 0 )
        , m_capacity( capacity )
    {
    }

    FastVector( const FastVector& ) = delete;
    FastVector( FastVector&& ) = delete;

    ~FastVector()
    {
        tracy_free( m_ptr );
    }

    FastVector& operator=( const FastVector& ) = delete;
    FastVector& operator=( FastVector&& ) = delete;

    bool empty() const { return m_size == 0; }
    size_t size() const { return m_size; }

    T* data() { return m_ptr; }
    const T* data() const { return m_ptr; };

    T* begin() { return m_ptr; }
    const T* begin() const { return m_ptr; }
    T* end() { return m_ptr + m_size; }
    const T* end() const { return m_ptr + m_size; }

    T& front() { assert( m_size > 0 ); return m_ptr[0]; }
    const T& front() const { assert( m_size > 0 ); return m_ptr[0]; }

    T& back() { assert( m_size > 0 ); return m_ptr[m_size - 1]; }
    const T& back() const { assert( m_size > 0 ); return m_ptr[m_size - 1]; }

    T& operator[]( size_t idx ) { return m_ptr[idx]; }
    const T& operator[]( size_t idx ) const { return m_ptr[idx]; }

    T* push_next()
    {
        T* ret;
        if( m_size == m_capacity ) AllocMore();
        ret = m_ptr + m_size;
        m_size++;
        return ret;
    }

    void clear()
    {
        m_size = 0;
    }

private:
    tracy_no_inline void AllocMore()
    {
        m_capacity *= 2;
        T* ptr = (T*)tracy_malloc( sizeof( T ) * m_capacity );
        memcpy( ptr, m_ptr, m_size * sizeof( T ) );
        tracy_free( m_ptr );
        m_ptr = ptr;
    }

    T* m_ptr;
    size_t m_size;
    size_t m_capacity;
};

}

#endif
