#ifndef __TRACYVECTOR_HPP__
#define __TRACYVECTOR_HPP__

#include <assert.h>
#include <stdint.h>

namespace tracy
{

#if 1
template<typename T>
using Vector = std::vector<T>;
#else
template<typename T>
class Vector
{
public:
    Vector()
        : m_ptr( nullptr )
        , m_size( 0 )
        , m_capacity( 0 )
    {
    }

    ~Vector()
    {
        delete[] m_ptr;
    }

    bool empty() const { return m_size == 0; }

    T* begin() { return m_ptr; }
    const T* begin() const { return m_ptr; }
    T* end() { return m_ptr + m_size; }
    const T* end() const { return m_ptr + m_size; }

    T& back() { assert( m_size > 0 ); return m_ptr[m_size - 1]; }
    const T& back() const { assert( m_size > 0 ); return m_ptr[m_size - 1]; }

    void push_back( const T& v )
    {
        if( m_size == m_capacity ) AllocMore();
        m_ptr[m_size++] = v;
    }

    void push_back( T&& v )
    {
        if( m_size == m_capacity ) AllocMore();
        m_ptr[m_size++] = std::move( v );
    }

private:
    void AllocMore()
    {
        if( m_capacity == 0 )
        {
            m_capacity = 64;
        }
        else
        {
            m_capacity *= 2;
        }
        T* ptr = new T[m_capacity];
        memcpy( ptr, m_ptr, m_size * sizeof( T ) );
        delete[] m_ptr;
        m_ptr = ptr;
    }

    T* m_ptr;
    uint32_t m_size;
    uint32_t m_capacity;
};
#endif

}

#endif
