#ifndef __TRACYVECTOR_HPP__
#define __TRACYVECTOR_HPP__

#include <assert.h>
#include <stdint.h>

#include "TracyMemory.hpp"

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

    Vector( const Vector& ) = delete;
    Vector( Vector&& src )
        : m_ptr( src.m_ptr )
        , m_size( src.m_size )
        , m_capacity( src.m_capacity )
    {
        src.m_ptr = nullptr;
    }

    ~Vector()
    {
        memUsage.fetch_sub( m_capacity * sizeof( T ), std::memory_order_relaxed );
        delete[] m_ptr;
    }

    Vector& operator=( const Vector& ) = delete;
    Vector& operator=( Vector&& src )
    {
        delete[] m_ptr;
        m_ptr = src.m_ptr;
        m_size = src.m_size;
        m_capacity = src.m_capacity;
        src.m_ptr = nullptr;
        return *this;
    }

    bool empty() const { return m_size == 0; }
    size_t size() const { return m_size; }

    T* begin() { return m_ptr; }
    const T* begin() const { return m_ptr; }
    T* end() { return m_ptr + m_size; }
    const T* end() const { return m_ptr + m_size; }

    T& back() { assert( m_size > 0 ); return m_ptr[m_size - 1]; }
    const T& back() const { assert( m_size > 0 ); return m_ptr[m_size - 1]; }

    T& operator[]( size_t idx ) { return m_ptr[idx]; }
    const T& operator[]( size_t idx ) const { return m_ptr[idx]; }

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

    void insert( T* it, const T& v )
    {
        assert( it >= m_ptr && it <= m_ptr + m_size );
        if( m_size == m_capacity ) AllocMore();
        if( it != m_ptr + m_size ) memmove( it+1, it, ( m_size - ( it - m_ptr ) ) * sizeof( T ) );
        m_size++;
        *it = v;
    }

    void insert( T* it, T&& v )
    {
        assert( it >= m_ptr && it <= m_ptr + m_size );
        if( m_size == m_capacity ) AllocMore();
        if( it != m_ptr + m_size ) memmove( it+1, it, ( m_size - ( it - m_ptr ) ) * sizeof( T ) );
        m_size++;
        *it = std::move( v );
    }

private:
    void AllocMore()
    {
        if( m_capacity == 0 )
        {
            m_capacity = 64;
            memUsage.fetch_add( m_capacity * sizeof( T ), std::memory_order_relaxed );
        }
        else
        {
            memUsage.fetch_add( m_capacity * sizeof( T ), std::memory_order_relaxed );
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
