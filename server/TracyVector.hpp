#ifndef __TRACYVECTOR_HPP__
#define __TRACYVECTOR_HPP__

#include <assert.h>
#include <stdint.h>

#include "../common/TracyForceInline.hpp"
#include "TracyMemory.hpp"
#include "TracyPopcnt.hpp"

namespace tracy
{

#pragma pack( 1 )
template<typename T>
class Vector
{
public:
    using iterator = T*;
    using const_iterator = const T*;

    Vector()
        : m_ptr( nullptr )
        , m_size( 0 )
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
        memUsage.fetch_sub( Capacity() * sizeof( T ), std::memory_order_relaxed );
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

    tracy_force_inline bool empty() const { return m_size == 0; }
    tracy_force_inline size_t size() const { return m_size; }

    tracy_force_inline void set_size( size_t sz ) { m_size = sz; }

    tracy_force_inline T* data() { return m_ptr; }
    tracy_force_inline const T* data() const { return m_ptr; };

    tracy_force_inline T* begin() { return m_ptr; }
    tracy_force_inline const T* begin() const { return m_ptr; }
    tracy_force_inline T* end() { return m_ptr + m_size; }
    tracy_force_inline const T* end() const { return m_ptr + m_size; }

    tracy_force_inline T& front() { assert( m_size > 0 ); return m_ptr[0]; }
    tracy_force_inline const T& front() const { assert( m_size > 0 ); return m_ptr[0]; }

    tracy_force_inline T& back() { assert( m_size > 0 ); return m_ptr[m_size - 1]; }
    tracy_force_inline const T& back() const { assert( m_size > 0 ); return m_ptr[m_size - 1]; }

    tracy_force_inline T& operator[]( size_t idx ) { return m_ptr[idx]; }
    tracy_force_inline const T& operator[]( size_t idx ) const { return m_ptr[idx]; }

    tracy_force_inline void push_back( const T& v )
    {
        if( m_size == Capacity() ) AllocMore();
        m_ptr[m_size++] = v;
    }

    tracy_force_inline void push_back_non_empty( const T& v )
    {
        if( m_size == CapacityNoNullptrCheck() ) AllocMore();
        m_ptr[m_size++] = v;
    }

    tracy_force_inline void push_back_no_space_check( const T& v )
    {
        assert( m_size < Capacity() );
        m_ptr[m_size++] = v;
    }

    tracy_force_inline void push_back( T&& v )
    {
        if( m_size == Capacity() ) AllocMore();
        m_ptr[m_size++] = std::move( v );
    }

    tracy_force_inline T& push_next()
    {
        if( m_size == Capacity() ) AllocMore();
        return m_ptr[m_size++];
    }

    tracy_force_inline T& push_next_no_space_check()
    {
        assert( m_size < Capacity() );
        return m_ptr[m_size++];
    }

    T* insert( T* it, const T& v )
    {
        assert( it >= m_ptr && it <= m_ptr + m_size );
        const auto dist = it - m_ptr;
        if( m_size == Capacity() ) AllocMore();
        if( dist != m_size ) memmove( m_ptr + dist + 1, m_ptr + dist, ( m_size - dist ) * sizeof( T ) );
        m_size++;
        m_ptr[dist] = v;
        return m_ptr + dist;
    }

    T* insert( T* it, T&& v )
    {
        assert( it >= m_ptr && it <= m_ptr + m_size );
        const auto dist = it - m_ptr;
        if( m_size == Capacity() ) AllocMore();
        if( dist != m_size ) memmove( m_ptr + dist + 1, m_ptr + dist, ( m_size - dist ) * sizeof( T ) );
        m_size++;
        m_ptr[dist] = std::move( v );
        return m_ptr + dist;
    }

    void insert( T* it, T* begin, T* end )
    {
        assert( it >= m_ptr && it <= m_ptr + m_size );
        const auto sz = end - begin;
        const auto dist = it - m_ptr;
        while( m_size + sz > Capacity() ) AllocMore();
        if( dist != m_size ) memmove( m_ptr + dist + sz, m_ptr + dist, ( m_size - dist ) * sizeof( T ) );
        m_size += sz;
        memcpy( m_ptr + dist, begin, sz * sizeof( T ) );
    }

    T* erase( T* it )
    {
        assert( it >= m_ptr && it <= m_ptr + m_size );
        m_size--;
        memmove( it, it+1, m_size * sizeof( T ) );
        return it;
    }

    T* erase( T* begin, T* end )
    {
        assert( begin >= m_ptr && begin <= m_ptr + m_size );
        assert( end >= m_ptr && end <= m_ptr + m_size );
        assert( begin <= end );

        const auto dist = end - begin;
        if( dist > 0 )
        {
            memmove( begin, end, ( m_size - ( end - m_ptr ) ) * sizeof( T ) );
            m_size -= dist;
        }
        return begin;
    }

    tracy_force_inline void pop_back()
    {
        assert( m_size > 0 );
        m_size--;
    }

    tracy_force_inline T& back_and_pop()
    {
        assert( m_size > 0 );
        m_size--;
        return m_ptr[m_size];
    }

    tracy_force_inline void reserve( size_t cap )
    {
        if( cap == 0 || cap <= Capacity() ) return;
        reserve_non_zero( cap );
    }

    void reserve_non_zero( size_t cap )
    {
        cap--;
        cap |= cap >> 1;
        cap |= cap >> 2;
        cap |= cap >> 4;
        cap |= cap >> 8;
        cap |= cap >> 16;
        cap = TracyCountBits( cap );
        memUsage.fetch_add( ( ( 1 << cap ) - Capacity() ) * sizeof( T ), std::memory_order_relaxed );
        m_capacity = cap;
        Realloc();
    }

    tracy_force_inline void reserve_and_use( size_t sz )
    {
        reserve( sz );
        m_size = sz;
    }

    tracy_force_inline void clear()
    {
        m_size = 0;
    }

private:
    tracy_no_inline void AllocMore()
    {
        if( m_ptr == nullptr )
        {
            memUsage.fetch_add( sizeof( T ), std::memory_order_relaxed );
            m_ptr = new T[1];
            m_capacity = 0;
        }
        else
        {
            memUsage.fetch_add( Capacity() * sizeof( T ), std::memory_order_relaxed );
            m_capacity++;
            Realloc();
        }
    }

    void Realloc()
    {
        T* ptr = new T[CapacityNoNullptrCheck()];
        if( m_size != 0 )
        {
            memcpy( ptr, m_ptr, m_size * sizeof( T ) );
            delete[] m_ptr;
        }
        m_ptr = ptr;
    }

    tracy_force_inline uint32_t Capacity() const
    {
        return m_ptr == nullptr ? 0 : 1 << m_capacity;
    }

    tracy_force_inline uint32_t CapacityNoNullptrCheck() const
    {
        return 1 << m_capacity;
    }

    T* m_ptr;
    uint32_t m_size;
    uint8_t m_capacity;
};
#pragma pack()

}

#endif
