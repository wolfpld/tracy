#ifndef __TRACYVECTOR_HPP__
#define __TRACYVECTOR_HPP__

#include <algorithm>
#include <assert.h>
#include <limits>
#include <stdint.h>
#include <stdlib.h>
#include <type_traits>

#include "../public/common/TracyForceInline.hpp"
#include "TracyMemory.hpp"
#include "TracyPopcnt.hpp"
#include "TracyShortPtr.hpp"
#include "TracySlab.hpp"

//#define TRACY_VECTOR_DEBUG

namespace tracy
{

#pragma pack( push, 1 )
template<typename T>
class Vector
{
    constexpr uint8_t MaxCapacity() { return 0x7F; }

public:
    using iterator = T*;
    using const_iterator = const T*;

    tracy_force_inline Vector()
    {
        memset( (char*)this, 0, sizeof( Vector<T> ) );
    }

    Vector( const Vector& ) = delete;
    tracy_force_inline Vector( Vector&& src ) noexcept
    {
        memcpy( (char*)this, &src, sizeof( Vector<T> ) );
        memset( (char*)&src, 0, sizeof( Vector<T> ) );
    }

    tracy_force_inline Vector( const T& value )
        : m_ptr( (T*)malloc( sizeof( T ) ) )
        , m_size( 1 )
        , m_capacity( 0 )
        , m_magic( 0 )
    {
        memUsage += sizeof( T );
        new(m_ptr) T( value );
    }

    tracy_force_inline ~Vector()
    {
        if( m_capacity != MaxCapacity() && m_ptr )
        {
            memUsage -= Capacity() * sizeof( T );
            free( m_ptr );
        }
    }

    Vector& operator=( const Vector& ) = delete;
    tracy_force_inline Vector& operator=( Vector&& src ) noexcept
    {
        if( m_capacity != MaxCapacity() && m_ptr )
        {
            memUsage -= Capacity() * sizeof( T );
            free( m_ptr );
        }
        memcpy( (char*)this, &src, sizeof( Vector<T> ) );
        memset( (char*)&src, 0, sizeof( Vector<T> ) );
        return *this;
    }

    tracy_force_inline void swap( Vector& other )
    {
        uint8_t tmp[sizeof( Vector<T> )];
        memcpy( (char*)tmp, &other, sizeof( Vector<T> ) );
        memcpy( (char*)&other, this, sizeof( Vector<T> ) );
        memcpy( (char*)this, tmp, sizeof( Vector<T> ) );
    }

    tracy_force_inline bool empty() const { return m_size == 0; }
    tracy_force_inline size_t size() const { return m_size; }

    tracy_force_inline void set_size( size_t sz ) { assert( m_capacity != MaxCapacity() ); m_size = sz; }

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
        assert( m_capacity != MaxCapacity() );
        if( m_size == Capacity() ) AllocMore();
        new(m_ptr+m_size) T( v );
        m_size++;
    }

    tracy_force_inline void push_back_non_empty( const T& v )
    {
        assert( m_capacity != MaxCapacity() );
        assert( m_ptr );
        if( m_size == CapacityNoNullptrCheck() ) AllocMore();
        new(m_ptr+m_size) T( v );
        m_size++;
    }

    tracy_force_inline void push_back_no_space_check( const T& v )
    {
        assert( m_capacity != MaxCapacity() );
        assert( m_size < Capacity() );
        new(m_ptr+m_size) T( v );
        m_size++;
    }

    tracy_force_inline void push_back( T&& v )
    {
        assert( m_capacity != MaxCapacity() );
        if( m_size == Capacity() ) AllocMore();
        new(m_ptr+m_size) T( std::move( v ) );
        m_size++;
    }

    tracy_force_inline T& push_next()
    {
        assert( m_capacity != MaxCapacity() );
        if( m_size == Capacity() ) AllocMore();
        new(m_ptr+m_size) T();
        return m_ptr[m_size++];
    }

    tracy_force_inline T& push_next_non_empty()
    {
        assert( m_capacity != MaxCapacity() );
        assert( m_ptr );
        if( m_size == CapacityNoNullptrCheck() ) AllocMore();
        new(m_ptr+m_size) T();
        return m_ptr[m_size++];
    }

    tracy_force_inline T& push_next_no_space_check()
    {
        assert( m_capacity != MaxCapacity() );
        assert( m_size < Capacity() );
        new(m_ptr+m_size) T();
        return m_ptr[m_size++];
    }

    T* insert( T* it, const T& v )
    {
        assert( m_capacity != MaxCapacity() );
        assert( it >= m_ptr && it <= m_ptr + m_size );
        const auto dist = it - m_ptr;
        if( m_size == Capacity() ) AllocMore();
        if( dist != m_size ) memmove( m_ptr + dist + 1, m_ptr + dist, ( m_size - dist ) * sizeof( T ) );
        m_size++;
        new(m_ptr+dist) T( v );
        m_ptr[dist] = v;
        return m_ptr + dist;
    }

    T* insert( T* it, T&& v )
    {
        assert( m_capacity != MaxCapacity() );
        assert( it >= m_ptr && it <= m_ptr + m_size );
        const auto dist = it - m_ptr;
        if( m_size == Capacity() ) AllocMore();
        if( dist != m_size ) memmove( m_ptr + dist + 1, m_ptr + dist, ( m_size - dist ) * sizeof( T ) );
        m_size++;
        new(m_ptr+dist) T( std::move( v ) );
        return m_ptr + dist;
    }

    void insert( T* it, T* begin, T* end )
    {
        assert( m_capacity != MaxCapacity() );
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
        assert( m_capacity != MaxCapacity() );
        assert( it >= m_ptr && it <= m_ptr + m_size );
        m_size--;
        memmove( it, it+1, ( m_size - ( it - m_ptr ) ) * sizeof( T ) );
        return it;
    }

    T* erase( T* begin, T* end )
    {
        assert( m_capacity != MaxCapacity() );
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
        assert( m_capacity != MaxCapacity() );
        assert( m_size > 0 );
        m_size--;
    }

    tracy_force_inline T& back_and_pop()
    {
        assert( m_capacity != MaxCapacity() );
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
        assert( m_capacity != MaxCapacity() );
        cap--;
        cap |= cap >> 1;
        cap |= cap >> 2;
        cap |= cap >> 4;
        cap |= cap >> 8;
        cap |= cap >> 16;
        cap = TracyCountBits( cap );
        memUsage += ( ( 1 << cap ) - Capacity() ) * sizeof( T );
        m_capacity = cap;
        Realloc();
    }

    tracy_force_inline void reserve_and_use( size_t sz )
    {
        assert( m_capacity != MaxCapacity() );
        reserve( sz );
        m_size = sz;
    }

    template<size_t U>
    tracy_force_inline void reserve_exact( uint32_t sz, Slab<U>& slab )
    {
        assert( !m_ptr );
        m_capacity = MaxCapacity();
        m_size = sz;
        m_ptr = (T*)slab.AllocBig( sizeof( T ) * sz );
    }

    tracy_force_inline void clear()
    {
        assert( m_capacity != MaxCapacity() );
        m_size = 0;
    }

    tracy_force_inline bool is_magic() const { return m_magic; }
    tracy_force_inline void set_magic() { assert( !m_magic ); m_magic = 1; }

private:
    tracy_no_inline void AllocMore()
    {
        assert( m_capacity != MaxCapacity() );

        if( m_ptr == nullptr )
        {
            memUsage += sizeof( T );
            m_ptr = (T*)malloc( sizeof( T ) );
            m_capacity = 0;
        }
        else
        {
            memUsage += Capacity() * sizeof( T );
            m_capacity++;
            Realloc();
        }
    }

    void Realloc()
    {
        T* ptr = (T*)malloc( sizeof( T ) * CapacityNoNullptrCheck() );
        if( m_size != 0 )
        {
            if( std::is_trivially_copyable<T>() )
            {
                memcpy( (char*)ptr, m_ptr, m_size * sizeof( T ) );
            }
            else
            {
                for( uint32_t i=0; i<m_size; i++ )
                {
                    new(ptr+i) T( std::move( m_ptr[i] ) );
                }
            }
            free( m_ptr );
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

#ifdef TRACY_VECTOR_DEBUG
    T* m_ptr;
#else
    short_ptr<T> m_ptr;
#endif
    uint32_t m_size;
    uint8_t m_capacity : 7;
    uint8_t m_magic : 1;
};


template<typename T> struct VectorAdapterDirect { const T& operator()( const T& it ) const { return it; } };
template<typename T> struct VectorAdapterPointer { const T& operator()( const short_ptr<T>& it ) const { return *it; } };

#pragma pack( pop )

enum { VectorSize = sizeof( Vector<int> ) };

}

#endif
