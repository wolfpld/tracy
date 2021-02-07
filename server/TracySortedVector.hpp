#ifndef __TRACYSORTEDVECTOR_HPP__
#define __TRACYSORTEDVECTOR_HPP__

#include "TracyVector.hpp"

namespace tracy
{

#pragma pack( 1 )
template<typename T>
class SortedVector
{
public:
    using iterator = T*;
    using const_iterator = const T*;

    tracy_force_inline SortedVector() {}

    SortedVector( const SortedVector& ) = delete;
    tracy_force_inline SortedVector( SortedVector&& src ) noexcept
        : v( std::move( src.v ) )
    {
    }

    tracy_force_inline SortedVector( const T& value )
        : v( value )
    {
    }

    SortedVector& operator=( const SortedVector& ) = delete;
    tracy_force_inline SortedVector& operator=( SortedVector&& src ) noexcept
    {
        v = std::move( src.v );
        return *this;
    }

    tracy_force_inline void swap( SortedVector& other ) { v.swap( other.v ); }

    tracy_force_inline bool empty() const { return v.empty(); }
    tracy_force_inline size_t size() const { return v.size(); }

    tracy_force_inline void set_size( size_t sz ) { v.set_size( sz ); }

    tracy_force_inline T* data() { return v.data(); }
    tracy_force_inline const T* data() const { return v.data(); };

    tracy_force_inline T* begin() { return v.begin(); }
    tracy_force_inline const T* begin() const { return v.begin(); }
    tracy_force_inline T* end() { return v.end(); }
    tracy_force_inline const T* end() const { return v.end(); }

    tracy_force_inline T& front() { return v.front(); }
    tracy_force_inline const T& front() const { return v.front(); }

    tracy_force_inline T& back() { return v.back(); }
    tracy_force_inline const T& back() const { return v.back(); }

    tracy_force_inline T& operator[]( size_t idx ) { return v[idx]; }
    tracy_force_inline const T& operator[]( size_t idx ) const { return v[idx]; }

    tracy_force_inline void push_back( const T& val ) { v.push_back( val ); }
    tracy_force_inline void push_back_non_empty( const T& val ) { v.push_back_non_empty( val ); }
    tracy_force_inline void push_back_no_space_check( const T& val ) { v.push_back_no_space_check( val ); }
    tracy_force_inline void push_back( T&& val ) { v.push_back( std::move( val ) ); }

    tracy_force_inline T& push_next() { return v.push_next(); }
    tracy_force_inline T& push_next_non_empty() { return v.push_next_non_empty(); }
    tracy_force_inline T& push_next_no_space_check() { return v.push_next_no_space_check(); }

    T* insert( T* it, const T& val ) { return v.insert( it, val ); }
    T* insert( T* it, T&& val ) { return v.insert( it, std::move( val ) ); }
    void insert( T* it, T* begin, T* end ) { v.insert( it, begin, end ); }

    T* erase( T* it ) { return v.erase( it ); }
    T* erase( T* begin, T* end ) { return v.erase( begin, end ); }

    tracy_force_inline void pop_back() { v.pop_back(); }
    tracy_force_inline T& back_and_pop() { return v.back_and_pop(); }

    tracy_force_inline void reserve( size_t cap ) { v.reserve( cap ); }
    void reserve_non_zero( size_t cap ) { v.reserve_non_zero( cap ); }
    tracy_force_inline void reserve_and_use( size_t sz ) { v.reserve_and_use( sz ); }
    template<size_t U>
    tracy_force_inline void reserve_exact( uint32_t sz, Slab<U>& slab ) { v.reserve_exact( sz, slab ); }

    tracy_force_inline void clear() { v.clear(); }

private:
    Vector<T> v;
};

#pragma pack()

enum { SortedVectorSize = sizeof( SortedVector<int> ) };

}

#endif
