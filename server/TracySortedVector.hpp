#ifndef __TRACYSORTEDVECTOR_HPP__
#define __TRACYSORTEDVECTOR_HPP__

#include "TracySort.hpp"
#include "TracyVector.hpp"

namespace tracy
{

#pragma pack( push, 1 )
template<typename T, class CompareDefault = std::less<T>>
class SortedVector
{
public:
    using iterator = T*;
    using const_iterator = const T*;

    tracy_force_inline SortedVector()
        : sortedEnd( 0 )
    {}

    SortedVector( const SortedVector& ) = delete;
    tracy_force_inline SortedVector( SortedVector&& src ) noexcept
        : v( std::move( src.v ) )
        , sortedEnd( src.sortedEnd )
    {
    }

    tracy_force_inline SortedVector( const T& value )
        : v( value )
        , sortedEnd( 0 )
    {
    }

    SortedVector& operator=( const SortedVector& ) = delete;
    tracy_force_inline SortedVector& operator=( SortedVector&& src ) noexcept
    {
        v = std::move( src.v );
        sortedEnd = src.sortedEnd;
        return *this;
    }

    tracy_force_inline void swap( SortedVector& other )
    {
        v.swap( other.v );
        std::swap( sortedEnd, other.sortedEnd );
    }

    tracy_force_inline bool empty() const { return v.empty(); }
    tracy_force_inline size_t size() const { return v.size(); }
    tracy_force_inline bool is_sorted() const { return sortedEnd == 0; }

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

    tracy_force_inline void push_back( const T& val ) { push_back( val, CompareDefault() ); }

    template<class Compare>
    tracy_force_inline void push_back( const T& val, Compare comp )
    {
        if( sortedEnd == 0 && !v.empty() && !comp( v.back(), val ) )
        {
            sortedEnd = (uint32_t)v.size();
        }
        v.push_back( val );
    }

    tracy_force_inline void reserve( size_t cap ) { v.reserve( cap ); }
    template<size_t U>
    tracy_force_inline void reserve_exact( uint32_t sz, Slab<U>& slab ) { v.reserve_exact( sz, slab ); }

    tracy_force_inline void clear() { v.clear(); sortedEnd = 0; }

    tracy_force_inline T* erase( T* begin, T* end )
    {
        assert( is_sorted() );
        return v.erase( begin, end );
    }

    tracy_force_inline void sort() { sort( CompareDefault() ); }
    tracy_force_inline void ensure_sorted() { if( !is_sorted() ) sort(); }

    template<class Compare>
    void sort( Compare comp )
    {
        assert( !is_sorted() );
        const auto sb = v.begin();
        const auto se = sb + sortedEnd;
        const auto sl = se - 1;
        const auto ue = v.end();
#ifdef NO_PARALLEL_SORT
        pdqsort_branchless( se, ue, comp );
#else
        std::sort( std::execution::par_unseq, se, ue, comp );
#endif
        const auto ss = std::lower_bound( sb, se, *se, comp );
        const auto uu = std::lower_bound( se, ue, *sl, comp );
        std::inplace_merge( ss, se, uu, comp );
        sortedEnd = 0;
    }

private:
    Vector<T> v;
    uint32_t sortedEnd;
};

#pragma pack( pop )

enum { SortedVectorSize = sizeof( SortedVector<int> ) };

}

#endif
