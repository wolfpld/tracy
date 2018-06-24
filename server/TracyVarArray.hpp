#ifndef __TRACYVARARRAY_HPP__
#define __TRACYVARARRAY_HPP__

#include <stdint.h>

#include "../common/TracyForceInline.hpp"
#include "tracy_flat_hash_map.hpp"
#include "TracyCharUtil.hpp"
#include "TracyMemory.hpp"

namespace tracy
{

#pragma pack( 1 )
template<typename T>
class VarArray
{
public:
    VarArray( uint8_t size, const T* data )
        : m_size( size )
        , m_ptr( data )
    {
        T hash = 5381;
        for( uint8_t i=0; i<size; i++ )
        {
            hash = ( ( hash << 5 ) + hash ) ^ data[i];
        }
        m_hash = uint32_t( hash );
    }

    VarArray( const VarArray& ) = delete;
    VarArray( VarArray&& ) = delete;

    VarArray& operator=( const VarArray& ) = delete;
    VarArray& operator=( VarArray&& ) = delete;

    tracy_force_inline uint32_t get_hash() const { return m_hash; }

    tracy_force_inline bool empty() const { return m_size == 0; }
    tracy_force_inline uint8_t size() const { return m_size; }

    tracy_force_inline const T* data() const { return m_ptr; };

    tracy_force_inline const T* begin() const { return m_ptr; }
    tracy_force_inline const T* end() const { return m_ptr + m_size; }

    tracy_force_inline const T& front() const { assert( m_size > 0 ); return m_ptr[0]; }
    tracy_force_inline const T& back() const { assert( m_size > 0 ); return m_ptr[m_size - 1]; }

    tracy_force_inline const T& operator[]( size_t idx ) const { return m_ptr[idx]; }

private:
    uint8_t m_size;
    uint32_t m_hash;
    const T* m_ptr;
};
#pragma pack()

template<typename T>
bool Compare( const VarArray<T>& lhs, const VarArray<T>& rhs )
{
    if( lhs.size() != rhs.size() || lhs.get_hash() != rhs.get_hash() ) return false;
    const auto sz = lhs.size();
    for( uint8_t i=0; i<sz; i++ )
    {
        if( lhs[i] != rhs[i] ) return false;
    }
    return true;
}

template<typename T>
struct VarArrayHasher
{
    size_t operator()( const VarArray<T>* arr ) const
    {
        return arr->get_hash();
    }
};

template<typename T>
struct VarArrayHasherPOT : public VarArrayHasher<T>
{
    typedef tracy::power_of_two_hash_policy hash_policy;
};

template<typename T>
struct VarArrayComparator
{
    bool operator()( const VarArray<T>* lhs, const VarArray<T>* rhs ) const
    {
        return Compare( *lhs, *rhs );
    }
};

}

#endif
