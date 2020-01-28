#ifndef __TRACYVARARRAY_HPP__
#define __TRACYVARARRAY_HPP__

#include <stdint.h>
#include <string.h>

#include "../common/TracyForceInline.hpp"
#include "TracyCharUtil.hpp"
#include "TracyEvent.hpp"
#include "TracyMemory.hpp"
#include "TracyShortPtr.hpp"

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
        CalcHash();
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
    tracy_force_inline void CalcHash();

    uint8_t m_size;
    uint32_t m_hash;
    const short_ptr<T> m_ptr;
};
#pragma pack()

enum { VarArraySize = sizeof( VarArray<int> ) };


template<typename T>
inline void VarArray<T>::CalcHash()
{
    T hash = 5381;
    for( uint8_t i=0; i<m_size; i++ )
    {
        hash = ( ( hash << 5 ) + hash ) ^ m_ptr[i];
    }
    m_hash = uint32_t( hash );
}

template<>
inline void VarArray<CallstackFrameId>::CalcHash()
{
    uint64_t hash = 5381;
    for( uint8_t i=0; i<m_size; i++ )
    {
        hash = ( ( hash << 5 ) + hash ) ^ m_ptr[i].data;
    }
    m_hash = uint32_t( hash );
}

template<typename T>
static inline bool Compare( const VarArray<T>& lhs, const VarArray<T>& rhs )
{
    if( lhs.size() != rhs.size() || lhs.get_hash() != rhs.get_hash() ) return false;
    return memcmp( lhs.data(), rhs.data(), lhs.size() * sizeof( T ) ) == 0;
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
struct VarArrayComparator
{
    bool operator()( const VarArray<T>* lhs, const VarArray<T>* rhs ) const
    {
        return Compare( *lhs, *rhs );
    }
};

}

#endif
