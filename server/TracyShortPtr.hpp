#ifndef __TRACYSHORTPTR_HPP__
#define __TRACYSHORTPTR_HPP__

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "../public/common/TracyForceInline.hpp"

namespace tracy
{

#if UINTPTR_MAX == 0xFFFFFFFFFFFFFFFF
template<typename T>
class short_ptr
{
public:
    tracy_force_inline short_ptr() {}
    tracy_force_inline short_ptr( const T* ptr ) { Set( ptr ); }

    tracy_force_inline operator T*() { return Get(); }
    tracy_force_inline operator const T*() const { return Get(); }
    tracy_force_inline T& operator*() { return *Get(); }
    tracy_force_inline const T& operator*() const { return *Get(); }
    tracy_force_inline T* operator->() { return Get(); }
    tracy_force_inline const T* operator->() const { return Get(); }

    tracy_force_inline T* get() { return Get(); }
    tracy_force_inline const T* get() const { return Get(); }

private:
    tracy_force_inline void Set( const T* ptr )
    {
        assert( ( uint64_t( ptr ) & 0xFFFF000000000000 ) == 0 );
        memcpy( m_ptr, &ptr, 4 );
        memcpy( m_ptr+4, ((char*)&ptr)+4, 2 );
    }

    tracy_force_inline T* Get()
    {
        uint32_t lo;
        uint16_t hi;
        memcpy( &lo, m_ptr, 4 );
        memcpy( &hi, m_ptr+4, 2 );
        return (T*)( uint64_t( lo ) | ( ( uint64_t( hi ) << 32 ) ) );
    }

    tracy_force_inline const T* Get() const
    {
        uint32_t lo;
        uint16_t hi;
        memcpy( &lo, m_ptr, 4 );
        memcpy( &hi, m_ptr+4, 2 );
        return (T*)( uint64_t( lo ) | ( ( uint64_t( hi ) << 32 ) ) );
    }

    uint8_t m_ptr[6];
};
#else
template<typename T>
class short_ptr
{
public:
    tracy_force_inline short_ptr() {}
    tracy_force_inline short_ptr( const T* ptr ) { memcpy( &m_ptr, &ptr, sizeof( T* ) ); }

    tracy_force_inline operator T*() { return m_ptr; }
    tracy_force_inline operator const T*() const { return m_ptr; }
    tracy_force_inline T& operator*() { return *m_ptr; }
    tracy_force_inline const T& operator*() const { return *m_ptr; }
    tracy_force_inline T* operator->() { return m_ptr; }
    tracy_force_inline const T* operator->() const { return m_ptr; }

    tracy_force_inline T* get() { return m_ptr; }
    tracy_force_inline const T* get() const { return m_ptr; }

private:
    T* m_ptr;
};
#endif

}

#endif
