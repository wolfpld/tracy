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
    tracy_force_inline short_ptr( const T* ptr ) { set( ptr ); }

    tracy_force_inline operator T*() { return get(); }
    tracy_force_inline operator const T*() const { return get(); }
    tracy_force_inline T& operator*() { return *get(); }
    tracy_force_inline const T& operator*() const { return *get(); }
    tracy_force_inline T* operator->() { return get(); }
    tracy_force_inline const T* operator->() const { return get(); }

    tracy_force_inline void set( const T* ptr )
    {
        assert( ( uint64_t( ptr ) & 0xFFFF000000000000 ) == 0 );
        memcpy( m_ptr, &ptr, 4 );
        memcpy( m_ptr+4, ((char*)&ptr)+4, 2 );
    }

    tracy_force_inline T* get()
    {
        uint32_t lo;
        uint16_t hi;
        memcpy( &lo, m_ptr, 4 );
        memcpy( &hi, m_ptr+4, 2 );
        return (T*)( uint64_t( lo ) | ( ( uint64_t( hi ) << 32 ) ) );
    }

    tracy_force_inline const T* get() const
    {
        uint32_t lo;
        uint16_t hi;
        memcpy( &lo, m_ptr, 4 );
        memcpy( &hi, m_ptr+4, 2 );
        return (T*)( uint64_t( lo ) | ( ( uint64_t( hi ) << 32 ) ) );
    }

private:
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

    tracy_force_inline void set( const T* ptr ) { m_ptr = ptr; }
    tracy_force_inline T* get() { return m_ptr; }
    tracy_force_inline const T* get() const { return m_ptr; }

private:
    T* m_ptr;
};
#endif

}

#endif
