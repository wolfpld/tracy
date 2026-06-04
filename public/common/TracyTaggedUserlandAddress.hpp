#ifndef __TRACYTAGGEDPTR_HPP__
#define __TRACYTAGGEDPTR_HPP__

#include <stdint.h>
#include <assert.h>

#include "TracyForceInline.hpp"

namespace tracy
{

class TaggedUserlandAddress
{
    static constexpr uint64_t ptrShift = 8;
    static constexpr uint64_t highBits = 0xFF00000000000000;

public:
    TaggedUserlandAddress() = default;
    tracy_force_inline explicit TaggedUserlandAddress( uint64_t address, uint8_t tag = 0 )
    {
        assert( ( address & highBits ) == 0 );
        m_storage = ( address << ptrShift ) | tag;
    }

    tracy_force_inline uint64_t GetAddress() const { return m_storage >> ptrShift; }
    tracy_force_inline uint8_t GetTag() const { return uint8_t( m_storage & 0xFF ); }

private:
    uint64_t m_storage;
};

}

#endif
