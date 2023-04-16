#ifndef __TRACY__THREADCOMPRESS_HPP__
#define __TRACY__THREADCOMPRESS_HPP__

#include <assert.h>
#include <stdint.h>

#include "../public/common/TracyForceInline.hpp"
#include "tracy_robin_hood.h"
#include "TracyVector.hpp"

namespace tracy
{

class FileRead;
class FileWrite;

class ThreadCompress
{
public:
    ThreadCompress();

    void InitZero();
    void Load( FileRead& f );
    void Save( FileWrite& f ) const;

    tracy_force_inline uint16_t CompressThread( uint64_t thread )
    {
        if( m_threadLast.first == thread ) return m_threadLast.second;
        return CompressThreadReal( thread );
    }

    tracy_force_inline uint64_t DecompressThread( uint16_t thread ) const
    {
        assert( thread < m_threadExpand.size() );
        return m_threadExpand[thread];
    }

    tracy_force_inline uint16_t DecompressMustRaw( uint64_t thread ) const
    {
        auto it = m_threadMap.find( thread );
        assert( it != m_threadMap.end() );
        return it->second;
    }

    tracy_force_inline bool Exists( uint64_t thread ) const
    {
        return m_threadMap.find( thread ) != m_threadMap.end();
    }

private:
    uint16_t CompressThreadReal( uint64_t thread );
    uint16_t CompressThreadNew( uint64_t thread );

    unordered_flat_map<uint64_t, uint16_t> m_threadMap;
    Vector<uint64_t> m_threadExpand;
    std::pair<uint64_t, uint16_t> m_threadLast;
};

}

#endif
