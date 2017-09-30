#ifndef __TRACYFILEREAD_HPP__
#define __TRACYFILEREAD_HPP__

#include <algorithm>
#include <stdio.h>

namespace tracy
{

class FileRead
{
public:
    static FileRead* Open( const char* fn )
    {
        auto f = fopen( fn, "rb" );
        return f ? new FileRead( f ) : nullptr;
    }

    ~FileRead()
    {
        fclose( m_file );
    }

    void Read( void* ptr, size_t size )
    {
        auto dst = (char*)ptr;
        while( size > 0 )
        {
            if( m_offset == BufSize )
            {
                fread( m_buf, 1, BufSize, m_file );
                m_offset = 0;
            }

            const auto sz = std::min( size, BufSize - m_offset );
            memcpy( dst, m_buf + m_offset, sz );
            m_offset += sz;
            dst += sz;
            size -= sz;
        }
    }

private:
    FileRead( FILE* f )
        : m_file( f )
        , m_offset( BufSize )
    {}

    enum { BufSize = 64 * 1024 };

    FILE* m_file;
    char m_buf[BufSize];
    size_t m_offset;
};

}

#endif
