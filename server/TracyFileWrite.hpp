#ifndef __TRACYFILEWRITE_HPP__
#define __TRACYFILEWRITE_HPP__

#include <algorithm>
#include <stdio.h>

namespace tracy
{

class FileWrite
{
public:
    static FileWrite* Open( const char* fn )
    {
        auto f = fopen( fn, "wb" );
        return f ? new FileWrite( f ) : nullptr;
    }

    ~FileWrite()
    {
        if( m_offset > 0 )
        {
            fwrite( m_buf, 1, m_offset, m_file );
        }
        fclose( m_file );
    }

    void Write( const void* ptr, size_t size )
    {
        if( m_offset + size <= BufSize )
        {
            memcpy( m_buf + m_offset, ptr, size );
            m_offset += size;
        }
        else
        {
            auto src = (const char*)ptr;
            while( size > 0 )
            {
                const auto sz = std::min( size, BufSize - m_offset );
                memcpy( m_buf + m_offset, src, sz );
                m_offset += sz;
                src += sz;
                size -= sz;

                if( m_offset == BufSize )
                {
                    fwrite( m_buf, 1, BufSize, m_file );
                    m_offset = 0;
                }
            }
        }
    }

private:
    FileWrite( FILE* f )
        : m_file( f )
        , m_offset( 0 )
    {}

    enum { BufSize = 64 * 1024 };

    FILE* m_file;
    char m_buf[BufSize];
    size_t m_offset;
};

}

#endif
