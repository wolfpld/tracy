#ifndef __TRACYFILEWRITE_HPP__
#define __TRACYFILEWRITE_HPP__

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
        fclose( m_file );
    }

    void Write( const void* ptr, size_t size )
    {
        fwrite( ptr, 1, size, m_file );
    }

private:
    FileWrite( FILE* f ) : m_file( f ) {}

    FILE* m_file;
};

}

#endif
