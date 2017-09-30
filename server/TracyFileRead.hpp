#ifndef __TRACYFILEREAD_HPP__
#define __TRACYFILEREAD_HPP__

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

    size_t Read( void* ptr, size_t size )
    {
        return fread( ptr, 1, size, m_file );
    }

private:
    FileRead( FILE* f ) : m_file( f ) {}

    FILE* m_file;
};

}

#endif
