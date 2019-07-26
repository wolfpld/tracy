#include <assert.h>
#include <memory>
#include <stdio.h>

#include "TracyStorage.hpp"
#include "TracyUserData.hpp"

namespace tracy
{

constexpr auto FileDescription = "description";

UserData::UserData()
{
}

UserData::UserData( const char* program, uint64_t time )
    : m_program( program )
    , m_time( time )
{
    const auto descpath = GetSavePath( m_program.c_str(), m_time, FileDescription, false );
    if( descpath )
    {
        FILE* f = fopen( descpath, "rb" );
        if( f )
        {
            fseek( f, 0, SEEK_END );
            const auto sz = ftell( f );
            fseek( f, 0, SEEK_SET );
            auto buf = std::make_unique<char[]>( sz );
            fread( buf.get(), 1, sz, f );
            fclose( f );
            m_description.assign( buf.get(), buf.get() + sz );
        }
    }
}

void UserData::Init( const char* program, uint64_t time )
{
    assert( !Valid() );
    m_program = program;
    m_time = time;
}

bool UserData::SetDescription( const char* description )
{
    assert( Valid() );

    m_description = description;
    const auto sz = m_description.size();

    const auto path = GetSavePath( m_program.c_str(), m_time, FileDescription, true );
    if( !path ) return false;

    FILE* f = fopen( path, "wb" );
    if( !f ) return false;

    fwrite( description, 1, sz, f );
    fclose( f );
    return true;
}

}
