#include <assert.h>
#include <memory>

#include "TracyStorage.hpp"
#include "TracyUserData.hpp"
#include "TracyViewData.hpp"

namespace tracy
{

constexpr auto FileDescription = "description";
constexpr auto FileTimeline = "timeline";

enum : uint32_t { VersionTimeline = 0 };

UserData::UserData()
    : m_preserveState( false )
{
}

UserData::UserData( const char* program, uint64_t time )
    : m_program( program )
    , m_time( time )
{
    FILE* f = OpenFile( FileDescription, false );
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

    FILE* f = OpenFile( FileDescription, true );
    if( !f ) return false;

    fwrite( description, 1, sz, f );
    fclose( f );
    return true;
}

void UserData::LoadState( ViewData& data )
{
    assert( Valid() );
    FILE* f = OpenFile( FileTimeline, false );
    if( !f ) return;
    uint32_t ver;
    fread( &ver, 1, sizeof( ver ), f );
    if( ver == VersionTimeline )
    {
        fread( &data.zvStart, 1, sizeof( data.zvStart ), f );
        fread( &data.zvEnd, 1, sizeof( data.zvEnd ), f );
    }
    fclose( f );
}

void UserData::SaveState( const ViewData& data )
{
    if( !m_preserveState ) return;
    assert( Valid() );
    FILE* f = OpenFile( FileTimeline, true );
    if( !f ) return;
    uint32_t ver = VersionTimeline;
    fwrite( &ver, 1, sizeof( ver ), f );
    fwrite( &data.zvStart, 1, sizeof( data.zvStart ), f );
    fwrite( &data.zvEnd, 1, sizeof( data.zvEnd ), f );
    fclose( f );
}

void UserData::StateShouldBePreserved()
{
    m_preserveState = true;
}

FILE* UserData::OpenFile( const char* filename, bool write )
{
    const auto path = GetSavePath( m_program.c_str(), m_time, filename, write );
    if( !path ) return nullptr;
    FILE* f = fopen( path, write ? "wb" : "rb" );
    return f;
}

}
