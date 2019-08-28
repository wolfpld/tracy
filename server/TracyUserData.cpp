#include <assert.h>
#include <memory>

#include "TracyStorage.hpp"
#include "TracyUserData.hpp"
#include "TracyViewData.hpp"

namespace tracy
{

constexpr auto FileDescription = "description";
constexpr auto FileTimeline = "timeline";
constexpr auto FileOptions = "options";

enum : uint32_t { VersionTimeline = 0 };
enum : uint32_t { VersionOptions = 0 };

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
    if( f )
    {
        uint32_t ver;
        fread( &ver, 1, sizeof( ver ), f );
        if( ver == VersionTimeline )
        {
            fread( &data.zvStart, 1, sizeof( data.zvStart ), f );
            fread( &data.zvEnd, 1, sizeof( data.zvEnd ), f );
            fread( &data.zvHeight, 1, sizeof( data.zvHeight ), f );
            fread( &data.zvScroll, 1, sizeof( data.zvScroll ), f );
            fread( &data.frameScale, 1, sizeof( data.frameScale ), f );
            fread( &data.frameStart, 1, sizeof( data.frameStart ), f );
        }
        fclose( f );
    }

    f = OpenFile( FileOptions, false );
    if( f )
    {
        uint32_t ver;
        fread( &ver, 1, sizeof( ver ), f );
        if( ver == VersionOptions )
        {
            fread( &data.drawGpuZones, 1, sizeof( data.drawGpuZones ), f );
            fread( &data.drawZones, 1, sizeof( data.drawZones ), f );
            fread( &data.drawLocks, 1, sizeof( data.drawLocks ), f );
            fread( &data.drawPlots, 1, sizeof( data.drawPlots ), f );
            fread( &data.onlyContendedLocks, 1, sizeof( data.onlyContendedLocks ), f );
            fread( &data.drawEmptyLabels, 1, sizeof( data.drawEmptyLabels ), f );
            fread( &data.drawContextSwitches, 1, sizeof( data.drawContextSwitches ), f );
            fread( &data.drawCpuData, 1, sizeof( data.drawCpuData ), f );
        }
        fclose( f );
    }
}

void UserData::SaveState( const ViewData& data )
{
    if( !m_preserveState ) return;
    assert( Valid() );
    FILE* f = OpenFile( FileTimeline, true );
    if( f )
    {
        uint32_t ver = VersionTimeline;
        fwrite( &ver, 1, sizeof( ver ), f );
        fwrite( &data.zvStart, 1, sizeof( data.zvStart ), f );
        fwrite( &data.zvEnd, 1, sizeof( data.zvEnd ), f );
        fwrite( &data.zvHeight, 1, sizeof( data.zvHeight ), f );
        fwrite( &data.zvScroll, 1, sizeof( data.zvScroll ), f );
        fwrite( &data.frameScale, 1, sizeof( data.frameScale ), f );
        fwrite( &data.frameStart, 1, sizeof( data.frameStart ), f );
        fclose( f );
    }

    f = OpenFile( FileOptions, true );
    if( f )
    {
        uint32_t ver = VersionOptions;
        fwrite( &ver, 1, sizeof( ver ), f );
        fwrite( &data.drawGpuZones, 1, sizeof( data.drawGpuZones ), f );
        fwrite( &data.drawZones, 1, sizeof( data.drawZones ), f );
        fwrite( &data.drawLocks, 1, sizeof( data.drawLocks ), f );
        fwrite( &data.drawPlots, 1, sizeof( data.drawPlots ), f );
        fwrite( &data.onlyContendedLocks, 1, sizeof( data.onlyContendedLocks ), f );
        fwrite( &data.drawEmptyLabels, 1, sizeof( data.drawEmptyLabels ), f );
        fwrite( &data.drawContextSwitches, 1, sizeof( data.drawContextSwitches ), f );
        fwrite( &data.drawCpuData, 1, sizeof( data.drawCpuData ), f );
        fclose( f );
    }
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
