#include <assert.h>
#include <memory>

#ifdef _WIN32
#  include <stdio.h>
#else
#  include <unistd.h>
#endif

#include "TracyStorage.hpp"
#include "TracyUserData.hpp"
#include "TracyViewData.hpp"

namespace tracy
{

constexpr auto FileDescription = "description";
constexpr auto FileTimeline = "timeline";
constexpr auto FileOptions = "options";
constexpr auto FileAnnotations = "annotations";
constexpr auto FileSourceSubstitutions = "srcsub";

enum : uint32_t { VersionTimeline = 0 };
enum : uint32_t { VersionOptions = 7 };
enum : uint32_t { VersionAnnotations = 0 };
enum : uint32_t { VersionSourceSubstitutions = 0 };

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
            fread( &data.drawFrameTargets, 1, sizeof( data.drawFrameTargets ), f );
            fread( &data.drawContextSwitches, 1, sizeof( data.drawContextSwitches ), f );
            fread( &data.darkenContextSwitches, 1, sizeof( data.darkenContextSwitches ), f );
            fread( &data.drawCpuData, 1, sizeof( data.drawCpuData ), f );
            fread( &data.drawCpuUsageGraph, 1, sizeof( data.drawCpuUsageGraph ), f );
            fread( &data.drawSamples, 1, sizeof( data.drawSamples ), f );
            fread( &data.dynamicColors, 1, sizeof( data.dynamicColors ), f );
            fread( &data.forceColors, 1, sizeof( data.forceColors ), f );
            fread( &data.ghostZones, 1, sizeof( data.ghostZones ), f );
            fread( &data.frameTarget, 1, sizeof( data.frameTarget ), f );
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
        fwrite( &data.drawFrameTargets, 1, sizeof( data.drawFrameTargets ), f );
        fwrite( &data.drawContextSwitches, 1, sizeof( data.drawContextSwitches ), f );
        fwrite( &data.darkenContextSwitches, 1, sizeof( data.darkenContextSwitches ), f );
        fwrite( &data.drawCpuData, 1, sizeof( data.drawCpuData ), f );
        fwrite( &data.drawCpuUsageGraph, 1, sizeof( data.drawCpuUsageGraph ), f );
        fwrite( &data.drawSamples, 1, sizeof( data.drawSamples ), f );
        fwrite( &data.dynamicColors, 1, sizeof( data.dynamicColors ), f );
        fwrite( &data.forceColors, 1, sizeof( data.forceColors ), f );
        fwrite( &data.ghostZones, 1, sizeof( data.ghostZones ), f );
        fwrite( &data.frameTarget, 1, sizeof( data.frameTarget ), f );
        fclose( f );
    }
}

void UserData::StateShouldBePreserved()
{
    m_preserveState = true;
}

void UserData::LoadAnnotations( std::vector<std::unique_ptr<Annotation>>& data )
{
    assert( Valid() );
    FILE* f = OpenFile( FileAnnotations, false );
    if( f )
    {
        uint32_t ver;
        fread( &ver, 1, sizeof( ver ), f );
        if( ver == VersionAnnotations )
        {
            uint32_t sz;
            fread( &sz, 1, sizeof( sz ), f );
            for( uint32_t i=0; i<sz; i++ )
            {
                auto ann = std::make_unique<Annotation>();

                uint32_t tsz;
                fread( &tsz, 1, sizeof( tsz ), f );
                if( tsz != 0 )
                {
                    char buf[1024];
                    assert( tsz < 1024 );
                    fread( buf, 1, tsz, f );
                    ann->text.assign( buf, tsz );
                }
                fread( &ann->range.min, 1, sizeof( ann->range.min ), f );
                fread( &ann->range.max, 1, sizeof( ann->range.max ), f );
                fread( &ann->color, 1, sizeof( ann->color ), f );
                ann->range.active = true;

                data.emplace_back( std::move( ann ) );
            }
        }
        fclose( f );
    }
}

void UserData::SaveAnnotations( const std::vector<std::unique_ptr<Annotation>>& data )
{
    if( !m_preserveState ) return;
    if( data.empty() )
    {
        Remove( FileAnnotations );
        return;
    }
    assert( Valid() );
    FILE* f = OpenFile( FileAnnotations, true );
    if( f )
    {
        uint32_t ver = VersionAnnotations;
        fwrite( &ver, 1, sizeof( ver ), f );
        uint32_t sz = uint32_t( data.size() );
        fwrite( &sz, 1, sizeof( sz ), f );
        for( auto& ann : data )
        {
            sz = uint32_t( ann->text.size() );
            fwrite( &sz, 1, sizeof( sz ), f );
            if( sz != 0 )
            {
                fwrite( ann->text.c_str(), 1, sz, f );
            }
            fwrite( &ann->range.min, 1, sizeof( ann->range.min ), f );
            fwrite( &ann->range.max, 1, sizeof( ann->range.max ), f );
            fwrite( &ann->color, 1, sizeof( ann->color ), f );
        }
        fclose( f );
    }
}

bool UserData::LoadSourceSubstitutions( std::vector<SourceRegex>& data )
{
    assert( Valid() );
    bool regexValid = true;
    FILE* f = OpenFile( FileSourceSubstitutions, false );
    if( f )
    {
        uint32_t ver;
        fread( &ver, 1, sizeof( ver ), f );
        if( ver == VersionSourceSubstitutions )
        {
            uint32_t sz;
            fread( &sz, 1, sizeof( sz ), f );
            for( uint32_t i=0; i<sz; i++ )
            {
                std::string pattern, target;
                uint32_t tsz;
                fread( &tsz, 1, sizeof( tsz ), f );
                if( tsz != 0 )
                {
                    char buf[1024];
                    assert( tsz < 1024 );
                    fread( buf, 1, tsz, f );
                    pattern.assign( buf, tsz );
                }
                fread( &tsz, 1, sizeof( tsz ), f );
                if( tsz != 0 )
                {
                    char buf[1024];
                    assert( tsz < 1024 );
                    fread( buf, 1, tsz, f );
                    target.assign( buf, tsz );
                }
                std::regex regex;
                try
                {
                    regex.assign( pattern );
                }
                catch( std::regex_error& err )
                {
                    regexValid = false;
                }
                data.emplace_back( SourceRegex { std::move( pattern ), std::move( target ), std::move( regex ) } );
            }
        }
        fclose( f );
    }
    return regexValid;
}

void UserData::SaveSourceSubstitutions( const std::vector<SourceRegex>& data )
{
    if( !m_preserveState ) return;
    if( data.empty() )
    {
        Remove( FileSourceSubstitutions );
        return;
    }
    assert( Valid() );
    FILE* f = OpenFile( FileSourceSubstitutions, true );
    if( f )
    {
        uint32_t ver = VersionSourceSubstitutions;
        fwrite( &ver, 1, sizeof( ver ), f );
        uint32_t sz = uint32_t( data.size() );
        fwrite( &sz, 1, sizeof( sz ), f );
        for( auto& v : data )
        {
            sz = uint32_t( v.pattern.size() );
            fwrite( &sz, 1, sizeof( sz ), f );
            if( sz != 0 )
            {
                fwrite( v.pattern.c_str(), 1, sz, f );
            }
            sz = uint32_t( v.target.size() );
            fwrite( &sz, 1, sizeof( sz ), f );
            if( sz != 0 )
            {
                fwrite( v.target.c_str(), 1, sz, f );
            }
        }
        fclose( f );
    }
}


FILE* UserData::OpenFile( const char* filename, bool write )
{
    const auto path = GetSavePath( m_program.c_str(), m_time, filename, write );
    if( !path ) return nullptr;
    FILE* f = fopen( path, write ? "wb" : "rb" );
    return f;
}

void UserData::Remove( const char* filename )
{
    const auto path = GetSavePath( m_program.c_str(), m_time, filename, false );
    if( !path ) return;
    unlink( path );
}

const char* UserData::GetConfigLocation() const
{
    assert( Valid() );
    return GetSavePath( m_program.c_str(), m_time, nullptr, false );
}

}
