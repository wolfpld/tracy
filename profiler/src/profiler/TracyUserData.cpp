#include <assert.h>
#include <memory>

#ifdef _WIN32
#  include <stdio.h>
#else
#  include <unistd.h>
#endif

#include "../ini.h"

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

constexpr uint32_t VersionTimeline = 0;
constexpr uint32_t VersionOptions = 7;
constexpr uint32_t VersionAnnotations = 0;
constexpr uint32_t VersionSourceSubstitutions = 0;

UserData::UserData()
    : m_preserveState( false )
{
}

UserData::UserData( const char* program, uint64_t time )
    : m_program( program )
    , m_time( time )
    , m_preserveState( false )
{
    if( m_program.empty() ) m_program = "_";

    LoadLegacyDescription();
    LoadLegacyState();
    LoadLegacyAnnotations();
    LoadLegacySourceSubstitutions();
}

void UserData::Init( const char* program, uint64_t time )
{
    assert( !Valid() );
    m_program = program;
    m_time = time;

    if( m_program.empty() ) m_program = "_";
}

void UserData::SetDescription( const char* description )
{
    m_description = description;
}

void UserData::LoadState( ViewData& data )
{
    assert( m_preserveState );
    assert( Valid() );

    if( m_viewData.zvStart == 0 && m_viewData.zvEnd == 0 ) return;
    data = m_viewData;
}

void UserData::StoreState( const ViewData& data )
{
    m_viewData = data;
}

void UserData::StateShouldBePreserved()
{
    m_preserveState = true;
}

void UserData::LoadAnnotations( std::vector<std::shared_ptr<Annotation>>& data )
{
    assert( m_preserveState );
    assert( Valid() );
    data = m_annotations;
}

void UserData::StoreAnnotations( const std::vector<std::shared_ptr<Annotation>>& data )
{
    m_annotations = data;
}

void UserData::LoadSourceSubstitutions( std::vector<SourceRegex>& data )
{
    assert( m_preserveState );
    assert( Valid() );
    data = m_sourceSubstitutions;
}

void UserData::StoreSourceSubstitutions( const std::vector<SourceRegex>& data )
{
    m_sourceSubstitutions = data;
}

void UserData::Save()
{
    if( !m_preserveState ) return;
    assert( Valid() );

    FILE* f;

    f = OpenFile( FileDescription, true );
    if( f )
    {
        fwrite( m_description.c_str(), 1, m_description.size(), f );
        fclose( f );
    }

    f = OpenFile( FileTimeline, true );
    if( f )
    {
        uint32_t ver = VersionTimeline;
        fwrite( &ver, 1, sizeof( ver ), f );
        fwrite( &m_viewData.zvStart, 1, sizeof( m_viewData.zvStart ), f );
        fwrite( &m_viewData.zvEnd, 1, sizeof( m_viewData.zvEnd ), f );
        float zero = 0;
        fwrite( &zero, 1, sizeof( zero ), f );
        fwrite( &zero, 1, sizeof( zero ), f );
        fwrite( &m_viewData.frameScale, 1, sizeof( m_viewData.frameScale ), f );
        fwrite( &m_viewData.frameStart, 1, sizeof( m_viewData.frameStart ), f );
        fclose( f );
    }

    f = OpenFile( FileOptions, true );
    if( f )
    {
        fprintf( f, "[options]\n" );
        fprintf( f, "drawGpuZones = %d\n", m_viewData.drawGpuZones );
        fprintf( f, "drawZones = %d\n", m_viewData.drawZones );
        fprintf( f, "drawLocks = %d\n", m_viewData.drawLocks );
        fprintf( f, "drawPlots = %d\n", m_viewData.drawPlots );
        fprintf( f, "onlyContendedLocks = %d\n", m_viewData.onlyContendedLocks );
        fprintf( f, "drawEmptyLabels = %d\n", m_viewData.drawEmptyLabels );
        fprintf( f, "drawFrameTargets = %d\n", m_viewData.drawFrameTargets );
        fprintf( f, "drawContextSwitches = %d\n", m_viewData.drawContextSwitches );
        fprintf( f, "darkenContextSwitches = %d\n", m_viewData.darkenContextSwitches );
        fprintf( f, "drawCpuData = %d\n", m_viewData.drawCpuData );
        fprintf( f, "drawCpuUsageGraph = %d\n", m_viewData.drawCpuUsageGraph );
        fprintf( f, "drawSamples = %d\n", m_viewData.drawSamples );
        fprintf( f, "dynamicColors = %d\n", m_viewData.dynamicColors );
        fprintf( f, "inheritParentColors = %d\n", m_viewData.inheritParentColors );
        fprintf( f, "forceColors = %d\n", m_viewData.forceColors );
        fprintf( f, "ghostZones = %d\n", m_viewData.ghostZones );
        fprintf( f, "frameTarget = %d\n", m_viewData.frameTarget );
        fprintf( f, "shortenName = %d\n", (int)m_viewData.shortenName );
        fprintf( f, "plotHeight = %d\n", m_viewData.plotHeight );
        fclose( f );
    }

    if( m_sourceSubstitutions.empty() )
    {
        Remove( FileSourceSubstitutions );
    }
    else
    {
        f = OpenFile( FileSourceSubstitutions, true );
        if( f )
        {
            uint32_t ver = VersionSourceSubstitutions;
            fwrite( &ver, 1, sizeof( ver ), f );
            uint32_t sz = uint32_t( m_sourceSubstitutions.size() );
            fwrite( &sz, 1, sizeof( sz ), f );
            for( auto& v : m_sourceSubstitutions )
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

    if( m_annotations.empty() )
    {
        Remove( FileAnnotations );
    }
    else
    {
        f = OpenFile( FileAnnotations, true );
        if( f )
        {
            uint32_t ver = VersionAnnotations;
            fwrite( &ver, 1, sizeof( ver ), f );
            uint32_t sz = uint32_t( m_annotations.size() );
            fwrite( &sz, 1, sizeof( sz ), f );
            for( auto& ann : m_annotations )
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

void UserData::LoadLegacyDescription()
{
    FILE* f = OpenFile( FileDescription, false );
    if( f )
    {
        fseek( f, 0, SEEK_END );
        const auto sz = ftell( f );
        fseek( f, 0, SEEK_SET );
        auto buf = std::unique_ptr<char[]>( new char[sz] );
        fread( buf.get(), 1, sz, f );
        fclose( f );
        m_description.assign( buf.get(), buf.get() + sz );
    }
}

void UserData::LoadLegacyState()
{
    FILE* f = OpenFile( FileTimeline, false );
    if( f )
    {
        uint32_t ver;
        fread( &ver, 1, sizeof( ver ), f );
        if( ver == VersionTimeline )
        {
            fread( &m_viewData.zvStart, 1, sizeof( m_viewData.zvStart ), f );
            fread( &m_viewData.zvEnd, 1, sizeof( m_viewData.zvEnd ), f );
            fseek( f, sizeof( float ) * 2, SEEK_CUR );
            fread( &m_viewData.frameScale, 1, sizeof( m_viewData.frameScale ), f );
            fread( &m_viewData.frameStart, 1, sizeof( m_viewData.frameStart ), f );
        }
        fclose( f );
    }

    const auto path = GetSavePath( m_program.c_str(), m_time, FileOptions, false );
    assert( path );
    auto ini = ini_load( path );
    if( ini )
    {
        int v;
        if( ini_sget( ini, "options", "drawGpuZones", "%d", &v ) ) m_viewData.drawGpuZones = v;
        if( ini_sget( ini, "options", "drawZones", "%d", &v ) ) m_viewData.drawZones = v;
        if( ini_sget( ini, "options", "drawLocks", "%d", &v ) ) m_viewData.drawLocks = v;
        if( ini_sget( ini, "options", "drawPlots", "%d", &v ) ) m_viewData.drawPlots = v;
        if( ini_sget( ini, "options", "onlyContendedLocks", "%d", &v ) ) m_viewData.onlyContendedLocks = v;
        if( ini_sget( ini, "options", "drawEmptyLabels", "%d", &v ) ) m_viewData.drawEmptyLabels = v;
        if( ini_sget( ini, "options", "drawFrameTargets", "%d", &v ) ) m_viewData.drawFrameTargets = v;
        if( ini_sget( ini, "options", "drawContextSwitches", "%d", &v ) ) m_viewData.drawContextSwitches = v;
        if( ini_sget( ini, "options", "darkenContextSwitches", "%d", &v ) ) m_viewData.darkenContextSwitches = v;
        if( ini_sget( ini, "options", "drawCpuData", "%d", &v ) ) m_viewData.drawCpuData = v;
        if( ini_sget( ini, "options", "drawCpuUsageGraph", "%d", &v ) ) m_viewData.drawCpuUsageGraph = v;
        if( ini_sget( ini, "options", "drawSamples", "%d", &v ) ) m_viewData.drawSamples = v;
        if( ini_sget( ini, "options", "dynamicColors", "%d", &v ) ) m_viewData.dynamicColors = v;
        if( ini_sget( ini, "options", "inheritParentColors", "%d", &v ) ) m_viewData.inheritParentColors = v;
        if( ini_sget( ini, "options", "forceColors", "%d", &v ) ) m_viewData.forceColors = v;
        if( ini_sget( ini, "options", "ghostZones", "%d", &v ) ) m_viewData.ghostZones = v;
        if( ini_sget( ini, "options", "frameTarget", "%d", &v ) ) m_viewData.frameTarget = v;
        if( ini_sget( ini, "options", "shortenName", "%d", &v ) ) m_viewData.shortenName = (ShortenName)v;
        if( ini_sget( ini, "options", "plotHeight", "%d", &v ) ) m_viewData.plotHeight = v;
        ini_free( ini );
    }
}

void UserData::LoadLegacyAnnotations()
{
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

                m_annotations.emplace_back( std::move( ann ) );
            }
        }
        fclose( f );
    }
}

void UserData::LoadLegacySourceSubstitutions()
{
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
                m_sourceSubstitutions.emplace_back( SourceRegex { std::move( pattern ), std::move( target ) } );
            }
        }
        fclose( f );
    }
}

}
