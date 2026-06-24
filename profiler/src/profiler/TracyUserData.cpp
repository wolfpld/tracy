#include <assert.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <sys/stat.h>

#ifdef _WIN32
#  include <stdio.h>
#  ifdef _MSC_VER
#    define unlink _unlink
#  endif
#else
#  include <unistd.h>
#endif

#include "../ini.h"

#include "TracyStorage.hpp"
#include "TracyUserData.hpp"
#include "TracyViewData.hpp"

namespace tracy
{

UserData::UserData()
    : m_preserveState( false )
    , m_sidecarPublic( false )
{
}

UserData::UserData( const char* program, uint64_t time, const char* filePath )
    : m_program( program )
    , m_time( time )
    , m_preserveState( false )
    , m_sidecarPublic( false )
{
    if( m_program.empty() ) m_program = "_";
    if( filePath )
    {
        m_filePath = filePath;
        m_sidecarPublic = true;
        auto sidecar = GetSidecarPath( false );
        if( sidecar.empty() )
        {
            m_sidecarPublic = false;
        }
        else
        {
            struct stat st;
            if( stat( sidecar.c_str(), &st ) != 0 ) m_sidecarPublic = false;
        }
    }

    if( !Load() )
    {
        LoadLegacyDescription();
        LoadLegacyState();
        LoadLegacyAnnotations();
        LoadLegacySourceSubstitutions();
    }
}

void UserData::Init( const char* program, uint64_t time, const char* filePath )
{
    assert( !Valid() );
    m_program = program;
    m_time = time;
    if( filePath ) m_filePath = filePath;

    if( m_program.empty() ) m_program = "_";
}

void UserData::SetFilePath( const char* filePath )
{
    assert( filePath );
    m_filePath = filePath;
    if( m_sidecarPublic ) Save();
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

void UserData::SetSidecarPublic( bool state )
{
    assert( Valid() );
    assert( m_sidecarPublic != state );

    const auto oldFn = GetSidecarPath( false );
    m_sidecarPublic = state;

    if( Save() )
    {
        unlink( oldFn.c_str() );
    }
    else
    {
        m_sidecarPublic = !state;
    }
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

bool UserData::Save()
{
    if( !m_preserveState ) return false;
    assert( Valid() );

    nlohmann::json json = {
        { "description", m_description },
        { "viewData", {
            { "zvStart", m_viewData.zvStart },
            { "zvEnd", m_viewData.zvEnd },
            { "frameScale", m_viewData.frameScale },
            { "frameStart", m_viewData.frameStart }
        } },
        { "options", {
            { "drawGpuZones", m_viewData.drawGpuZones },
            { "drawZones", m_viewData.drawZones },
            { "drawLocks", m_viewData.drawLocks },
            { "drawPlots", m_viewData.drawPlots },
            { "onlyContendedLocks", m_viewData.onlyContendedLocks },
            { "drawEmptyLabels", m_viewData.drawEmptyLabels },
            { "drawFrameTargets", m_viewData.drawFrameTargets },
            { "drawContextSwitches", m_viewData.drawContextSwitches },
            { "darkenContextSwitches", m_viewData.darkenContextSwitches },
            { "drawCpuData", m_viewData.drawCpuData },
            { "drawCpuUsageGraph", m_viewData.drawCpuUsageGraph },
            { "drawSamples", m_viewData.drawSamples },
            { "dynamicColors", m_viewData.dynamicColors },
            { "inheritParentColors", m_viewData.inheritParentColors },
            { "forceColors", m_viewData.forceColors },
            { "ghostZones", m_viewData.ghostZones },
            { "frameTarget", m_viewData.frameTarget },
            { "shortenName", (int)m_viewData.shortenName },
            { "plotHeight", m_viewData.plotHeight },
        } },
    };

    if( !m_sourceSubstitutions.empty() )
    {
        json["sourceSubstitutions"] = nlohmann::json::array();
        for( auto& v : m_sourceSubstitutions )
        {
            json["sourceSubstitutions"].push_back( {
                { "pattern", v.pattern },
                { "target", v.target }
            } );
        }
    }

    if( !m_annotations.empty() )
    {
        json["annotations"] = nlohmann::json::array();
        for( auto& v : m_annotations )
        {
            json["annotations"].push_back( {
                { "text", v->text },
                { "min", v->range.min },
                { "max", v->range.max },
                { "color", v->color },
                { "visible", v->visible },
            } );
        }
    }

    auto f = OpenFile( true );
    if( !f ) return false;

    auto str = json.dump( 2 );
    const auto sz = str.size();
    const auto wrote = fwrite( str.c_str(), 1, sz, f );
    fclose( f );

    return sz == wrote;
}

template<typename T>
static bool LoadValue( const nlohmann::json& json, const char* key, T& value )
{
    if( !json.contains( key ) ) return false;
    value = json[key].get<T>();
    return true;
}

template<typename T>
static bool LoadValueCast( const nlohmann::json& json, const char* key, T& value )
{
    if( !json.contains( key ) ) return false;
    value = (T)json[key].get<int>();
    return true;
}

bool UserData::Load()
{
    auto f = OpenFile( false );
    if( !f ) return false;

    try
    {
        auto json = nlohmann::json::parse( f );

        LoadValue( json, "description", m_description );

        if( json.contains( "viewData" ) )
        {
            const auto& viewData = json["viewData"];
            LoadValue( viewData, "zvStart", m_viewData.zvStart );
            LoadValue( viewData, "zvEnd", m_viewData.zvEnd );
            LoadValue( viewData, "frameScale", m_viewData.frameScale );
            LoadValue( viewData, "frameStart", m_viewData.frameStart );
        }

        if( json.contains( "options" ) )
        {
            const auto& options = json["options"];
            LoadValue( options, "drawGpuZones", m_viewData.drawGpuZones );
            LoadValue( options, "drawZones", m_viewData.drawZones );
            LoadValue( options, "drawLocks", m_viewData.drawLocks );
            LoadValue( options, "drawPlots", m_viewData.drawPlots );
            LoadValue( options, "onlyContendedLocks", m_viewData.onlyContendedLocks );
            LoadValue( options, "drawEmptyLabels", m_viewData.drawEmptyLabels );
            LoadValue( options, "drawFrameTargets", m_viewData.drawFrameTargets );
            LoadValue( options, "drawContextSwitches", m_viewData.drawContextSwitches );
            LoadValue( options, "darkenContextSwitches", m_viewData.darkenContextSwitches );
            LoadValue( options, "drawCpuData", m_viewData.drawCpuData );
            LoadValue( options, "drawCpuUsageGraph", m_viewData.drawCpuUsageGraph );
            LoadValue( options, "drawSamples", m_viewData.drawSamples );
            LoadValue( options, "dynamicColors", m_viewData.dynamicColors );
            LoadValue( options, "inheritParentColors", m_viewData.inheritParentColors );
            LoadValue( options, "forceColors", m_viewData.forceColors );
            LoadValue( options, "ghostZones", m_viewData.ghostZones );
            LoadValue( options, "frameTarget", m_viewData.frameTarget );
            LoadValueCast( options, "shortenName", m_viewData.shortenName );
            LoadValue( options, "plotHeight", m_viewData.plotHeight );
        }

        if( json.contains( "sourceSubstitutions" ) )
        {
            for( auto& v : json["sourceSubstitutions"] )
            {
                SourceRegex s;
                LoadValue( v, "pattern", s.pattern );
                LoadValue( v, "target", s.target );
                m_sourceSubstitutions.emplace_back( std::move( s ) );
            }
        }

        if( json.contains( "annotations" ) )
        {
            for( auto& v : json["annotations"] )
            {
                auto a = std::make_unique<Annotation>();
                LoadValue( v, "text", a->text );
                LoadValue( v, "min", a->range.min );
                LoadValue( v, "max", a->range.max );
                LoadValue( v, "color", a->color );
                LoadValue( v, "visible", a->visible );
                a->range.active = true;
                m_annotations.emplace_back( std::move( a ) );
            }
        }
    }
    catch( nlohmann::json::exception& )
    {
        fclose( f );
        return true;
    }

    fclose( f );
    return true;
}

FILE* UserData::OpenFile( bool write )
{
    const auto path = GetSidecarPath( write );
    if( path.empty() ) return nullptr;
    FILE* f = fopen( path.c_str(), write ? "wb" : "rb" );
    return f;
}

FILE* UserData::OpenFileLegacy( const char* filename )
{
    const auto path = GetSavePathLegacy( m_program.c_str(), m_time, filename );
    if( !path ) return nullptr;
    FILE* f = fopen( path, "rb" );
    return f;
}

std::string UserData::GetSidecarPath( bool write ) const
{
    if( m_sidecarPublic )
    {
        assert( !m_filePath.empty() );
        return m_filePath + ".json";
    }

    auto path = GetSavePath( m_program.c_str(), m_time, write );
    if( !path ) return {};
    return path;
}

void UserData::LoadLegacyDescription()
{
    constexpr auto FileDescription = "description";

    FILE* f = OpenFileLegacy( FileDescription );
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
    constexpr auto FileTimeline = "timeline";
    constexpr auto FileOptions = "options";

    FILE* f = OpenFileLegacy( FileTimeline );
    if( f )
    {
        uint32_t ver;
        fread( &ver, 1, sizeof( ver ), f );
        if( ver == 0 )
        {
            fread( &m_viewData.zvStart, 1, sizeof( m_viewData.zvStart ), f );
            fread( &m_viewData.zvEnd, 1, sizeof( m_viewData.zvEnd ), f );
            fseek( f, sizeof( float ) * 2, SEEK_CUR );
            fread( &m_viewData.frameScale, 1, sizeof( m_viewData.frameScale ), f );
            fread( &m_viewData.frameStart, 1, sizeof( m_viewData.frameStart ), f );
        }
        fclose( f );
    }

    const auto path = GetSavePathLegacy( m_program.c_str(), m_time, FileOptions );
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
    constexpr auto FileAnnotations = "annotations";
    FILE* f = OpenFileLegacy( FileAnnotations );
    if( f )
    {
        uint32_t ver;
        fread( &ver, 1, sizeof( ver ), f );
        if( ver == 0 )
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
    constexpr auto FileSourceSubstitutions = "srcsub";
    FILE* f = OpenFileLegacy( FileSourceSubstitutions );
    if( f )
    {
        uint32_t ver;
        fread( &ver, 1, sizeof( ver ), f );
        if( ver == 0 )
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
