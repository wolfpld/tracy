#include <inttypes.h>

#include "TracyColor.hpp"
#include "TracyPrint.hpp"
#include "TracyUtility.hpp"
#include "TracyView.hpp"

namespace tracy
{

uint32_t View::GetThreadColor( uint64_t thread, int depth )
{
    return tracy::GetThreadColor( thread, depth, m_vd.dynamicColors != 0 );
}

uint32_t View::GetRawSrcLocColor( const SourceLocation& srcloc, int depth )
{
    auto namehash = srcloc.namehash;
    if( namehash == 0 && srcloc.function.active )
    {
        const auto f = m_worker.GetString( srcloc.function );
        namehash = charutil::hash( f );
        if( namehash == 0 ) namehash++;
        srcloc.namehash = namehash;
    }
    if( namehash == 0 )
    {
        return GetHsvColor( uint64_t( &srcloc ), depth );
    }
    else
    {
        return GetHsvColor( namehash, depth );
    }
}

uint32_t View::GetSrcLocColor( const SourceLocation& srcloc, int depth )
{
    const auto color = srcloc.color;
    if( color != 0 && !m_vd.forceColors ) return color | 0xFF000000;
    if( m_vd.dynamicColors == 0 ) return 0xFFCC5555;
    return GetRawSrcLocColor( srcloc, depth );
}

uint32_t View::GetZoneColor( const ZoneEvent& ev, uint64_t thread, int depth )
{
    const auto sl = ev.SrcLoc();
    const auto& srcloc = m_worker.GetSourceLocation( sl );
    if( !m_vd.forceColors )
    {
        if( m_worker.HasZoneExtra( ev ) )
        {
            const auto custom_color = m_worker.GetZoneExtra( ev ).color.Val();
            if( custom_color != 0 ) return custom_color | 0xFF000000;
        }
        const auto color = srcloc.color;
        if( color != 0 ) return color | 0xFF000000;
    }
    switch( m_vd.dynamicColors )
    {
    case 0:
        return 0xFFCC5555;
    case 1:
        return GetHsvColor( thread, depth );
    case 2:
        return GetRawSrcLocColor( srcloc, depth );
    default:
        assert( false );
        return 0;
    }
}

uint32_t View::GetZoneColor( const GpuEvent& ev )
{
    const auto& srcloc = m_worker.GetSourceLocation( ev.SrcLoc() );
    const auto color = srcloc.color;
    return color != 0 ? ( color | 0xFF000000 ) : 0xFF222288;
}

View::ZoneColorData View::GetZoneColorData( const ZoneEvent& ev, uint64_t thread, int depth )
{
    ZoneColorData ret;
    const auto& srcloc = ev.SrcLoc();
    if( m_zoneInfoWindow == &ev )
    {
        ret.color = GetZoneColor( ev, thread, depth );
        ret.accentColor = 0xFF44DD44;
        ret.thickness = 3.f;
        ret.highlight = true;
    }
    else if( m_zoneHighlight == &ev )
    {
        ret.color = GetZoneColor( ev, thread, depth );
        ret.accentColor = 0xFF4444FF;
        ret.thickness = 3.f;
        ret.highlight = true;
    }
    else if( m_zoneSrcLocHighlight == srcloc )
    {
        ret.color = GetZoneColor( ev, thread, depth );
        ret.accentColor = 0xFFEEEEEE;
        ret.thickness = 1.f;
        ret.highlight = true;
    }
    else if( m_findZone.show && !m_findZone.match.empty() && m_findZone.match[m_findZone.selMatch] == srcloc )
    {
        uint32_t color = 0xFF229999;
        if( m_findZone.highlight.active )
        {
            const auto zt = m_worker.GetZoneEnd( ev ) - ev.Start();
            if( zt >= m_findZone.highlight.start && zt <= m_findZone.highlight.end )
            {
                color = 0xFFFFCC66;
            }
        }
        ret.color = color;
        ret.accentColor = HighlightColor( color );
        ret.thickness = 3.f;
        ret.highlight = true;
    }
    else
    {
        const auto color = GetZoneColor( ev, thread, depth );
        ret.color = color;
        ret.accentColor = HighlightColor( color );
        ret.thickness = 1.f;
        ret.highlight = false;
    }
    return ret;
}

View::ZoneColorData View::GetZoneColorData( const GpuEvent& ev )
{
    ZoneColorData ret;
    const auto color = GetZoneColor( ev );
    ret.color = color;
    if( m_gpuInfoWindow == &ev )
    {
        ret.accentColor = 0xFF44DD44;
        ret.thickness = 3.f;
        ret.highlight = true;
    }
    else if( m_gpuHighlight == &ev )
    {
        ret.accentColor = 0xFF4444FF;
        ret.thickness = 3.f;
        ret.highlight = true;
    }
    else
    {
        ret.accentColor = HighlightColor( color );
        ret.thickness = 1.f;
        ret.highlight = false;
    }
    return ret;
}


const ZoneEvent* View::FindZoneAtTime( uint64_t thread, int64_t time ) const
{
    // TODO add thread rev-map
    ThreadData* td = nullptr;
    for( const auto& t : m_worker.GetThreadData() )
    {
        if( t->id == thread )
        {
            td = t;
            break;
        }
    }
    if( !td ) return nullptr;

    const Vector<short_ptr<ZoneEvent>>* timeline = &td->timeline;
    if( timeline->empty() ) return nullptr;
    const ZoneEvent* ret = nullptr;
    for(;;)
    {
        if( timeline->is_magic() )
        {
            auto vec = (Vector<ZoneEvent>*)timeline;
            auto it = std::upper_bound( vec->begin(), vec->end(), time, [] ( const auto& l, const auto& r ) { return l < r.Start(); } );
            if( it != vec->begin() ) --it;
            if( it->Start() > time || ( it->IsEndValid() && it->End() < time ) ) return ret;
            ret = it;
            if( !it->HasChildren() ) return ret;
            timeline = &m_worker.GetZoneChildren( it->Child() );
        }
        else
        {
            auto it = std::upper_bound( timeline->begin(), timeline->end(), time, [] ( const auto& l, const auto& r ) { return l < r->Start(); } );
            if( it != timeline->begin() ) --it;
            if( (*it)->Start() > time || ( (*it)->IsEndValid() && (*it)->End() < time ) ) return ret;
            ret = *it;
            if( !(*it)->HasChildren() ) return ret;
            timeline = &m_worker.GetZoneChildren( (*it)->Child() );
        }
    }
}

const ZoneEvent* View::GetZoneChild( const ZoneEvent& zone, int64_t time ) const
{
    if( !zone.HasChildren() ) return nullptr;
    auto& children = m_worker.GetZoneChildren( zone.Child() );
    if( children.is_magic() )
    {
        auto& vec = *((Vector<ZoneEvent>*)&children);
        auto it = std::upper_bound( vec.begin(), vec.end(), time, [] ( const auto& l, const auto& r ) { return l < r.Start(); } );
        if( it != vec.begin() ) --it;
        if( it->Start() > time || ( it->IsEndValid() && it->End() < time ) ) return nullptr;
        return it;
    }
    else
    {
        auto it = std::upper_bound( children.begin(), children.end(), time, [] ( const auto& l, const auto& r ) { return l < r->Start(); } );
        if( it != children.begin() ) --it;
        if( (*it)->Start() > time || ( (*it)->IsEndValid() && (*it)->End() < time ) ) return nullptr;
        return *it;
    }
}

const ZoneEvent* View::GetZoneParent( const ZoneEvent& zone ) const
{
#ifndef TRACY_NO_STATISTICS
    if( m_worker.AreSourceLocationZonesReady() )
    {
        auto& slz = m_worker.GetZonesForSourceLocation( zone.SrcLoc() );
        if( !slz.zones.empty() && slz.zones.is_sorted() )
        {
            auto it = std::lower_bound( slz.zones.begin(), slz.zones.end(), zone.Start(), [] ( const auto& lhs, const auto& rhs ) { return lhs.Zone()->Start() < rhs; } );
            if( it != slz.zones.end() && it->Zone() == &zone )
            {
                return GetZoneParent( zone, m_worker.DecompressThread( it->Thread() ) );
            }
        }
    }
#endif

    for( const auto& thread : m_worker.GetThreadData() )
    {
        const ZoneEvent* parent = nullptr;
        const Vector<short_ptr<ZoneEvent>>* timeline = &thread->timeline;
        if( timeline->empty() ) continue;
        for(;;)
        {
            if( timeline->is_magic() )
            {
                auto vec = (Vector<ZoneEvent>*)timeline;
                auto it = std::upper_bound( vec->begin(), vec->end(), zone.Start(), [] ( const auto& l, const auto& r ) { return l < r.Start(); } );
                if( it != vec->begin() ) --it;
                if( zone.IsEndValid() && it->Start() > zone.End() ) break;
                if( it == &zone ) return parent;
                if( !it->HasChildren() ) break;
                parent = it;
                timeline = &m_worker.GetZoneChildren( parent->Child() );
            }
            else
            {
                auto it = std::upper_bound( timeline->begin(), timeline->end(), zone.Start(), [] ( const auto& l, const auto& r ) { return l < r->Start(); } );
                if( it != timeline->begin() ) --it;
                if( zone.IsEndValid() && (*it)->Start() > zone.End() ) break;
                if( *it == &zone ) return parent;
                if( !(*it)->HasChildren() ) break;
                parent = *it;
                timeline = &m_worker.GetZoneChildren( parent->Child() );
            }
        }
    }
    return nullptr;
}

const ZoneEvent* View::GetZoneParent( const ZoneEvent& zone, uint64_t tid ) const
{
    const auto thread = m_worker.GetThreadData( tid );
    const ZoneEvent* parent = nullptr;
    const Vector<short_ptr<ZoneEvent>>* timeline = &thread->timeline;
    if( timeline->empty() ) return nullptr;
    for(;;)
    {
        if( timeline->is_magic() )
        {
            auto vec = (Vector<ZoneEvent>*)timeline;
            auto it = std::upper_bound( vec->begin(), vec->end(), zone.Start(), [] ( const auto& l, const auto& r ) { return l < r.Start(); } );
            if( it != vec->begin() ) --it;
            if( zone.IsEndValid() && it->Start() > zone.End() ) break;
            if( it == &zone ) return parent;
            if( !it->HasChildren() ) break;
            parent = it;
            timeline = &m_worker.GetZoneChildren( parent->Child() );
        }
        else
        {
            auto it = std::upper_bound( timeline->begin(), timeline->end(), zone.Start(), [] ( const auto& l, const auto& r ) { return l < r->Start(); } );
            if( it != timeline->begin() ) --it;
            if( zone.IsEndValid() && (*it)->Start() > zone.End() ) break;
            if( *it == &zone ) return parent;
            if( !(*it)->HasChildren() ) break;
            parent = *it;
            timeline = &m_worker.GetZoneChildren( parent->Child() );
        }
    }
    return nullptr;
}

bool View::IsZoneReentry( const ZoneEvent& zone ) const
{
#ifndef TRACY_NO_STATISTICS
    if( m_worker.AreSourceLocationZonesReady() )
    {
        auto& slz = m_worker.GetZonesForSourceLocation( zone.SrcLoc() );
        if( !slz.zones.empty() && slz.zones.is_sorted() )
        {
            auto it = std::lower_bound( slz.zones.begin(), slz.zones.end(), zone.Start(), [] ( const auto& lhs, const auto& rhs ) { return lhs.Zone()->Start() < rhs; } );
            if( it != slz.zones.end() && it->Zone() == &zone )
            {
                return IsZoneReentry( zone, m_worker.DecompressThread( it->Thread() ) );
            }
        }
    }
#endif

    for( const auto& thread : m_worker.GetThreadData() )
    {
        const ZoneEvent* parent = nullptr;
        const Vector<short_ptr<ZoneEvent>>* timeline = &thread->timeline;
        if( timeline->empty() ) continue;
        for(;;)
        {
            if( timeline->is_magic() )
            {
                auto vec = (Vector<ZoneEvent>*)timeline;
                auto it = std::upper_bound( vec->begin(), vec->end(), zone.Start(), [] ( const auto& l, const auto& r ) { return l < r.Start(); } );
                if( it != vec->begin() ) --it;
                if( zone.IsEndValid() && it->Start() > zone.End() ) break;
                if( it == &zone ) return false;
                if( !it->HasChildren() ) break;
                parent = it;
                if (parent->SrcLoc() == zone.SrcLoc() ) return true;
                timeline = &m_worker.GetZoneChildren( parent->Child() );
            }
            else
            {
                auto it = std::upper_bound( timeline->begin(), timeline->end(), zone.Start(), [] ( const auto& l, const auto& r ) { return l < r->Start(); } );
                if( it != timeline->begin() ) --it;
                if( zone.IsEndValid() && (*it)->Start() > zone.End() ) break;
                if( *it == &zone ) return false;
                if( !(*it)->HasChildren() ) break;
                parent = *it;
                if (parent->SrcLoc() == zone.SrcLoc() ) return true;
                timeline = &m_worker.GetZoneChildren( parent->Child() );
            }
        }
    }
    return false;
}

bool View::IsZoneReentry( const ZoneEvent& zone, uint64_t tid ) const
{
    const auto thread = m_worker.GetThreadData( tid );
    const ZoneEvent* parent = nullptr;
    const Vector<short_ptr<ZoneEvent>>* timeline = &thread->timeline;
    if( timeline->empty() ) return false;
    for(;;)
    {
        if( timeline->is_magic() )
        {
            auto vec = (Vector<ZoneEvent>*)timeline;
            auto it = std::upper_bound( vec->begin(), vec->end(), zone.Start(), [] ( const auto& l, const auto& r ) { return l < r.Start(); } );
            if( it != vec->begin() ) --it;
            if( zone.IsEndValid() && it->Start() > zone.End() ) break;
            if( it == &zone ) return false;
            if( !it->HasChildren() ) break;
            parent = it;
            if (parent->SrcLoc() == zone.SrcLoc() ) return true;
            timeline = &m_worker.GetZoneChildren( parent->Child() );
        }
        else
        {
            auto it = std::upper_bound( timeline->begin(), timeline->end(), zone.Start(), [] ( const auto& l, const auto& r ) { return l < r->Start(); } );
            if( it != timeline->begin() ) --it;
            if( zone.IsEndValid() && (*it)->Start() > zone.End() ) break;
            if( *it == &zone ) return false;
            if( !(*it)->HasChildren() ) break;
            parent = *it;
            if (parent->SrcLoc() == zone.SrcLoc() ) return true;
            timeline = &m_worker.GetZoneChildren( parent->Child() );
        }
    }
    return false;
}

const GpuEvent* View::GetZoneParent( const GpuEvent& zone ) const
{
    for( const auto& ctx : m_worker.GetGpuData() )
    {
        for( const auto& td : ctx->threadData )
        {
            const GpuEvent* parent = nullptr;
            const Vector<short_ptr<GpuEvent>>* timeline = &td.second.timeline;
            if( timeline->empty() ) continue;
            for(;;)
            {
                if( timeline->is_magic() )
                {
                    auto vec = (Vector<GpuEvent>*)timeline;
                    auto it = std::upper_bound( vec->begin(), vec->end(), zone.GpuStart(), [] ( const auto& l, const auto& r ) { return (uint64_t)l < (uint64_t)r.GpuStart(); } );
                    if( it != vec->begin() ) --it;
                    if( zone.GpuEnd() >= 0 && it->GpuStart() > zone.GpuEnd() ) break;
                    if( it == &zone ) return parent;
                    if( it->Child() < 0 ) break;
                    parent = it;
                    timeline = &m_worker.GetGpuChildren( parent->Child() );
                }
                else
                {
                    auto it = std::upper_bound( timeline->begin(), timeline->end(), zone.GpuStart(), [] ( const auto& l, const auto& r ) { return (uint64_t)l < (uint64_t)r->GpuStart(); } );
                    if( it != timeline->begin() ) --it;
                    if( zone.GpuEnd() >= 0 && (*it)->GpuStart() > zone.GpuEnd() ) break;
                    if( *it == &zone ) return parent;
                    if( (*it)->Child() < 0 ) break;
                    parent = *it;
                    timeline = &m_worker.GetGpuChildren( parent->Child() );
                }
            }
        }
    }
    return nullptr;
}

const ThreadData* View::GetZoneThreadData( const ZoneEvent& zone ) const
{
#ifndef TRACY_NO_STATISTICS
    if( m_worker.AreSourceLocationZonesReady() )
    {
        auto& slz = m_worker.GetZonesForSourceLocation( zone.SrcLoc() );
        if( !slz.zones.empty() && slz.zones.is_sorted() )
        {
            auto it = std::lower_bound( slz.zones.begin(), slz.zones.end(), zone.Start(), [] ( const auto& lhs, const auto& rhs ) { return lhs.Zone()->Start() < rhs; } );
            if( it != slz.zones.end() && it->Zone() == &zone )
            {
                return m_worker.GetThreadData( m_worker.DecompressThread( it->Thread() ) );
            }
        }
    }
#endif

    for( const auto& thread : m_worker.GetThreadData() )
    {
        const Vector<short_ptr<ZoneEvent>>* timeline = &thread->timeline;
        if( timeline->empty() ) continue;
        for(;;)
        {
            if( timeline->is_magic() )
            {
                auto vec = (Vector<ZoneEvent>*)timeline;
                auto it = std::upper_bound( vec->begin(), vec->end(), zone.Start(), [] ( const auto& l, const auto& r ) { return l < r.Start(); } );
                if( it != vec->begin() ) --it;
                if( zone.IsEndValid() && it->Start() > zone.End() ) break;
                if( it == &zone ) return thread;
                if( !it->HasChildren() ) break;
                timeline = &m_worker.GetZoneChildren( it->Child() );
            }
            else
            {
                auto it = std::upper_bound( timeline->begin(), timeline->end(), zone.Start(), [] ( const auto& l, const auto& r ) { return l < r->Start(); } );
                if( it != timeline->begin() ) --it;
                if( zone.IsEndValid() && (*it)->Start() > zone.End() ) break;
                if( *it == &zone ) return thread;
                if( !(*it)->HasChildren() ) break;
                timeline = &m_worker.GetZoneChildren( (*it)->Child() );
            }
        }
    }
    return nullptr;
}

uint64_t View::GetZoneThread( const ZoneEvent& zone ) const
{
    auto threadData = GetZoneThreadData( zone );
    return threadData ? threadData->id : 0;
}

uint64_t View::GetZoneThread( const GpuEvent& zone ) const
{
    if( zone.Thread() == 0 )
    {
        for( const auto& ctx : m_worker.GetGpuData() )
        {
            if ( ctx->threadData.size() != 1 ) continue;
            const Vector<short_ptr<GpuEvent>>* timeline = &ctx->threadData.begin()->second.timeline;
            if( timeline->empty() ) continue;
            for(;;)
            {
                if( timeline->is_magic() )
                {
                    auto vec = (Vector<GpuEvent>*)timeline;
                    auto it = std::upper_bound( vec->begin(), vec->end(), zone.GpuStart(), [] ( const auto& l, const auto& r ) { return (uint64_t)l < (uint64_t)r.GpuStart(); } );
                    if( it != vec->begin() ) --it;
                    if( zone.GpuEnd() >= 0 && it->GpuStart() > zone.GpuEnd() ) break;
                    if( it == &zone ) return ctx->thread;
                    if( it->Child() < 0 ) break;
                    timeline = &m_worker.GetGpuChildren( it->Child() );
                }
                else
                {
                    auto it = std::upper_bound( timeline->begin(), timeline->end(), zone.GpuStart(), [] ( const auto& l, const auto& r ) { return (uint64_t)l < (uint64_t)r->GpuStart(); } );
                    if( it != timeline->begin() ) --it;
                    if( zone.GpuEnd() >= 0 && (*it)->GpuStart() > zone.GpuEnd() ) break;
                    if( *it == &zone ) return ctx->thread;
                    if( (*it)->Child() < 0 ) break;
                    timeline = &m_worker.GetGpuChildren( (*it)->Child() );
                }
            }
        }
        return 0;
    }
    else
    {
        return m_worker.DecompressThread( zone.Thread() );
    }
}

const GpuCtxData* View::GetZoneCtx( const GpuEvent& zone ) const
{
    for( const auto& ctx : m_worker.GetGpuData() )
    {
        for( const auto& td : ctx->threadData )
        {
            const Vector<short_ptr<GpuEvent>>* timeline = &td.second.timeline;
            if( timeline->empty() ) continue;
            for(;;)
            {
                if( timeline->is_magic() )
                {
                    auto vec = (Vector<GpuEvent>*)timeline;
                    auto it = std::upper_bound( vec->begin(), vec->end(), zone.GpuStart(), [] ( const auto& l, const auto& r ) { return (uint64_t)l < (uint64_t)r.GpuStart(); } );
                    if( it != vec->begin() ) --it;
                    if( zone.GpuEnd() >= 0 && it->GpuStart() > zone.GpuEnd() ) break;
                    if( it == &zone ) return ctx;
                    if( it->Child() < 0 ) break;
                    timeline = &m_worker.GetGpuChildren( it->Child() );
                }
                else
                {
                    auto it = std::upper_bound( timeline->begin(), timeline->end(), zone.GpuStart(), [] ( const auto& l, const auto& r ) { return (uint64_t)l < (uint64_t)r->GpuStart(); } );
                    if( it != timeline->begin() ) --it;
                    if( zone.GpuEnd() >= 0 && (*it)->GpuStart() > zone.GpuEnd() ) break;
                    if( *it == &zone ) return ctx;
                    if( (*it)->Child() < 0 ) break;
                    timeline = &m_worker.GetGpuChildren( (*it)->Child() );
                }
            }
        }
    }
    return nullptr;
}

int64_t View::GetZoneChildTime( const ZoneEvent& zone )
{
    int64_t time = 0;
    if( zone.HasChildren() )
    {
        auto& children = m_worker.GetZoneChildren( zone.Child() );
        if( children.is_magic() )
        {
            auto& vec = *(Vector<ZoneEvent>*)&children;
            for( auto& v : vec )
            {
                const auto childSpan = std::max( int64_t( 0 ), v.End() - v.Start() );
                time += childSpan;
            }
        }
        else
        {
            for( auto& v : children )
            {
                const auto childSpan = std::max( int64_t( 0 ), v->End() - v->Start() );
                time += childSpan;
            }
        }
    }
    return time;
}

int64_t View::GetZoneChildTime( const GpuEvent& zone )
{
    int64_t time = 0;
    if( zone.Child() >= 0 )
    {
        auto& children = m_worker.GetGpuChildren( zone.Child() );
        if( children.is_magic() )
        {
            auto& vec = *(Vector<GpuEvent>*)&children;
            for( auto& v : vec )
            {
                const auto childSpan = std::max( int64_t( 0 ), v.GpuEnd() - v.GpuStart() );
                time += childSpan;
            }
        }
        else
        {
            for( auto& v : children )
            {
                const auto childSpan = std::max( int64_t( 0 ), v->GpuEnd() - v->GpuStart() );
                time += childSpan;
            }
        }
    }
    return time;
}

int64_t View::GetZoneChildTimeFast( const ZoneEvent& zone )
{
    int64_t time = 0;
    if( zone.HasChildren() )
    {
        auto& children = m_worker.GetZoneChildren( zone.Child() );
        if( children.is_magic() )
        {
            auto& vec = *(Vector<ZoneEvent>*)&children;
            for( auto& v : vec )
            {
                assert( v.IsEndValid() );
                time += v.End() - v.Start();
            }
        }
        else
        {
            for( auto& v : children )
            {
                assert( v->IsEndValid() );
                time += v->End() - v->Start();
            }
        }
    }
    return time;
}

int64_t View::GetZoneChildTimeFastClamped( const ZoneEvent& zone, int64_t t0, int64_t t1 )
{
    int64_t time = 0;
    if( zone.HasChildren() )
    {
        auto& children = m_worker.GetZoneChildren( zone.Child() );
        if( children.is_magic() )
        {
            auto& vec = *(Vector<ZoneEvent>*)&children;
            auto it = std::lower_bound( vec.begin(), vec.end(), t0, [] ( const auto& l, const auto& r ) { return (uint64_t)l.End() < (uint64_t)r; } );
            if( it == vec.end() ) return 0;
            const auto zitend = std::lower_bound( it, vec.end(), t1, [] ( const auto& l, const auto& r ) { return l.Start() < r; } );
            if( it == zitend ) return 0;
            while( it < zitend )
            {
                const auto c0 = std::max<int64_t>( it->Start(), t0 );
                const auto c1 = std::min<int64_t>( it->End(), t1 );
                time += c1 - c0;
                ++it;
            }
        }
        else
        {
            auto it = std::lower_bound( children.begin(), children.end(), t0, [] ( const auto& l, const auto& r ) { return (uint64_t)l->End() < (uint64_t)r; } );
            if( it == children.end() ) return 0;
            const auto zitend = std::lower_bound( it, children.end(), t1, [] ( const auto& l, const auto& r ) { return l->Start() < r; } );
            if( it == zitend ) return 0;
            while( it < zitend )
            {
                const auto c0 = std::max<int64_t>( (*it)->Start(), t0 );
                const auto c1 = std::min<int64_t>( (*it)->End(), t1 );
                time += c1 - c0;
                ++it;
            }
        }
    }
    return time;
}

int64_t View::GetZoneSelfTime( const ZoneEvent& zone )
{
    if( m_cache.zoneSelfTime.first == &zone ) return m_cache.zoneSelfTime.second;
    if( m_cache.zoneSelfTime2.first == &zone ) return m_cache.zoneSelfTime2.second;
    const auto ztime = m_worker.GetZoneEnd( zone ) - zone.Start();
    const auto selftime = ztime - GetZoneChildTime( zone );
    if( zone.IsEndValid() )
    {
        m_cache.zoneSelfTime2 = m_cache.zoneSelfTime;
        m_cache.zoneSelfTime = std::make_pair( &zone, selftime );
    }
    return selftime;
}

int64_t View::GetZoneSelfTime( const GpuEvent& zone )
{
    if( m_cache.gpuSelfTime.first == &zone ) return m_cache.gpuSelfTime.second;
    if( m_cache.gpuSelfTime2.first == &zone ) return m_cache.gpuSelfTime2.second;
    const auto ztime = m_worker.GetZoneEnd( zone ) - zone.GpuStart();
    const auto selftime = ztime - GetZoneChildTime( zone );
    if( zone.GpuEnd() >= 0 )
    {
        m_cache.gpuSelfTime2 = m_cache.gpuSelfTime;
        m_cache.gpuSelfTime = std::make_pair( &zone, selftime );
    }
    return selftime;
}

bool View::GetZoneRunningTime( const ContextSwitch* ctx, const ZoneEvent& ev, int64_t& time, uint64_t& cnt )
{
    auto it = std::lower_bound( ctx->v.begin(), ctx->v.end(), ev.Start(), [] ( const auto& l, const auto& r ) { return (uint64_t)l.End() < (uint64_t)r; } );
    if( it == ctx->v.end() ) return false;
    const auto end = m_worker.GetZoneEnd( ev );
    const auto eit = std::upper_bound( it, ctx->v.end(), end, [] ( const auto& l, const auto& r ) { return l < r.Start(); } );
    if( eit == ctx->v.end() ) return false;
    cnt = std::distance( it, eit );
    if( cnt == 0 ) return false;
    if( cnt == 1 )
    {
        time = end - ev.Start();
    }
    else
    {
        int64_t running = it->End() - ev.Start();
        ++it;
        for( uint64_t i=0; i<cnt-2; i++ )
        {
            running += it->End() - it->Start();
            ++it;
        }
        running += end - it->Start();
        time = running;
    }
    return true;
}

const char* View::SourceSubstitution( const char* srcFile ) const
{
    if( !m_sourceRegexValid || m_sourceSubstitutions.empty() ) return srcFile;
    static std::string res, tmp;
    res.assign( srcFile );
    for( auto& v : m_sourceSubstitutions )
    {
        tmp = std::regex_replace( res, v.regex, v.target );
        std::swap( tmp, res );
    }
    return res.c_str();
}

int64_t View::AdjustGpuTime( int64_t time, int64_t begin, int drift )
{
    if( time < 0 ) return time;
    const auto t = time - begin;
    return time + t / 1000000000 * drift;
}

uint64_t View::GetFrameNumber( const FrameData& fd, int i ) const
{
    if( fd.name == 0 )
    {
        const auto offset = m_worker.GetFrameOffset();
        if( offset == 0 )
        {
            return i;
        }
        else
        {
            return i + offset - 1;
        }
    }
    else
    {
        return i + 1;
    }
}

const char* View::GetFrameText( const FrameData& fd, int i, uint64_t ftime ) const
{
    const auto fnum = GetFrameNumber( fd, i );
    static char buf[1024];
    if( fd.name == 0 )
    {
        if( i == 0 )
        {
            sprintf( buf, "Tracy init (%s)", TimeToString( ftime ) );
        }
        else if( i != 1 || !m_worker.IsOnDemand() )
        {
            sprintf( buf, "Frame %s (%s)", RealToString( fnum ), TimeToString( ftime ) );
        }
        else
        {
            sprintf( buf, "Missed frames (%s)", TimeToString( ftime ) );
        }
    }
    else
    {
        sprintf( buf, "%s %s (%s)", GetFrameSetName( fd ), RealToString( fnum ), TimeToString( ftime ) );
    }
    return buf;
}

const char* View::GetFrameSetName( const FrameData& fd ) const
{
    return GetFrameSetName( fd, m_worker );
}

const char* View::GetFrameSetName( const FrameData& fd, const Worker& worker )
{
    enum { Pool = 4 };
    static char bufpool[Pool][64];
    static int bufsel = 0;

    if( fd.name == 0 )
    {
        return "Frames";
    }
    else if( fd.name >> 63 != 0 )
    {
        char* buf = bufpool[bufsel];
        bufsel = ( bufsel + 1 ) % Pool;
        sprintf( buf, "[%" PRIu32 "] Vsync", uint32_t( fd.name ) );
        return buf;
    }
    else
    {
        return worker.GetString( fd.name );
    }
}

const char* View::GetThreadContextData( uint64_t thread, bool& _local, bool& _untracked, const char*& program )
{
    static char buf[256];
    const auto local = m_worker.IsThreadLocal( thread );
    auto txt = local ? m_worker.GetThreadName( thread ) : m_worker.GetExternalName( thread ).first;
    auto label = txt;
    bool untracked = false;
    if( !local )
    {
        if( m_worker.GetPid() == 0 )
        {
            untracked = strcmp( txt, m_worker.GetCaptureProgram().c_str() ) == 0;
        }
        else
        {
            const auto pid = m_worker.GetPidFromTid( thread );
            untracked = pid == m_worker.GetPid();
            if( untracked )
            {
                label = txt = m_worker.GetExternalName( thread ).second;
            }
            else
            {
                const auto ttxt = m_worker.GetExternalName( thread ).second;
                if( strcmp( ttxt, "???" ) != 0 && strcmp( ttxt, txt ) != 0 )
                {
                    snprintf( buf, 256, "%s (%s)", txt, ttxt );
                    label = buf;
                }
            }
        }
    }
    _local = local;
    _untracked = untracked;
    program = txt;
    return label;
}

void View::Attention( bool& alreadyDone )
{
    if( !alreadyDone )
    {
        alreadyDone = true;
        m_acb();
    }
}

void View::UpdateTitle()
{
    auto captureName = m_worker.GetCaptureName().c_str();
    const auto& desc = m_userData.GetDescription();
    if( !desc.empty() )
    {
        char buf[1024];
        snprintf( buf, 1024, "%s (%s)", captureName, desc.c_str() );
        m_stcb( buf );
    }
    else if( !m_filename.empty() )
    {
        auto fptr = m_filename.c_str() + m_filename.size() - 1;
        while( fptr > m_filename.c_str() && *fptr != '/' && *fptr != '\\' ) fptr--;
        if( *fptr == '/' || *fptr == '\\' ) fptr++;

        char buf[1024];
        snprintf( buf, 1024, "%s (%s)", captureName, fptr );
        m_stcb( buf );
    }
    else
    {
        m_stcb( captureName );
    }
}

}
