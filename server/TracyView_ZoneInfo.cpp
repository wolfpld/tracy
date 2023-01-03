#include <inttypes.h>

#include "TracyFilesystem.hpp"
#include "TracyImGui.hpp"
#include "TracyPrint.hpp"
#include "TracyMouse.hpp"
#include "TracyView.hpp"

namespace tracy
{

extern double s_time;

template<typename T>
static inline uint32_t GetZoneCallstack( const T& ev, const Worker& worker );

template<>
inline uint32_t GetZoneCallstack<ZoneEvent>( const ZoneEvent& ev, const Worker& worker )
{
    return worker.GetZoneExtra( ev ).callstack.Val();
}

template<>
inline uint32_t GetZoneCallstack<GpuEvent>( const GpuEvent& ev, const Worker& worker )
{
    return ev.callstack.Val();
}

void View::CalcZoneTimeData( unordered_flat_map<int16_t, ZoneTimeData>& data, int64_t& ztime, const ZoneEvent& zone )
{
    assert( zone.HasChildren() );
    const auto& children = m_worker.GetZoneChildren( zone.Child() );
    if( children.is_magic() )
    {
        CalcZoneTimeDataImpl<VectorAdapterDirect<ZoneEvent>>( *(Vector<ZoneEvent>*)( &children ), data, ztime, zone );
    }
    else
    {
        CalcZoneTimeDataImpl<VectorAdapterPointer<ZoneEvent>>( children, data, ztime, zone );
    }
}

template<typename Adapter, typename V>
void View::CalcZoneTimeDataImpl( const V& children, unordered_flat_map<int16_t, ZoneTimeData>& data, int64_t& ztime, const ZoneEvent& zone )
{
    Adapter a;
    if( m_timeDist.exclusiveTime )
    {
        int64_t zt = ztime;
        for( auto& child : children )
        {
            const auto t = m_worker.GetZoneEnd( a(child) ) - a(child).Start();
            zt -= t;
        }
        ztime = zt;
    }
    for( auto& child : children )
    {
        const auto srcloc = a(child).SrcLoc();
        const auto t = m_worker.GetZoneEnd( a(child) ) - a(child).Start();
        auto it = data.find( srcloc );
        if( it == data.end() )
        {
            it = data.emplace( srcloc, ZoneTimeData { t, 1 } ).first;
        }
        else
        {
            it->second.time += t;
            it->second.count++;
        }
        if( a(child).Child() >= 0 ) CalcZoneTimeData( data, it->second.time, a(child) );
    }
}

void View::CalcZoneTimeData( const ContextSwitch* ctx, unordered_flat_map<int16_t, ZoneTimeData>& data, int64_t& ztime, const ZoneEvent& zone )
{
    assert( zone.HasChildren() );
    const auto& children = m_worker.GetZoneChildren( zone.Child() );
    if( children.is_magic() )
    {
        CalcZoneTimeDataImpl<VectorAdapterDirect<ZoneEvent>>( *(Vector<ZoneEvent>*)( &children ), ctx, data, ztime, zone );
    }
    else
    {
        CalcZoneTimeDataImpl<VectorAdapterPointer<ZoneEvent>>( children, ctx, data, ztime, zone );
    }
}

template<typename Adapter, typename V>
void View::CalcZoneTimeDataImpl( const V& children, const ContextSwitch* ctx, unordered_flat_map<int16_t, ZoneTimeData>& data, int64_t& ztime, const ZoneEvent& zone )
{
    Adapter a;
    if( m_timeDist.exclusiveTime )
    {
        int64_t zt = ztime;
        for( auto& child : children )
        {
            int64_t t;
            uint64_t cnt;
            const auto res = GetZoneRunningTime( ctx, a(child), t, cnt );
            assert( res );
            zt -= t;
        }
        ztime = zt;
    }
    for( auto& child : children )
    {
        const auto srcloc = a(child).SrcLoc();
        int64_t t;
        uint64_t cnt;
        const auto res = GetZoneRunningTime( ctx, a(child), t, cnt );
        assert( res );
        auto it = data.find( srcloc );
        if( it == data.end() )
        {
            it = data.emplace( srcloc, ZoneTimeData { t, 1 } ).first;
        }
        else
        {
            it->second.time += t;
            it->second.count++;
        }
        if( a(child).HasChildren() ) CalcZoneTimeData( ctx, data, it->second.time, a(child) );
    }
}

template<typename T>
void DrawZoneTrace( T zone, const std::vector<T>& trace, const Worker& worker, BuzzAnim<const void*>& anim, View& view, bool& showUnknownFrames, std::function<void(T, int&)> showZone )
{
    bool expand = ImGui::TreeNode( "Zone trace" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(%s)", RealToString( trace.size() ) );
    if( !expand ) return;

    const auto shortenName = view.GetShortenName();

    ImGui::SameLine();
    SmallCheckbox( "Show unknown frames", &showUnknownFrames );

    int fidx = 1;
    TextDisabledUnformatted( "0." );
    ImGui::SameLine();
    TextDisabledUnformatted( "[this zone]" );

    if( !trace.empty() )
    {
        T prev = zone;
        const auto sz = trace.size();
        for( size_t i=0; i<sz; i++ )
        {
            auto curr = trace[i];
            const auto pcv = GetZoneCallstack( *prev, worker );
            const auto ccv = GetZoneCallstack( *curr, worker );
            if( pcv == 0 || ccv == 0 )
            {
                if( showUnknownFrames )
                {
                    ImGui::TextDisabled( "%i.", fidx++ );
                    ImGui::SameLine();
                    TextDisabledUnformatted( "[unknown frames]" );
                }
            }
            else if( pcv != ccv )
            {
                auto& prevCs = worker.GetCallstack( pcv );
                auto& currCs = worker.GetCallstack( ccv );

                const auto psz = int( prevCs.size() );
                int idx;
                for( idx=0; idx<psz; idx++ )
                {
                    auto pf = prevCs[idx];
                    bool found = false;
                    for( auto& cf : currCs )
                    {
                        if( cf.data == pf.data )
                        {
                            idx--;
                            found = true;
                            break;
                        }
                    }
                    if( found ) break;
                }
                for( int j=1; j<idx; j++ )
                {
                    auto frameData = worker.GetCallstackFrame( prevCs[j] );
                    auto frame = frameData->data + frameData->size - 1;
                    ImGui::TextDisabled( "%i.", fidx++ );
                    ImGui::SameLine();
                    const auto frameName = worker.GetString( frame->name );
                    const auto normalized = shortenName != ShortenName::Never ? ShortenZoneName( ShortenName::OnlyNormalize, frameName ) : frameName;
                    TextDisabledUnformatted( normalized );
                    TooltipNormalizedName( frameName, normalized );
                    ImGui::SameLine();
                    ImGui::Spacing();
                    if( anim.Match( frame ) )
                    {
                        const auto time = anim.Time();
                        const auto indentVal = sin( time * 60.f ) * 10.f * time;
                        ImGui::SameLine( 0, ImGui::GetStyle().ItemSpacing.x + indentVal );
                        s_wasActive = true;
                    }
                    else
                    {
                        ImGui::SameLine();
                    }
                    const auto fileName = worker.GetString( frame->file );
                    TextDisabledUnformatted( LocationToString( fileName, frame->line ) );
                    if( ImGui::IsItemClicked( 1 ) )
                    {
                        if( !view.ViewDispatch( fileName, frame->line, frame->symAddr ) )
                        {
                            anim.Enable( frame, 0.5f );
                        }
                    }
                }
            }

            showZone( curr, fidx );
            prev = curr;
        }
    }

    auto last = trace.empty() ? zone : trace.back();
    const auto lcv = GetZoneCallstack( *last, worker );
    if( lcv == 0 )
    {
        if( showUnknownFrames )
        {
            ImGui::TextDisabled( "%i.", fidx++ );
            ImGui::SameLine();
            TextDisabledUnformatted( "[unknown frames]" );
        }
    }
    else
    {
        auto& cs = worker.GetCallstack( lcv );
        const auto csz = cs.size();
        for( uint16_t i=1; i<csz; i++ )
        {
            auto frameData = worker.GetCallstackFrame( cs[i] );
            auto frame = frameData->data + frameData->size - 1;
            ImGui::TextDisabled( "%i.", fidx++ );
            ImGui::SameLine();
            const auto frameName = worker.GetString( frame->name );
            const auto normalized = shortenName != ShortenName::Never ? ShortenZoneName( ShortenName::OnlyNormalize, frameName ) : frameName;
            TextDisabledUnformatted( normalized );
            TooltipNormalizedName( frameName, normalized );
            ImGui::SameLine();
            ImGui::Spacing();
            if( anim.Match( frame ) )
            {
                const auto time = anim.Time();
                const auto indentVal = sin( time * 60.f ) * 10.f * time;
                ImGui::SameLine( 0, ImGui::GetStyle().ItemSpacing.x + indentVal );
                s_wasActive = true;
            }
            else
            {
                ImGui::SameLine();
            }
            const auto fileName = worker.GetString( frame->file );
            TextDisabledUnformatted( LocationToString( fileName, frame->line ) );
            if( ImGui::IsItemClicked( 1 ) )
            {
                if( !view.ViewDispatch( fileName, frame->line, frame->symAddr ) )
                {
                    anim.Enable( frame, 0.5f );
                }
            }
        }
    }

    ImGui::TreePop();
}

void View::DrawInfoWindow()
{
    if( m_zoneInfoWindow )
    {
        DrawZoneInfoWindow();
    }
    else if( m_gpuInfoWindow )
    {
        DrawGpuInfoWindow();
    }
}

void View::DrawZoneInfoWindow()
{
    auto& ev = *m_zoneInfoWindow;

    const auto& srcloc = m_worker.GetSourceLocation( ev.SrcLoc() );

    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 500 * scale, 600 * scale ), ImGuiCond_FirstUseEver );
    bool show = true;
    ImGui::Begin( "Zone info", &show, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse );
    if( !ImGui::GetCurrentWindowRead()->SkipItems )
    {
        if( ImGui::Button( ICON_FA_MICROSCOPE " Zoom to zone" ) )
        {
            ZoomToZone( ev );
        }
        auto parent = GetZoneParent( ev );
        if( parent )
        {
            ImGui::SameLine();
            if( ImGui::Button( ICON_FA_ARROW_UP " Go to parent" ) )
            {
                ShowZoneInfo( *parent );
            }
        }
#ifndef TRACY_NO_STATISTICS
        if( m_worker.AreSourceLocationZonesReady() )
        {
            const auto sl = ev.SrcLoc();
            const auto& slz = m_worker.GetZonesForSourceLocation( sl );
            if( !slz.zones.empty() )
            {
                ImGui::SameLine();
                if( ImGui::Button( ICON_FA_CHART_BAR " Statistics" ) )
                {
                    m_findZone.ShowZone( sl, m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function ) );
                }
            }
        }
#endif
        if( m_worker.HasZoneExtra( ev ) && m_worker.GetZoneExtra( ev ).callstack.Val() != 0 )
        {
            const auto& extra = m_worker.GetZoneExtra( ev );
            ImGui::SameLine();
            bool hilite = m_callstackInfoWindow == extra.callstack.Val();
            if( hilite )
            {
                SetButtonHighlightColor();
            }
            if( ImGui::Button( ICON_FA_ALIGN_JUSTIFY " Call stack" ) )
            {
                m_callstackInfoWindow = extra.callstack.Val();
            }
            if( hilite )
            {
                ImGui::PopStyleColor( 3 );
            }
        }
        const auto fileName = m_worker.GetString( srcloc.file );
        if( SourceFileValid( fileName, m_worker.GetCaptureTime(), *this, m_worker ) )
        {
            ImGui::SameLine();
            bool hilite = m_sourceViewFile == fileName;
            if( hilite )
            {
                SetButtonHighlightColor();
            }
            if( ImGui::Button( ICON_FA_FILE_LINES " Source" ) )
            {
                ViewSource( fileName, srcloc.line );
            }
            if( hilite )
            {
                ImGui::PopStyleColor( 3 );
            }
        }
        if( !m_zoneInfoStack.empty() )
        {
            ImGui::SameLine();
            if( ImGui::Button( ICON_FA_ARROW_LEFT " Go back" ) )
            {
                m_zoneInfoWindow = m_zoneInfoStack.back_and_pop();
            }
        }

        ImGui::Separator();

        auto threadData = GetZoneThreadData( ev );
        assert( threadData );
        const auto tid = threadData->id;
        if( m_worker.HasZoneExtra( ev ) && m_worker.GetZoneExtra( ev ).name.Active() )
        {
            ImGui::PushFont( m_bigFont );
            TextFocused( "Zone name:", m_worker.GetString( m_worker.GetZoneExtra( ev ).name ) );
            ImGui::PopFont();
            if( srcloc.name.active )
            {
                ImGui::SameLine();
                ImGui::TextDisabled( "(%s)", m_worker.GetString( srcloc.name ) );
            }
            ImGui::SameLine();
            if( ClipboardButton( 1 ) )
            {
                if( srcloc.name.active )
                {
                    char tmp[1024];
                    sprintf( tmp, "%s (%s)", m_worker.GetString( m_worker.GetZoneExtra( ev ).name ), m_worker.GetString( srcloc.name ) );
                    ImGui::SetClipboardText( tmp );
                }
                else
                {
                    ImGui::SetClipboardText( m_worker.GetString( m_worker.GetZoneExtra( ev ).name ) );
                }
            }
            TextFocused( "Function:", m_worker.GetString( srcloc.function ) );
            ImGui::SameLine();
            if( ClipboardButton( 2 ) ) ImGui::SetClipboardText( m_worker.GetString( srcloc.function ) );
        }
        else if( srcloc.name.active )
        {
            ImGui::PushFont( m_bigFont );
            TextFocused( "Zone name:", m_worker.GetString( srcloc.name ) );
            ImGui::PopFont();
            ImGui::SameLine();
            if( ClipboardButton( 1 ) ) ImGui::SetClipboardText( m_worker.GetString( srcloc.name ) );
            TextFocused( "Function:", m_worker.GetString( srcloc.function ) );
            ImGui::SameLine();
            if( ClipboardButton( 2 ) ) ImGui::SetClipboardText( m_worker.GetString( srcloc.function ) );
        }
        else
        {
            ImGui::PushFont( m_bigFont );
            TextFocused( "Function:", m_worker.GetString( srcloc.function ) );
            ImGui::PopFont();
            ImGui::SameLine();
            if( ClipboardButton( 1 ) ) ImGui::SetClipboardText( m_worker.GetString( srcloc.function ) );
        }
        SmallColorBox( GetSrcLocColor( m_worker.GetSourceLocation( ev.SrcLoc() ), 0 ) );
        ImGui::SameLine();
        TextDisabledUnformatted( "Location:" );
        ImGui::SameLine();
        ImGui::TextUnformatted( LocationToString( m_worker.GetString( srcloc.file ), srcloc.line ) );
        ImGui::SameLine();
        if( ClipboardButton( 3 ) )
        {
            ImGui::SetClipboardText( LocationToString( m_worker.GetString( srcloc.file ), srcloc.line ) );
        }
        SmallColorBox( GetThreadColor( tid, 0 ) );
        ImGui::SameLine();
        TextFocused( "Thread:", m_worker.GetThreadName( tid ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s)", RealToString( tid ) );
        if( m_worker.IsThreadFiber( tid ) )
        {
            ImGui::SameLine();
            TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
        }
        if( m_worker.HasZoneExtra( ev ) && m_worker.GetZoneExtra( ev ).text.Active() )
        {
            TextFocused( "User text:", m_worker.GetString( m_worker.GetZoneExtra( ev ).text ) );
        }

        ImGui::Separator();
        ImGui::BeginChild( "##zoneinfo" );

        const auto end = m_worker.GetZoneEnd( ev );
        const auto ztime = end - ev.Start();
        const auto selftime = GetZoneSelfTime( ev );
        TextFocused( "Time from start of program:", TimeToStringExact( ev.Start() ) );
        TextFocused( "Execution time:", TimeToString( ztime ) );
#ifndef TRACY_NO_STATISTICS
        if( m_worker.AreSourceLocationZonesReady() )
        {
            auto& zoneData = m_worker.GetZonesForSourceLocation( ev.SrcLoc() );
            if( zoneData.total > 0 )
            {
                ImGui::SameLine();
                ImGui::TextDisabled( "(%.2f%% of mean time)", float( ztime ) / zoneData.total * zoneData.zones.size() * 100 );
            }
        }
#endif
        TextFocused( "Self time:", TimeToString( selftime ) );
        if( ztime != 0 )
        {
            char buf[64];
            PrintStringPercent( buf, 100.f * selftime / ztime );
            ImGui::SameLine();
            TextDisabledUnformatted( buf );
        }
        const auto ctx = m_worker.GetContextSwitchData( tid );
        if( ctx )
        {
            auto it = std::lower_bound( ctx->v.begin(), ctx->v.end(), ev.Start(), [] ( const auto& l, const auto& r ) { return (uint64_t)l.End() < (uint64_t)r; } );
            if( it != ctx->v.end() )
            {
                const auto end = m_worker.GetZoneEnd( ev );
                auto eit = std::upper_bound( it, ctx->v.end(), end, [] ( const auto& l, const auto& r ) { return l < r.Start(); } );
                bool incomplete = eit == ctx->v.end() && !m_worker.IsThreadFiber( tid );
                uint64_t cnt = std::distance( it, eit );
                if( cnt == 1 )
                {
                    if( !incomplete )
                    {
                        TextFocused( "Running state time:", TimeToString( ztime ) );
                        ImGui::SameLine();
                        TextDisabledUnformatted( "(100%)" );
                        ImGui::Separator();
                        TextFocused( "Running state regions:", "1" );
                        if( !threadData->isFiber ) TextFocused( "CPU:", RealToString( it->Cpu() ) );
                    }
                }
                else if( cnt > 1 )
                {
                    uint8_t cpus[256] = {};
                    auto bit = it;
                    int64_t running = it->End() - ev.Start();
                    cpus[it->Cpu()] = 1;
                    ++it;
                    for( uint64_t i=0; i<cnt-2; i++ )
                    {
                        running += it->End() - it->Start();
                        cpus[it->Cpu()] = 1;
                        ++it;
                    }
                    running += end - it->Start();
                    cpus[it->Cpu()] = 1;
                    TextFocused( "Running state time:", TimeToString( running ) );
                    if( ztime != 0 )
                    {
                        char buf[64];
                        PrintStringPercent( buf, 100.f * running / ztime );
                        ImGui::SameLine();
                        TextDisabledUnformatted( buf );
                    }
                    ImGui::Separator();
                    if( incomplete )
                    {
                        TextColoredUnformatted( ImVec4( 1, 0, 0, 1 ), "Incomplete context switch data!" );
                    }
                    TextFocused( "Running state regions:", RealToString( cnt ) );

                    if( !threadData->isFiber )
                    {
                        int numCpus = 0;
                        for( int i=0; i<256; i++ ) numCpus += cpus[i];
                        if( numCpus == 1 )
                        {
                            TextFocused( "CPU:", RealToString( it->Cpu() ) );
                        }
                        else
                        {
                            ImGui::TextDisabled( "CPUs (%i):", numCpus );
                            for( int i=0;; i++ )
                            {
                                if( cpus[i] != 0 )
                                {
                                    ImGui::SameLine();
                                    numCpus--;
                                    if( numCpus == 0 )
                                    {
                                        ImGui::Text( "%i", i );
                                        break;
                                    }
                                    else
                                    {
                                        int consecutive = 1;
                                        int remaining = numCpus;
                                        for(;;)
                                        {
                                            if( cpus[i+consecutive] == 0 ) break;
                                            consecutive++;
                                            if( --remaining == 0 ) break;
                                        }
                                        if( consecutive > 2 )
                                        {
                                            if( remaining == 0 )
                                            {
                                                ImGui::Text( "%i \xE2\x80\x93 %i", i, i+consecutive-1 );
                                                break;
                                            }
                                            else
                                            {
                                                ImGui::Text( "%i \xE2\x80\x93 %i,", i, i+consecutive-1 );
                                                i += consecutive - 1;
                                                numCpus = remaining;
                                            }
                                        }
                                        else
                                        {
                                            ImGui::Text( "%i,", i );
                                        }
                                    }
                                }
                            }
                        }
                    }

                    --eit;
                    if( ImGui::TreeNode( "Wait regions" ) )
                    {
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        SmallCheckbox( "Time relative to zone start", &m_ctxSwitchTimeRelativeToZone );
                        const int64_t adjust = m_ctxSwitchTimeRelativeToZone ? ev.Start() : 0;
                        const auto wrsz = eit - bit;

                        const auto numColumns = threadData->isFiber ? 4 : 6;
                        if( ImGui::BeginTable( "##waitregions", numColumns, ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable, ImVec2( 0, ImGui::GetTextLineHeightWithSpacing() * std::min<int64_t>( 1+wrsz, 15 ) ) ) )
                        {
                            ImGui::TableSetupScrollFreeze( 0, 1 );
                            ImGui::TableSetupColumn( "Begin" );
                            ImGui::TableSetupColumn( "End" );
                            ImGui::TableSetupColumn( "Time" );
                            if( threadData->isFiber )
                            {
                                ImGui::TableSetupColumn( "Thread" );
                            }
                            else
                            {
                                ImGui::TableSetupColumn( "Wakeup" );
                                ImGui::TableSetupColumn( "CPU" );
                                ImGui::TableSetupColumn( "State" );
                            }
                            ImGui::TableHeadersRow();

                            ImGuiListClipper clipper;
                            clipper.Begin( wrsz );
                            while( clipper.Step() )
                            {
                                for( auto i=clipper.DisplayStart; i<clipper.DisplayEnd; i++ )
                                {
                                    const auto cend = bit[i].End();
                                    const auto cstart = bit[i+1].Start();
                                    const auto cwakeup = bit[i+1].WakeupVal();

                                    ImGui::PushID( i );
                                    ImGui::TableNextRow();
                                    ImGui::TableNextColumn();

                                    auto tt = adjust == 0 ? TimeToStringExact( cend ) : TimeToString( cend - adjust );
                                    if( ImGui::Selectable( tt ) )
                                    {
                                        CenterAtTime( cend );
                                    }
                                    ImGui::TableNextColumn();
                                    tt = adjust == 0 ? TimeToStringExact( cstart ) : TimeToString( cstart - adjust );
                                    if( ImGui::Selectable( tt ) )
                                    {
                                        CenterAtTime( cstart );
                                    }
                                    ImGui::TableNextColumn();
                                    if( ImGui::Selectable( TimeToString( cwakeup - cend ) ) )
                                    {
                                        ZoomToRange( cend, cwakeup );
                                    }
                                    ImGui::TableNextColumn();
                                    if( threadData->isFiber )
                                    {
                                        const auto ftid = m_worker.DecompressThread( bit[i].Thread() );
                                        ImGui::TextUnformatted( m_worker.GetThreadName( ftid ) );
                                        ImGui::SameLine();
                                        ImGui::TextDisabled( "(%s)", RealToString( ftid ) );
                                    }
                                    else
                                    {
                                        const auto cpu0 = bit[i].Cpu();
                                        const auto reason = bit[i].Reason();
                                        const auto state = bit[i].State();
                                        const auto cpu1 = bit[i+1].Cpu();

                                        if( cstart != cwakeup )
                                        {
                                            if( ImGui::Selectable( TimeToString( cstart - cwakeup ) ) )
                                            {
                                                ZoomToRange( cwakeup, cstart );
                                            }
                                        }
                                        else
                                        {
                                            ImGui::TextUnformatted( "-" );
                                        }
                                        ImGui::TableNextColumn();
                                        if( cpu0 == cpu1 )
                                        {
                                            ImGui::TextUnformatted( RealToString( cpu0 ) );
                                        }
                                        else
                                        {
                                            ImGui::Text( "%i " ICON_FA_RIGHT_LONG " %i", cpu0, cpu1 );
                                            const auto tt0 = m_worker.GetThreadTopology( cpu0 );
                                            const auto tt1 = m_worker.GetThreadTopology( cpu1 );
                                            if( tt0 && tt1 )
                                            {
                                                if( tt0->package != tt1->package )
                                                {
                                                    ImGui::SameLine();
                                                    TextDisabledUnformatted( "P" );
                                                }
                                                else if( tt0->core != tt1->core )
                                                {
                                                    ImGui::SameLine();
                                                    TextDisabledUnformatted( "C" );
                                                }
                                            }
                                        }
                                        ImGui::TableNextColumn();
                                        const char* desc;
                                        if( reason == ContextSwitchData::NoState )
                                        {
                                            ImGui::TextUnformatted( DecodeContextSwitchStateCode( state ) );
                                            desc = DecodeContextSwitchState( state );
                                        }
                                        else
                                        {
                                            ImGui::TextUnformatted( DecodeContextSwitchReasonCode( reason ) );
                                            desc = DecodeContextSwitchReason( reason );
                                        }
                                        if( *desc ) TooltipIfHovered( desc );
                                    }
                                    ImGui::PopID();
                                }
                            }
                            ImGui::EndTable();
                        }
                        ImGui::TreePop();
                    }
                }
            }
        }

        ImGui::Separator();
        auto& memNameMap = m_worker.GetMemNameMap();
        if( memNameMap.size() > 1 )
        {
            ImGui::AlignTextToFramePadding();
            TextDisabledUnformatted( ICON_FA_BOX_ARCHIVE " Memory pool:" );
            ImGui::SameLine();
            if( ImGui::BeginCombo( "##memoryPool", m_zoneInfoMemPool == 0 ? "Default allocator" : m_worker.GetString( m_zoneInfoMemPool ) ) )
            {
                for( auto& v : memNameMap )
                {
                    if( ImGui::Selectable( v.first == 0 ? "Default allocator" : m_worker.GetString( v.first ) ) )
                    {
                        m_zoneInfoMemPool = v.first;
                    }
                }
                ImGui::EndCombo();
            }
        }
        auto& mem = m_worker.GetMemoryNamed( m_zoneInfoMemPool );
        if( mem.data.empty() )
        {
            TextDisabledUnformatted( "No memory events." );
        }
        else
        {
            if( !mem.plot )
            {
                ImGui::Text( "Please wait, computing data..." );
                DrawWaitingDots( s_time );
            }
            else
            {
                const auto thread = m_worker.CompressThread( tid );

                auto ait = std::lower_bound( mem.data.begin(), mem.data.end(), ev.Start(), [] ( const auto& l, const auto& r ) { return l.TimeAlloc() < r; } );
                const auto aend = std::upper_bound( ait, mem.data.end(), end, [] ( const auto& l, const auto& r ) { return l < r.TimeAlloc(); } );

                auto fit = std::lower_bound( mem.frees.begin(), mem.frees.end(), ev.Start(), [&mem] ( const auto& l, const auto& r ) { return mem.data[l].TimeFree() < r; } );
                const auto fend = std::upper_bound( fit, mem.frees.end(), end, [&mem] ( const auto& l, const auto& r ) { return l < mem.data[r].TimeFree(); } );

                const auto aDist = std::distance( ait, aend );
                const auto fDist = std::distance( fit, fend );
                if( aDist == 0 && fDist == 0 )
                {
                    TextDisabledUnformatted( "No memory events." );
                }
                else
                {
                    int64_t cAlloc = 0;
                    int64_t cFree = 0;
                    int64_t nAlloc = 0;
                    int64_t nFree = 0;

                    auto ait2 = ait;
                    auto fit2 = fit;

                    while( ait != aend )
                    {
                        if( ait->ThreadAlloc() == thread )
                        {
                            cAlloc += ait->Size();
                            nAlloc++;
                        }
                        ait++;
                    }
                    while( fit != fend )
                    {
                        if( mem.data[*fit].ThreadFree() == thread )
                        {
                            cFree += mem.data[*fit].Size();
                            nFree++;
                        }
                        fit++;
                    }

                    if( nAlloc == 0 && nFree == 0 )
                    {
                        TextDisabledUnformatted( "No memory events." );
                    }
                    else
                    {
                        ImGui::TextUnformatted( RealToString( nAlloc + nFree ) );
                        ImGui::SameLine();
                        TextDisabledUnformatted( "memory events." );
                        ImGui::TextUnformatted( RealToString( nAlloc ) );
                        ImGui::SameLine();
                        TextDisabledUnformatted( "allocs," );
                        ImGui::SameLine();
                        ImGui::TextUnformatted( RealToString( nFree ) );
                        ImGui::SameLine();
                        TextDisabledUnformatted( "frees." );
                        TextFocused( "Memory allocated:", MemSizeToString( cAlloc ) );
                        TextFocused( "Memory freed:", MemSizeToString( cFree ) );
                        TextFocused( "Overall change:", MemSizeToString( cAlloc - cFree ) );

                        if( ImGui::TreeNode( "Allocations list" ) )
                        {
                            ImGui::SameLine();
                            ImGui::Spacing();
                            ImGui::SameLine();
                            SmallCheckbox( "Time relative to zone start", &m_allocTimeRelativeToZone );

                            std::vector<const MemEvent*> v;
                            v.reserve( nAlloc + nFree );

                            auto it = ait2;
                            while( it != aend )
                            {
                                if( it->ThreadAlloc() == thread )
                                {
                                    v.emplace_back( it );
                                }
                                it++;
                            }
                            while( fit2 != fend )
                            {
                                const auto ptr = &mem.data[*fit2++];
                                if( ptr->ThreadFree() == thread )
                                {
                                    if( ptr < ait2 || ptr >= aend )
                                    {
                                        v.emplace_back( ptr );
                                    }
                                }
                            }
                            pdqsort_branchless( v.begin(), v.end(), [] ( const auto& l, const auto& r ) { return l->TimeAlloc() < r->TimeAlloc(); } );

                            ListMemData( v, []( auto v ) {
                                ImGui::Text( "0x%" PRIx64, v->Ptr() );
                                }, nullptr, m_allocTimeRelativeToZone ? ev.Start() : -1, m_zoneInfoMemPool );
                            ImGui::TreePop();
                        }
                    }
                }
            }
        }

        ImGui::Separator();
        {
            if( threadData->messages.empty() )
            {
                TextDisabledUnformatted( "No messages" );
            }
            else
            {
                auto msgit = std::lower_bound( threadData->messages.begin(), threadData->messages.end(), ev.Start(), [] ( const auto& lhs, const auto& rhs ) { return lhs->time < rhs; } );
                auto msgend = std::lower_bound( msgit, threadData->messages.end(), end+1, [] ( const auto& lhs, const auto& rhs ) { return lhs->time < rhs; } );

                const auto dist = std::distance( msgit, msgend );
                if( dist == 0 )
                {
                    TextDisabledUnformatted( "No messages" );
                }
                else
                {
                    bool expand = ImGui::TreeNode( "Messages" );
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(%s)", RealToString( dist ) );
                    if( expand )
                    {
                        ImGui::SameLine();
                        SmallCheckbox( "Time relative to zone start", &m_messageTimeRelativeToZone );
                        ImGui::SameLine();
                        SmallCheckbox( "Exclude children", &m_messagesExcludeChildren );
                        if( ImGui::BeginTable( "##messages", 2, ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV, ImVec2( 0, ImGui::GetTextLineHeightWithSpacing() * std::min<int64_t>( msgend-msgit+1, 15 ) ) ) )
                        {
                            ImGui::TableSetupScrollFreeze( 0, 1 );
                            ImGui::TableSetupColumn( "Time", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
                            ImGui::TableSetupColumn( "Message" );
                            ImGui::TableHeadersRow();
                            do
                            {
                                if( m_messagesExcludeChildren && GetZoneChild( ev, (*msgit)->time ) ) continue;
                                ImGui::PushID( *msgit );
                                ImGui::TableNextRow();
                                ImGui::TableNextColumn();
                                if( ImGui::Selectable( m_messageTimeRelativeToZone ? TimeToString( (*msgit)->time - ev.Start() ) : TimeToStringExact( (*msgit)->time ), m_msgHighlight == *msgit, ImGuiSelectableFlags_SpanAllColumns ) )
                                {
                                    CenterAtTime( (*msgit)->time );
                                }
                                if( ImGui::IsItemHovered() )
                                {
                                    m_msgHighlight = *msgit;
                                }
                                ImGui::PopID();
                                ImGui::TableNextColumn();
                                ImGui::PushStyleColor( ImGuiCol_Text, (*msgit)->color );
                                ImGui::TextWrapped( "%s", m_worker.GetString( (*msgit)->ref ) );
                                ImGui::PopStyleColor();
                            }
                            while( ++msgit != msgend );
                            ImGui::EndTable();
                        }
                        ImGui::TreePop();
                        ImGui::Spacing();
                    }
                }
            }
        }

        ImGui::Separator();

        std::vector<const ZoneEvent*> zoneTrace;
        while( parent )
        {
            zoneTrace.emplace_back( parent );
            parent = GetZoneParent( *parent );
        }
        int idx = 0;
        DrawZoneTrace<const ZoneEvent*>( &ev, zoneTrace, m_worker, m_zoneinfoBuzzAnim, *this, m_showUnknownFrames, [&idx, this] ( const ZoneEvent* v, int& fidx ) {
            ImGui::TextDisabled( "%i.", fidx++ );
            ImGui::SameLine();
            const auto& srcloc = m_worker.GetSourceLocation( v->SrcLoc() );
            SmallColorBox( GetSrcLocColor( srcloc, 0 ) );
            ImGui::SameLine();
            const auto txt = m_worker.GetZoneName( *v, srcloc );
            ImGui::PushID( idx++ );
            auto sel = ImGui::Selectable( txt, false );
            auto hover = ImGui::IsItemHovered();
            const auto fileName = m_worker.GetString( srcloc.file );
            if( m_zoneinfoBuzzAnim.Match( v ) )
            {
                const auto time = m_zoneinfoBuzzAnim.Time();
                const auto indentVal = sin( time * 60.f ) * 10.f * time;
                ImGui::SameLine( 0, ImGui::GetStyle().ItemSpacing.x + indentVal );
            }
            else
            {
                ImGui::SameLine();
            }
            ImGui::TextDisabled( "(%s) %s", TimeToString( m_worker.GetZoneEnd( *v ) - v->Start() ), LocationToString( fileName, srcloc.line ) );
            ImGui::PopID();
            if( ImGui::IsItemClicked( 1 ) )
            {
                if( SourceFileValid( fileName, m_worker.GetCaptureTime(), *this, m_worker ) )
                {
                    ViewSource( fileName, srcloc.line );
                }
                else
                {
                    m_zoneinfoBuzzAnim.Enable( v, 0.5f );
                }
            }
            if( sel )
            {
                ShowZoneInfo( *v );
            }
            if( hover )
            {
                m_zoneHighlight = v;
                if( IsMouseClicked( 2 ) )
                {
                    ZoomToZone( *v );
                }
                ZoneTooltip( *v );
            }
            } );

        if( ev.HasChildren() )
        {
            const auto& children = m_worker.GetZoneChildren( ev.Child() );
            bool expand = ImGui::TreeNode( "Child zones" );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s)", RealToString( children.size() ) );
            if( expand )
            {
                if( children.is_magic() )
                {
                    DrawZoneInfoChildren<VectorAdapterDirect<ZoneEvent>>( *(Vector<ZoneEvent>*)( &children ), ztime );
                }
                else
                {
                    DrawZoneInfoChildren<VectorAdapterPointer<ZoneEvent>>( children, ztime );
                }
                ImGui::TreePop();
            }

            expand = ImGui::TreeNode( "Time distribution" );
            if( expand )
            {
                ImGui::SameLine();
                if( SmallCheckbox( "Self time", &m_timeDist.exclusiveTime ) ) m_timeDist.dataValidFor = nullptr;
                if( ctx )
                {
                    ImGui::SameLine();
                    if( SmallCheckbox( "Running time", &m_timeDist.runningTime ) ) m_timeDist.dataValidFor = nullptr;
                }
                if( m_timeDist.dataValidFor != &ev )
                {
                    m_timeDist.data.clear();
                    if( ev.IsEndValid() ) m_timeDist.dataValidFor = &ev;

                    if( m_timeDist.runningTime )
                    {
                        assert( ctx );
                        int64_t time;
                        uint64_t cnt;
                        if( !GetZoneRunningTime( ctx, ev, time, cnt ) )
                        {
                            TextDisabledUnformatted( "Incomplete context switch data." );
                            m_timeDist.dataValidFor = nullptr;
                        }
                        else
                        {
                            auto it = m_timeDist.data.emplace( ev.SrcLoc(), ZoneTimeData{ time, 1 } ).first;
                            CalcZoneTimeData( ctx, m_timeDist.data, it->second.time, ev );
                        }
                        m_timeDist.fztime = 100.f / time;
                    }
                    else
                    {
                        auto it = m_timeDist.data.emplace( ev.SrcLoc(), ZoneTimeData{ ztime, 1 } ).first;
                        CalcZoneTimeData( m_timeDist.data, it->second.time, ev );
                        m_timeDist.fztime = 100.f / ztime;
                    }
                }
                if( !m_timeDist.data.empty() )
                {
                    std::vector<unordered_flat_map<int16_t, ZoneTimeData>::const_iterator> vec;
                    vec.reserve( m_timeDist.data.size() );
                    for( auto it = m_timeDist.data.cbegin(); it != m_timeDist.data.cend(); ++it ) vec.emplace_back( it );
                    if( ImGui::BeginTable( "##timedist", 3, ImGuiTableFlags_Sortable | ImGuiTableFlags_BordersInnerV ) )
                    {
                        ImGui::TableSetupColumn( "Zone", ImGuiTableColumnFlags_PreferSortDescending );
                        ImGui::TableSetupColumn( "Time", ImGuiTableColumnFlags_PreferSortDescending | ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
                        ImGui::TableSetupColumn( "MTPC", ImGuiTableColumnFlags_PreferSortDescending | ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
                        ImGui::TableHeadersRow();
                        const auto& sortspec = *ImGui::TableGetSortSpecs()->Specs;
                        switch( sortspec.ColumnIndex )
                        {
                        case 0:
                            if( sortspec.SortDirection == ImGuiSortDirection_Ascending )
                            {
                                pdqsort_branchless( vec.begin(), vec.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.count < rhs->second.count; } );
                            }
                            else
                            {
                                pdqsort_branchless( vec.begin(), vec.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.count > rhs->second.count; } );
                            }
                            break;
                        case 1:
                            if( sortspec.SortDirection == ImGuiSortDirection_Ascending )
                            {
                                pdqsort_branchless( vec.begin(), vec.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.time < rhs->second.time; } );
                            }
                            else
                            {
                                pdqsort_branchless( vec.begin(), vec.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.time > rhs->second.time; } );
                            }
                            break;
                        case 2:
                            if( sortspec.SortDirection == ImGuiSortDirection_Ascending )
                            {
                                pdqsort_branchless( vec.begin(), vec.end(), []( const auto& lhs, const auto& rhs ) { return float( lhs->second.time ) / lhs->second.count < float( rhs->second.time ) / rhs->second.count; } );
                            }
                            else
                            {
                                pdqsort_branchless( vec.begin(), vec.end(), []( const auto& lhs, const auto& rhs ) { return float( lhs->second.time ) / lhs->second.count > float( rhs->second.time ) / rhs->second.count; } );
                            }
                            break;
                        default:
                            assert( false );
                            break;
                        }
                        for( auto& v : vec )
                        {
                            ImGui::TableNextRow();
                            ImGui::TableNextColumn();
                            const auto& sl = m_worker.GetSourceLocation( v->first );
                            SmallColorBox( GetSrcLocColor( sl, 0 ) );
                            ImGui::SameLine();
                            const auto name = m_worker.GetZoneName( sl );
                            if( ImGui::Selectable( name, false, ImGuiSelectableFlags_SpanAllColumns ) )
                            {
                                m_findZone.ShowZone( v->first, name, ev.Start(), m_worker.GetZoneEnd( ev ) );
                            }
                            ImGui::SameLine();
                            ImGui::TextDisabled( "(\xc3\x97%s)", RealToString( v->second.count ) );
                            ImGui::TableNextColumn();
                            ImGui::TextUnformatted( TimeToString( v->second.time ) );
                            ImGui::SameLine();
                            char buf[64];
                            PrintStringPercent( buf, v->second.time * m_timeDist.fztime );
                            TextDisabledUnformatted( buf );
                            ImGui::TableNextColumn();
                            ImGui::TextUnformatted( TimeToString( v->second.time / v->second.count ) );
                        }
                        ImGui::EndTable();
                    }
                }
                ImGui::TreePop();
            }
        }

        ImGui::EndChild();
    }
    ImGui::End();

    if( !show )
    {
        m_zoneInfoWindow = nullptr;
        m_zoneInfoStack.clear();
    }
}

template<typename Adapter, typename V>
void View::DrawZoneInfoChildren( const V& children, int64_t ztime )
{
    Adapter a;
    const auto rztime = 1.0 / ztime;
    const auto ty = ImGui::GetTextLineHeight();

    ImGui::SameLine();
    SmallCheckbox( "Group children locations", &m_groupChildrenLocations );

    if( m_groupChildrenLocations )
    {
        struct ChildGroup
        {
            int16_t srcloc;
            uint64_t t;
            Vector<uint32_t> v;
        };
        uint64_t ctime = 0;
        unordered_flat_map<int16_t, ChildGroup> cmap;
        cmap.reserve( 128 );
        for( size_t i=0; i<children.size(); i++ )
        {
            const auto& child = a(children[i]);
            const auto cend = m_worker.GetZoneEnd( child );
            const auto ct = cend - child.Start();
            const auto srcloc = child.SrcLoc();
            ctime += ct;

            auto it = cmap.find( srcloc );
            if( it == cmap.end() ) it = cmap.emplace( srcloc, ChildGroup { srcloc } ).first;

            it->second.t += ct;
            it->second.v.push_back( i );
        }

        auto msz = cmap.size();
        Vector<ChildGroup*> cgvec;
        cgvec.reserve_and_use( msz );
        size_t idx = 0;
        for( auto& it : cmap )
        {
            cgvec[idx++] = &it.second;
        }

        pdqsort_branchless( cgvec.begin(), cgvec.end(), []( const auto& lhs, const auto& rhs ) { return lhs->t > rhs->t; } );

        ImGui::Columns( 2 );
        ImGui::Indent( ImGui::GetTreeNodeToLabelSpacing() * 2 );
        TextColoredUnformatted( ImVec4( 1.0f, 1.0f, 0.4f, 1.0f ), "Self time" );
        ImGui::Unindent( ImGui::GetTreeNodeToLabelSpacing() * 2 );
        ImGui::NextColumn();
        char buf[128];
        PrintStringPercent( buf, TimeToString( ztime - ctime ), double( ztime - ctime ) / ztime * 100 );
        ImGui::ProgressBar( double( ztime - ctime ) * rztime, ImVec2( -1, ty ), buf );
        ImGui::NextColumn();
        for( size_t i=0; i<msz; i++ )
        {
            bool expandGroup = false;
            const auto& cgr = *cgvec[i];
            const auto& srcloc = m_worker.GetSourceLocation( cgr.srcloc );
            const auto txt = m_worker.GetZoneName( srcloc );
            if( cgr.v.size() == 1 )
            {
                auto& cev = a(children[cgr.v.front()]);
                const auto txt = m_worker.GetZoneName( cev );
                SmallColorBox( GetSrcLocColor( srcloc, 0 ) );
                ImGui::SameLine();
                ImGui::PushID( (int)cgr.v.front() );
                ImGui::TreeNodeEx( txt, ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen );
                if( ImGui::IsItemClicked() )
                {
                    ShowZoneInfo( cev );
                }
                if( ImGui::IsItemHovered() )
                {
                    m_zoneHighlight = &cev;
                    if( IsMouseClicked( 2 ) )
                    {
                        ZoomToZone( cev );
                    }
                    ZoneTooltip( cev );
                }
                ImGui::PopID();
            }
            else
            {
                SmallColorBox( GetSrcLocColor( srcloc, 0 ) );
                ImGui::SameLine();
                ImGui::PushID( cgr.srcloc );
                expandGroup = ImGui::TreeNode( txt );
                ImGui::PopID();
                if( ImGui::IsItemHovered() )
                {
                    ImGui::BeginTooltip();
                    if( srcloc.name.active )
                    {
                        ImGui::TextUnformatted( m_worker.GetString( srcloc.name ) );
                    }
                    ImGui::TextUnformatted( m_worker.GetString( srcloc.function ) );
                    ImGui::Separator();
                    ImGui::TextUnformatted( LocationToString( m_worker.GetString( srcloc.file ), srcloc.line ) );
                    ImGui::EndTooltip();
                }
                ImGui::SameLine();
                ImGui::TextDisabled( "(\xc3\x97%s)", RealToString( cgr.v.size() ) );
            }
            ImGui::NextColumn();
            const auto part = double( cgr.t ) * rztime;
            char buf[128];
            PrintStringPercent( buf, TimeToString( cgr.t ), part * 100 );
            ImGui::ProgressBar( part, ImVec2( -1, ty ), buf );
            ImGui::NextColumn();
            if( expandGroup )
            {
                auto ctt = std::unique_ptr<uint64_t[]>( new uint64_t[cgr.v.size()] );
                auto cti = std::unique_ptr<uint32_t[]>( new uint32_t[cgr.v.size()] );
                for( size_t i=0; i<cgr.v.size(); i++ )
                {
                    const auto& child = a(children[cgr.v[i]]);
                    const auto cend = m_worker.GetZoneEnd( child );
                    const auto ct = cend - child.Start();
                    ctt[i] = ct;
                    cti[i] = uint32_t( i );
                }

                pdqsort_branchless( cti.get(), cti.get() + cgr.v.size(), [&ctt] ( const auto& lhs, const auto& rhs ) { return ctt[lhs] > ctt[rhs]; } );

                ImGuiListClipper clipper;
                clipper.Begin( cgr.v.size() );
                while( clipper.Step() )
                {
                    for( auto i=clipper.DisplayStart; i<clipper.DisplayEnd; i++ )
                    {
                        auto& cev = a(children[cgr.v[cti[i]]]);
                        const auto txt = m_worker.GetZoneName( cev );
                        bool b = false;
                        ImGui::Indent();
                        ImGui::PushID( (int)cgr.v[cti[i]] );
                        if( ImGui::Selectable( txt, &b, ImGuiSelectableFlags_SpanAllColumns ) )
                        {
                            ShowZoneInfo( cev );
                        }
                        if( ImGui::IsItemHovered() )
                        {
                            m_zoneHighlight = &cev;
                            if( IsMouseClicked( 2 ) )
                            {
                                ZoomToZone( cev );
                            }
                            ZoneTooltip( cev );
                        }
                        ImGui::PopID();
                        ImGui::Unindent();
                        ImGui::NextColumn();
                        const auto part = double( ctt[cti[i]] ) * rztime;
                        char buf[128];
                        PrintStringPercent( buf, TimeToString( ctt[cti[i]] ), part * 100 );
                        ImGui::ProgressBar( part, ImVec2( -1, ty ), buf );
                        ImGui::NextColumn();
                    }
                }
                ImGui::TreePop();
            }
        }
        ImGui::EndColumns();
    }
    else
    {
        auto ctt = std::unique_ptr<uint64_t[]>( new uint64_t[children.size()] );
        auto cti = std::unique_ptr<uint32_t[]>( new uint32_t[children.size()] );
        uint64_t ctime = 0;
        for( size_t i=0; i<children.size(); i++ )
        {
            const auto& child = a(children[i]);
            const auto cend = m_worker.GetZoneEnd( child );
            const auto ct = cend - child.Start();
            ctime += ct;
            ctt[i] = ct;
            cti[i] = uint32_t( i );
        }

        pdqsort_branchless( cti.get(), cti.get() + children.size(), [&ctt] ( const auto& lhs, const auto& rhs ) { return ctt[lhs] > ctt[rhs]; } );

        ImGui::Columns( 2 );
        ImGui::Indent( ImGui::GetTreeNodeToLabelSpacing() );
        TextColoredUnformatted( ImVec4( 1.0f, 1.0f, 0.4f, 1.0f ), "Self time" );
        ImGui::Unindent( ImGui::GetTreeNodeToLabelSpacing() );
        ImGui::NextColumn();
        char buf[128];
        PrintStringPercent( buf, TimeToString( ztime - ctime ), double( ztime - ctime ) / ztime * 100 );
        ImGui::ProgressBar( double( ztime - ctime ) * rztime, ImVec2( -1, ty ), buf );
        ImGui::NextColumn();
        ImGuiListClipper clipper;
        clipper.Begin( children.size() );
        while( clipper.Step() )
        {
            for( auto i=clipper.DisplayStart; i<clipper.DisplayEnd; i++ )
            {
                auto& cev = a(children[cti[i]]);
                const auto txt = m_worker.GetZoneName( cev );
                bool b = false;
                SmallColorBox( GetSrcLocColor( m_worker.GetSourceLocation( cev.SrcLoc() ), 0 ) );
                ImGui::SameLine();
                ImGui::PushID( (int)i );
                if( ImGui::Selectable( txt, &b, ImGuiSelectableFlags_SpanAllColumns ) )
                {
                    ShowZoneInfo( cev );
                }
                if( ImGui::IsItemHovered() )
                {
                    m_zoneHighlight = &cev;
                    if( IsMouseClicked( 2 ) )
                    {
                        ZoomToZone( cev );
                    }
                    ZoneTooltip( cev );
                }
                ImGui::PopID();
                ImGui::NextColumn();
                const auto part = double( ctt[cti[i]] ) * rztime;
                char buf[128];
                PrintStringPercent( buf, TimeToString( ctt[cti[i]] ), part * 100 );
                ImGui::ProgressBar( part, ImVec2( -1, ty ), buf );
                ImGui::NextColumn();
            }
        }
        ImGui::EndColumns();
    }
}

void View::DrawGpuInfoWindow()
{
    auto& ev = *m_gpuInfoWindow;
    const auto& srcloc = m_worker.GetSourceLocation( ev.SrcLoc() );

    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 500 * scale, 600 * scale), ImGuiCond_FirstUseEver );
    bool show = true;
    ImGui::Begin( "Zone info", &show, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse );
    if( !ImGui::GetCurrentWindowRead()->SkipItems )
    {
        if( ImGui::Button( ICON_FA_MICROSCOPE " Zoom to zone" ) )
        {
            ZoomToZone( ev );
        }
        auto parent = GetZoneParent( ev );
        if( parent )
        {
            ImGui::SameLine();
            if( ImGui::Button( ICON_FA_ARROW_UP " Go to parent" ) )
            {
                ShowZoneInfo( *parent, m_gpuInfoWindowThread );
            }
        }
        if( ev.callstack.Val() != 0 )
        {
            ImGui::SameLine();
            bool hilite = m_callstackInfoWindow == ev.callstack.Val();
            if( hilite )
            {
                SetButtonHighlightColor();
            }
            if( ImGui::Button( ICON_FA_ALIGN_JUSTIFY " Call stack" ) )
            {
                m_callstackInfoWindow = ev.callstack.Val();
            }
            if( hilite )
            {
                ImGui::PopStyleColor( 3 );
            }
        }
        const auto fileName = m_worker.GetString( srcloc.file );
        if( SourceFileValid( fileName, m_worker.GetCaptureTime(), *this, m_worker ) )
        {
            ImGui::SameLine();
            bool hilite = m_sourceViewFile == fileName;
            if( hilite )
            {
                SetButtonHighlightColor();
            }
            if( ImGui::Button( ICON_FA_FILE_LINES " Source" ) )
            {
                ViewSource( fileName, srcloc.line );
            }
            if( hilite )
            {
                ImGui::PopStyleColor( 3 );
            }
        }
        if( !m_gpuInfoStack.empty() )
        {
            ImGui::SameLine();
            if( ImGui::Button( ICON_FA_ARROW_LEFT " Go back" ) )
            {
                m_gpuInfoWindow = m_gpuInfoStack.back_and_pop();
            }
        }

        ImGui::Separator();

        const auto tid = GetZoneThread( ev );
        ImGui::PushFont( m_bigFont );
        TextFocused( "Zone name:", m_worker.GetString( srcloc.name ) );
        ImGui::PopFont();
        ImGui::SameLine();
        if( ClipboardButton( 1 ) ) ImGui::SetClipboardText( m_worker.GetString( srcloc.name ) );
        TextFocused( "Function:", m_worker.GetString( srcloc.function ) );
        ImGui::SameLine();
        if( ClipboardButton( 2 ) ) ImGui::SetClipboardText( m_worker.GetString( srcloc.function ) );
        SmallColorBox( GetZoneColor( ev ) );
        ImGui::SameLine();
        TextDisabledUnformatted( "Location:" );
        ImGui::SameLine();
        ImGui::TextUnformatted( LocationToString( m_worker.GetString( srcloc.file ), srcloc.line ) );
        ImGui::SameLine();
        if( ClipboardButton( 3 ) )
        {
            ImGui::SetClipboardText( LocationToString( m_worker.GetString( srcloc.file ), srcloc.line ) );
        }
        SmallColorBox( GetThreadColor( tid, 0 ) );
        ImGui::SameLine();
        TextFocused( "Thread:", m_worker.GetThreadName( tid ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s)", RealToString( tid ) );
        if( m_worker.IsThreadFiber( tid ) )
        {
            ImGui::SameLine();
            TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
        }
        ImGui::Separator();
        ImGui::BeginChild( "##gpuinfo" );

        const auto end = m_worker.GetZoneEnd( ev );
        const auto ztime = end - ev.GpuStart();
        const auto selftime = GetZoneSelfTime( ev );
        TextFocused( "Time from start of program:", TimeToStringExact( ev.GpuStart() ) );
        TextFocused( "GPU execution time:", TimeToString( ztime ) );
        TextFocused( "GPU self time:", TimeToString( selftime ) );
        if( ztime != 0 )
        {
            char buf[64];
            PrintStringPercent( buf, 100.f * selftime / ztime );
            ImGui::SameLine();
            TextDisabledUnformatted( buf );
        }
        TextFocused( "CPU command setup time:", TimeToString( ev.CpuEnd() - ev.CpuStart() ) );
        auto ctx = GetZoneCtx( ev );
        if( !ctx )
        {
            TextFocused( "Delay to execution:", TimeToString( ev.GpuStart() - ev.CpuStart() ) );
        }
        else
        {
            const auto td = ctx->threadData.size() == 1 ? ctx->threadData.begin() : ctx->threadData.find( m_worker.DecompressThread( ev.Thread() ) );
            assert( td != ctx->threadData.end() );
            int64_t begin;
            if( td->second.timeline.is_magic() )
            {
                begin = ((Vector<GpuEvent>*)&td->second.timeline)->front().GpuStart();
            }
            else
            {
                begin = td->second.timeline.front()->GpuStart();
            }
            const auto drift = GpuDrift( ctx );
            TextFocused( "Delay to execution:", TimeToString( AdjustGpuTime( ev.GpuStart(), begin, drift ) - ev.CpuStart() ) );
        }

        ImGui::Separator();

        std::vector<const GpuEvent*> zoneTrace;
        while( parent )
        {
            zoneTrace.emplace_back( parent );
            parent = GetZoneParent( *parent );
        }
        int idx = 0;
        DrawZoneTrace<const GpuEvent*>( &ev, zoneTrace, m_worker, m_zoneinfoBuzzAnim, *this, m_showUnknownFrames, [&idx, this] ( const GpuEvent* v, int& fidx ) {
            ImGui::TextDisabled( "%i.", fidx++ );
            ImGui::SameLine();
            const auto& srcloc = m_worker.GetSourceLocation( v->SrcLoc() );
            const auto txt = m_worker.GetZoneName( *v, srcloc );
            ImGui::PushID( idx++ );
            auto sel = ImGui::Selectable( txt, false );
            auto hover = ImGui::IsItemHovered();
            const auto fileName = m_worker.GetString( srcloc.file );
            if( m_zoneinfoBuzzAnim.Match( v ) )
            {
                const auto time = m_zoneinfoBuzzAnim.Time();
                const auto indentVal = sin( time * 60.f ) * 10.f * time;
                ImGui::SameLine( 0, ImGui::GetStyle().ItemSpacing.x + indentVal );
            }
            else
            {
                ImGui::SameLine();
            }
            ImGui::TextDisabled( "(%s) %s", TimeToString( m_worker.GetZoneEnd( *v ) - v->GpuStart() ), LocationToString( fileName, srcloc.line ) );
            ImGui::PopID();
            if( ImGui::IsItemClicked( 1 ) )
            {
                if( SourceFileValid( fileName, m_worker.GetCaptureTime(), *this, m_worker ) )
                {
                    ViewSource( fileName, srcloc.line );
                }
                else
                {
                    m_zoneinfoBuzzAnim.Enable( v, 0.5f );
                }
            }
            if( sel )
            {
                ShowZoneInfo( *v, m_gpuInfoWindowThread );
            }
            if( hover )
            {
                m_gpuHighlight = v;
                if( IsMouseClicked( 2 ) )
                {
                    ZoomToZone( *v );
                }
                ZoneTooltip( *v );
            }
            } );

        if( ev.Child() >= 0 )
        {
            const auto& children = m_worker.GetGpuChildren( ev.Child() );
            bool expand = ImGui::TreeNode( "Child zones" );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s)", RealToString( children.size() ) );
            if( expand )
            {
                if( children.is_magic() )
                {
                    DrawGpuInfoChildren<VectorAdapterDirect<GpuEvent>>( *(Vector<GpuEvent>*)( &children ), ztime );
                }
                else
                {
                    DrawGpuInfoChildren<VectorAdapterPointer<GpuEvent>>( children, ztime );
                }
                ImGui::TreePop();
            }
        }

        ImGui::EndChild();
    }
    ImGui::End();

    if( !show )
    {
        m_gpuInfoWindow = nullptr;
        m_gpuInfoStack.clear();
    }
}

template<typename Adapter, typename V>
void View::DrawGpuInfoChildren( const V& children, int64_t ztime )
{
    Adapter a;
    const auto rztime = 1.0 / ztime;
    const auto ty = ImGui::GetTextLineHeight();

    ImGui::SameLine();
    SmallCheckbox( "Group children locations", &m_groupChildrenLocations );

    if( m_groupChildrenLocations )
    {
        struct ChildGroup
        {
            int16_t srcloc;
            uint64_t t;
            Vector<uint32_t> v;
        };
        uint64_t ctime = 0;
        unordered_flat_map<int16_t, ChildGroup> cmap;
        cmap.reserve( 128 );
        for( size_t i=0; i<children.size(); i++ )
        {
            const auto& child = a(children[i]);
            const auto cend = m_worker.GetZoneEnd( child );
            const auto ct = cend - child.GpuStart();
            const auto srcloc = child.SrcLoc();
            ctime += ct;

            auto it = cmap.find( srcloc );
            if( it == cmap.end() ) it = cmap.emplace( srcloc, ChildGroup { srcloc } ).first;

            it->second.t += ct;
            it->second.v.push_back( i );
        }

        auto msz = cmap.size();
        Vector<ChildGroup*> cgvec;
        cgvec.reserve_and_use( msz );
        size_t idx = 0;
        for( auto& it : cmap )
        {
            cgvec[idx++] = &it.second;
        }

        pdqsort_branchless( cgvec.begin(), cgvec.end(), []( const auto& lhs, const auto& rhs ) { return lhs->t > rhs->t; } );

        ImGui::Columns( 2 );
        ImGui::Indent( ImGui::GetTreeNodeToLabelSpacing() );
        TextColoredUnformatted( ImVec4( 1.0f, 1.0f, 0.4f, 1.0f ), "Self time" );
        ImGui::Unindent( ImGui::GetTreeNodeToLabelSpacing() );
        ImGui::NextColumn();
        char buf[128];
        PrintStringPercent( buf, TimeToString( ztime - ctime ), double( ztime - ctime ) / ztime * 100 );
        ImGui::ProgressBar( double( ztime - ctime ) * rztime, ImVec2( -1, ty ), buf );
        ImGui::NextColumn();
        for( size_t i=0; i<msz; i++ )
        {
            bool expandGroup = false;
            const auto& cgr = *cgvec[i];
            const auto& srcloc = m_worker.GetSourceLocation( cgr.srcloc );
            const auto txt = m_worker.GetZoneName( srcloc );
            if( cgr.v.size() == 1 )
            {
                auto& cev = a(children[cgr.v.front()]);
                const auto txt = m_worker.GetZoneName( cev );
                ImGui::PushID( (int)cgr.v.front() );
                ImGui::TreeNodeEx( txt, ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen );
                if( ImGui::IsItemClicked() )
                {
                    ShowZoneInfo( cev, m_gpuInfoWindowThread );
                }
                if( ImGui::IsItemHovered() )
                {
                    m_gpuHighlight = &cev;
                    if( IsMouseClicked( 2 ) )
                    {
                        ZoomToZone( cev );
                    }
                    ZoneTooltip( cev );
                }
                ImGui::PopID();
            }
            else
            {
                ImGui::PushID( cgr.srcloc );
                expandGroup = ImGui::TreeNode( txt );
                ImGui::PopID();
                if( ImGui::IsItemHovered() )
                {
                    ImGui::BeginTooltip();
                    if( srcloc.name.active )
                    {
                        ImGui::TextUnformatted( m_worker.GetString( srcloc.name ) );
                    }
                    ImGui::TextUnformatted( m_worker.GetString( srcloc.function ) );
                    ImGui::Separator();
                    ImGui::TextUnformatted( LocationToString( m_worker.GetString( srcloc.file ), srcloc.line ) );
                    ImGui::EndTooltip();
                }
                ImGui::SameLine();
                ImGui::TextDisabled( "(\xc3\x97%s)", RealToString( cgr.v.size() ) );
            }
            ImGui::NextColumn();
            const auto part = double( cgr.t ) * rztime;
            char buf[128];
            PrintStringPercent( buf, TimeToString( cgr.t ), part * 100 );
            ImGui::ProgressBar( part, ImVec2( -1, ty ), buf );
            ImGui::NextColumn();
            if( expandGroup )
            {
                auto ctt = std::unique_ptr<uint64_t[]>( new uint64_t[cgr.v.size()] );
                auto cti = std::unique_ptr<uint32_t[]>( new uint32_t[cgr.v.size()] );
                for( size_t i=0; i<cgr.v.size(); i++ )
                {
                    const auto& child = a(children[cgr.v[i]]);
                    const auto cend = m_worker.GetZoneEnd( child );
                    const auto ct = cend - child.GpuStart();
                    ctt[i] = ct;
                    cti[i] = uint32_t( i );
                }

                pdqsort_branchless( cti.get(), cti.get() + cgr.v.size(), [&ctt] ( const auto& lhs, const auto& rhs ) { return ctt[lhs] > ctt[rhs]; } );

                for( size_t i=0; i<cgr.v.size(); i++ )
                {
                    auto& cev = a(children[cgr.v[cti[i]]]);
                    const auto txt = m_worker.GetZoneName( cev );
                    bool b = false;
                    ImGui::Indent();
                    ImGui::PushID( (int)cgr.v[cti[i]] );
                    if( ImGui::Selectable( txt, &b, ImGuiSelectableFlags_SpanAllColumns ) )
                    {
                        ShowZoneInfo( cev, m_gpuInfoWindowThread );
                    }
                    if( ImGui::IsItemHovered() )
                    {
                        m_gpuHighlight = &cev;
                        if( IsMouseClicked( 2 ) )
                        {
                            ZoomToZone( cev );
                        }
                        ZoneTooltip( cev );
                    }
                    ImGui::PopID();
                    ImGui::Unindent();
                    ImGui::NextColumn();
                    const auto part = double( ctt[cti[i]] ) * rztime;
                    char buf[128];
                    PrintStringPercent( buf, TimeToString( ctt[cti[i]] ), part * 100 );
                    ImGui::ProgressBar( part, ImVec2( -1, ty ), buf );
                    ImGui::NextColumn();
                }
                ImGui::TreePop();
            }
        }
        ImGui::EndColumns();
    }
    else
    {
        auto ctt = std::unique_ptr<uint64_t[]>( new uint64_t[children.size()] );
        auto cti = std::unique_ptr<uint32_t[]>( new uint32_t[children.size()] );
        uint64_t ctime = 0;
        for( size_t i=0; i<children.size(); i++ )
        {
            const auto& child = a(children[i]);
            const auto cend = m_worker.GetZoneEnd( child );
            const auto ct = cend - child.GpuStart();
            ctime += ct;
            ctt[i] = ct;
            cti[i] = uint32_t( i );
        }

        pdqsort_branchless( cti.get(), cti.get() + children.size(), [&ctt] ( const auto& lhs, const auto& rhs ) { return ctt[lhs] > ctt[rhs]; } );

        ImGui::Columns( 2 );
        TextColoredUnformatted( ImVec4( 1.0f, 1.0f, 0.4f, 1.0f ), "Self time" );
        ImGui::NextColumn();
        char buf[128];
        PrintStringPercent( buf, TimeToString( ztime - ctime ), double( ztime - ctime ) / ztime * 100 );
        ImGui::ProgressBar( double( ztime - ctime ) / ztime, ImVec2( -1, ty ), buf );
        ImGui::NextColumn();
        for( size_t i=0; i<children.size(); i++ )
        {
            auto& cev = a(children[cti[i]]);
            bool b = false;
            ImGui::PushID( (int)i );
            if( ImGui::Selectable( m_worker.GetZoneName( cev ), &b, ImGuiSelectableFlags_SpanAllColumns ) )
            {
                ShowZoneInfo( cev, m_gpuInfoWindowThread );
            }
            if( ImGui::IsItemHovered() )
            {
                m_gpuHighlight = &cev;
                if( IsMouseClicked( 2 ) )
                {
                    ZoomToZone( cev );
                }
                ZoneTooltip( cev );
            }
            ImGui::PopID();
            ImGui::NextColumn();
            const auto part = double( ctt[cti[i]] ) / ztime;
            char buf[128];
            PrintStringPercent( buf, TimeToString( ctt[cti[i]] ), part * 100 );
            ImGui::ProgressBar( part, ImVec2( -1, ty ), buf );
            ImGui::NextColumn();
        }
        ImGui::EndColumns();
    }
}

void View::ShowZoneInfo( const ZoneEvent& ev )
{
    if( m_zoneInfoWindow && m_zoneInfoWindow != &ev )
    {
        m_zoneInfoStack.push_back( m_zoneInfoWindow );
    }
    m_zoneInfoWindow = &ev;

    if( m_gpuInfoWindow )
    {
        m_gpuInfoWindow = nullptr;
        m_gpuInfoStack.clear();
    }
}

void View::ShowZoneInfo( const GpuEvent& ev, uint64_t thread )
{
    if( m_gpuInfoWindow && m_gpuInfoWindow != &ev )
    {
        m_gpuInfoStack.push_back( m_gpuInfoWindow );
    }
    m_gpuInfoWindow = &ev;
    m_gpuInfoWindowThread = thread;

    if( m_zoneInfoWindow )
    {
        m_zoneInfoWindow = nullptr;
        m_zoneInfoStack.clear();
    }
}

void View::ZoneTooltip( const ZoneEvent& ev )
{
    const auto tid = GetZoneThread( ev );
    auto& srcloc = m_worker.GetSourceLocation( ev.SrcLoc() );
    const auto end = m_worker.GetZoneEnd( ev );
    const auto ztime = end - ev.Start();
    const auto selftime = GetZoneSelfTime( ev );

    ImGui::BeginTooltip();
    if( m_worker.HasZoneExtra( ev ) && m_worker.GetZoneExtra( ev ).name.Active() )
    {
        ImGui::TextUnformatted( m_worker.GetString( m_worker.GetZoneExtra( ev ).name ) );
    }
    if( srcloc.name.active )
    {
        ImGui::TextUnformatted( m_worker.GetString( srcloc.name ) );
    }
    ImGui::TextUnformatted( m_worker.GetString( srcloc.function ) );
    ImGui::Separator();
    SmallColorBox( GetSrcLocColor( srcloc, 0 ) );
    ImGui::SameLine();
    ImGui::TextUnformatted( LocationToString( m_worker.GetString( srcloc.file ), srcloc.line ) );
    SmallColorBox( GetThreadColor( tid, 0 ) );
    ImGui::SameLine();
    TextFocused( "Thread:", m_worker.GetThreadName( tid ) );
    ImGui::SameLine();
    ImGui::TextDisabled( "(%s)", RealToString( tid ) );
    if( m_worker.IsThreadFiber( tid ) )
    {
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
    }
    ImGui::Separator();
    TextFocused( "Execution time:", TimeToString( ztime ) );
#ifndef TRACY_NO_STATISTICS
    if( m_worker.AreSourceLocationZonesReady() )
    {
        auto& zoneData = m_worker.GetZonesForSourceLocation( ev.SrcLoc() );
        if( zoneData.total > 0 )
        {
            ImGui::SameLine();
            ImGui::TextDisabled( "(%.2f%% of mean time)", float( ztime ) / zoneData.total * zoneData.zones.size() * 100 );
        }
    }
#endif
    TextFocused( "Self time:", TimeToString( selftime ) );
    if( ztime != 0 )
    {
        char buf[64];
        PrintStringPercent( buf, 100.f * selftime / ztime );
        ImGui::SameLine();
        TextDisabledUnformatted( buf );
    }
    const auto ctx = m_worker.GetContextSwitchData( tid );
    if( ctx )
    {
        int64_t time;
        uint64_t cnt;
        if( GetZoneRunningTime( ctx, ev, time, cnt ) )
        {
            TextFocused( "Running state time:", TimeToString( time ) );
            if( ztime != 0 )
            {
                char buf[64];
                PrintStringPercent( buf, 100.f * time / ztime );
                ImGui::SameLine();
                TextDisabledUnformatted( buf );
            }
            TextFocused( "Running state regions:", RealToString( cnt ) );
        }
    }
    if( m_worker.HasZoneExtra( ev ) && m_worker.GetZoneExtra( ev ).text.Active() )
    {
        ImGui::NewLine();
        TextColoredUnformatted( ImVec4( 0xCC / 255.f, 0xCC / 255.f, 0x22 / 255.f, 1.f ), m_worker.GetString( m_worker.GetZoneExtra( ev ).text ) );
    }
    ImGui::EndTooltip();
}

void View::ZoneTooltip( const GpuEvent& ev )
{
    const auto tid = GetZoneThread( ev );
    const auto& srcloc = m_worker.GetSourceLocation( ev.SrcLoc() );
    const auto end = m_worker.GetZoneEnd( ev );
    const auto ztime = end - ev.GpuStart();
    const auto selftime = GetZoneSelfTime( ev );

    ImGui::BeginTooltip();
    ImGui::TextUnformatted( m_worker.GetString( srcloc.name ) );
    ImGui::TextUnformatted( m_worker.GetString( srcloc.function ) );
    ImGui::Separator();
    SmallColorBox( GetSrcLocColor( srcloc, 0 ) );
    ImGui::SameLine();
    ImGui::TextUnformatted( LocationToString( m_worker.GetString( srcloc.file ), srcloc.line ) );
    SmallColorBox( GetThreadColor( tid, 0 ) );
    ImGui::SameLine();
    TextFocused( "Thread:", m_worker.GetThreadName( tid ) );
    ImGui::SameLine();
    ImGui::TextDisabled( "(%s)", RealToString( tid ) );
    if( m_worker.IsThreadFiber( tid ) )
    {
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
    }
    ImGui::Separator();
    TextFocused( "GPU execution time:", TimeToString( ztime ) );
    TextFocused( "GPU self time:", TimeToString( selftime ) );
    if( ztime != 0 )
    {
        char buf[64];
        PrintStringPercent( buf, 100.f * selftime / ztime );
        ImGui::SameLine();
        TextDisabledUnformatted( buf );
    }
    TextFocused( "CPU command setup time:", TimeToString( ev.CpuEnd() - ev.CpuStart() ) );
    auto ctx = GetZoneCtx( ev );
    if( !ctx )
    {
        TextFocused( "Delay to execution:", TimeToString( ev.GpuStart() - ev.CpuStart() ) );
    }
    else
    {
        const auto td = ctx->threadData.size() == 1 ? ctx->threadData.begin() : ctx->threadData.find( m_worker.DecompressThread( ev.Thread() ) );
        assert( td != ctx->threadData.end() );
        int64_t begin;
        if( td->second.timeline.is_magic() )
        {
            begin = ((Vector<GpuEvent>*)&td->second.timeline)->front().GpuStart();
        }
        else
        {
            begin = td->second.timeline.front()->GpuStart();
        }
        const auto drift = GpuDrift( ctx );
        TextFocused( "Delay to execution:", TimeToString( AdjustGpuTime( ev.GpuStart(), begin, drift ) - ev.CpuStart() ) );
    }

    ImGui::EndTooltip();
}

}
