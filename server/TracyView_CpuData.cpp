#include <math.h>

#include "TracyColor.hpp"
#include "TracyImGui.hpp"
#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracyView.hpp"

namespace tracy
{

constexpr float MinVisSize = 3;

bool View::DrawCpuData( double pxns, int& offset, const ImVec2& wpos, bool hover, float yMin, float yMax )
{
    auto cpuData = m_worker.GetCpuData();
    const auto cpuCnt = m_worker.GetCpuDataCpuCount();
    assert( cpuCnt != 0 );

    const auto w = ImGui::GetContentRegionAvail().x - 1;
    const auto ty = ImGui::GetTextLineHeight();
    const auto nspxdbl = 1.0 / pxns;
    const auto nspx = int64_t( nspxdbl );
    auto draw = ImGui::GetWindowDrawList();
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );

#ifdef TRACY_NO_STATISTICS
    if( m_vd.drawCpuUsageGraph )
#else
    if( m_vd.drawCpuUsageGraph && m_worker.IsCpuUsageReady() )
#endif
    {
        const auto cpuUsageHeight = floor( 30.f * GetScale() );
        if( wpos.y + offset + cpuUsageHeight + 3 >= yMin && wpos.y + offset <= yMax )
        {
            const auto iw = (size_t)w;
            m_worker.GetCpuUsage( m_vd.zvStart, nspxdbl, iw, m_cpuUsageBuf );

            const float cpuCntRev = 1.f / cpuCnt;
            float pos = 0;
            auto usage = m_cpuUsageBuf.begin();
            while( pos < w )
            {
                float base;
                if( usage->first != 0 )
                {
                    base = dpos.y + offset + ( 1.f - usage->first * cpuCntRev ) * cpuUsageHeight;
                    DrawLine( draw, ImVec2( dpos.x + pos, dpos.y + offset + cpuUsageHeight ), ImVec2( dpos.x + pos, base ), 0xFF55BB55 );
                }
                else
                {
                    base = dpos.y + offset + cpuUsageHeight;
                }
                if( usage->second != 0 )
                {
                    int usageTotal = usage->first + usage->second;
                    DrawLine( draw, ImVec2( dpos.x + pos, base ), ImVec2( dpos.x + pos, dpos.y + offset + ( 1.f - usageTotal * cpuCntRev ) * cpuUsageHeight ), 0xFF666666 );
                }
                pos++;
                usage++;
            }
            DrawLine( draw, dpos + ImVec2( 0, offset+cpuUsageHeight+2 ), dpos + ImVec2( w, offset+cpuUsageHeight+2 ), 0x22DD88DD );

            if( hover && ImGui::IsMouseHoveringRect( ImVec2( wpos.x, wpos.y + offset ), ImVec2( wpos.x + w, wpos.y + offset + cpuUsageHeight ), true ) )
            {
                const auto& usage = m_cpuUsageBuf[ImGui::GetIO().MousePos.x - wpos.x];
                ImGui::BeginTooltip();
                TextFocused( "Cores used by profiled program:", RealToString( usage.first ) );
                ImGui::SameLine();
                char buf[64];
                PrintStringPercent( buf, usage.first * cpuCntRev * 100 );
                TextDisabledUnformatted( buf );
                TextFocused( "Cores used by other programs:", RealToString( usage.second ) );
                ImGui::SameLine();
                PrintStringPercent( buf, usage.second * cpuCntRev * 100 );
                TextDisabledUnformatted( buf );
                TextFocused( "Number of cores:", RealToString( cpuCnt ) );
                if( usage.first + usage.second != 0 )
                {
                    const auto mt = m_vd.zvStart + ( ImGui::GetIO().MousePos.x - wpos.x ) * nspxdbl;
                    ImGui::Separator();
                    for( int i=0; i<cpuCnt; i++ )
                    {
                        if( !cpuData[i].cs.empty() )
                        {
                            auto& cs = cpuData[i].cs;
                            auto it = std::lower_bound( cs.begin(), cs.end(), mt, [] ( const auto& l, const auto& r ) { return (uint64_t)l.End() < (uint64_t)r; } );
                            if( it != cs.end() && it->Start() <= mt && it->End() >= mt )
                            {
                                auto tt = m_worker.GetThreadTopology( i );
                                if( tt )
                                {
                                    ImGui::TextDisabled( "[%i:%i] CPU %i:", tt->package, tt->core, i );
                                }
                                else
                                {
                                    ImGui::TextDisabled( "CPU %i:", i );
                                }
                                ImGui::SameLine();
                                const auto thread = m_worker.DecompressThreadExternal( it->Thread() );
                                bool local, untracked;
                                const char* txt;
                                auto label = GetThreadContextData( thread, local, untracked, txt );
                                if( local || untracked )
                                {
                                    uint32_t color;
                                    if( m_vd.dynamicColors != 0 )
                                    {
                                        color = local ? GetThreadColor( thread, 0 ) : ( untracked ? 0xFF663333 : 0xFF444444 );
                                    }
                                    else
                                    {
                                        color = local ? 0xFF334488 : ( untracked ? 0xFF663333 : 0xFF444444 );
                                    }
                                    TextColoredUnformatted( HighlightColor<75>( color ), label );
                                    ImGui::SameLine();
                                    ImGui::TextDisabled( "(%s)", RealToString( thread ) );
                                }
                                else
                                {
                                    TextDisabledUnformatted( label );
                                }
                            }
                        }
                    }
                }
                ImGui::EndTooltip();
            }
        }
        offset += cpuUsageHeight + 3;
    }

    ImGui::PushFont( m_smallFont );
    const auto sty = round( ImGui::GetTextLineHeight() );
    const auto sstep = sty + 1;

    const auto origOffset = offset;
    for( int i=0; i<cpuCnt; i++ )
    {
        if( !cpuData[i].cs.empty() )
        {
            if( wpos.y + offset + sty >= yMin && wpos.y + offset <= yMax )
            {
                DrawLine( draw, dpos + ImVec2( 0, offset+sty ), dpos + ImVec2( w, offset+sty ), 0x22DD88DD );

                auto& cs = cpuData[i].cs;
                auto tt = m_worker.GetThreadTopology( i );

                auto it = std::lower_bound( cs.begin(), cs.end(), std::max<int64_t>( 0, m_vd.zvStart ), [] ( const auto& l, const auto& r ) { return (uint64_t)l.End() < (uint64_t)r; } );
                if( it != cs.end() )
                {
                    auto eit = std::lower_bound( it, cs.end(), m_vd.zvEnd, [] ( const auto& l, const auto& r ) { return l.Start() < r; } );
                    while( it < eit )
                    {
                        const auto start = it->Start();
                        const auto end = it->End();
                        const auto zsz = std::max( ( end - start ) * pxns, pxns * 0.5 );
                        if( zsz < MinVisSize )
                        {
                            const auto MinVisNs = MinVisSize * nspx;
                            int num = 0;
                            const auto px0 = ( start - m_vd.zvStart ) * pxns;
                            auto px1ns = end - m_vd.zvStart;
                            auto rend = end;
                            auto nextTime = end + MinVisNs;
                            for(;;)
                            {
                                const auto prevIt = it;
                                it = std::lower_bound( it, eit, nextTime, [] ( const auto& l, const auto& r ) { return (uint64_t)l.End() < (uint64_t)r; } );
                                if( it == prevIt ) ++it;
                                num += std::distance( prevIt, it );
                                if( it == eit ) break;
                                const auto nend = it->IsEndValid() ? it->End() : m_worker.GetLastTime();
                                const auto nsnext = nend - m_vd.zvStart;
                                if( nsnext - px1ns >= MinVisNs * 2 ) break;
                                px1ns = nsnext;
                                rend = nend;
                                nextTime = nend + nspx;
                            }
                            const auto px1 = px1ns * pxns;
                            DrawZigZag( draw, wpos + ImVec2( 0, offset + sty/2 ), std::max( px0, -10.0 ), std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), sty/4, 0xFF888888 );

                            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset-1 ), wpos + ImVec2( std::max( px1, px0+MinVisSize ), offset + sty ) ) )
                            {
                                ImGui::PopFont();
                                ImGui::BeginTooltip();
                                TextFocused( "CPU:", RealToString( i ) );
                                if( tt )
                                {
                                    ImGui::SameLine();
                                    ImGui::Spacing();
                                    ImGui::SameLine();
                                    TextFocused( "Package:", RealToString( tt->package ) );
                                    ImGui::SameLine();
                                    TextFocused( "Core:", RealToString( tt->core ) );
                                }
                                TextFocused( "Context switch regions:", RealToString( num ) );
                                ImGui::Separator();
                                TextFocused( "Start time:", TimeToString( start ) );
                                TextFocused( "End time:", TimeToString( rend ) );
                                TextFocused( "Activity time:", TimeToString( rend - start ) );
                                ImGui::EndTooltip();
                                ImGui::PushFont( m_smallFont );

                                if( IsMouseClicked( 2 ) )
                                {
                                    ZoomToRange( start, rend );
                                }
                            }
                        }
                        else
                        {
                            const auto thread = m_worker.DecompressThreadExternal( it->Thread() );
                            bool local, untracked;
                            const char* txt;
                            auto label = GetThreadContextData( thread, local, untracked, txt );
                            const auto pr0 = ( start - m_vd.zvStart ) * pxns;
                            const auto pr1 = ( end - m_vd.zvStart ) * pxns;
                            const auto px0 = std::max( pr0, -10.0 );
                            const auto px1 = std::max( { std::min( pr1, double( w + 10 ) ), px0 + pxns * 0.5, px0 + MinVisSize } );

                            uint32_t color;
                            if( m_vd.dynamicColors != 0 )
                            {
                                color = local ? GetThreadColor( thread, 0 ) : ( untracked ? 0xFF663333 : 0xFF444444 );
                            }
                            else
                            {
                                color = local ? 0xFF334488 : ( untracked ? 0xFF663333 : 0xFF444444 );
                            }

                            draw->AddRectFilled( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + sty ), color );
                            if( m_drawThreadHighlight == thread )
                            {
                                draw->AddRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + sty ), 0xFFFFFFFF );
                            }
                            else
                            {
                                const auto accentColor = HighlightColor( color );
                                const auto darkColor = DarkenColor( color );
                                DrawLine( draw, dpos + ImVec2( px0, offset + sty ), dpos + ImVec2( px0, offset ), dpos + ImVec2( px1-1, offset ), accentColor, 1.f );
                                DrawLine( draw, dpos + ImVec2( px0, offset + sty ), dpos + ImVec2( px1-1, offset + sty ), dpos + ImVec2( px1-1, offset ), darkColor, 1.f );
                            }

                            auto tsz = ImGui::CalcTextSize( label );
                            if( tsz.x < zsz )
                            {
                                const auto x = ( start - m_vd.zvStart ) * pxns + ( ( end - start ) * pxns - tsz.x ) / 2;
                                if( x < 0 || x > w - tsz.x )
                                {
                                    ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                                    DrawTextContrast( draw, wpos + ImVec2( std::max( std::max( 0., px0 ), std::min( double( w - tsz.x ), x ) ), offset-1 ), local ? 0xFFFFFFFF : 0xAAFFFFFF, label );
                                    ImGui::PopClipRect();
                                }
                                else if( start == end )
                                {
                                    DrawTextContrast( draw, wpos + ImVec2( px0 + ( px1 - px0 - tsz.x ) * 0.5, offset-1 ), local ? 0xFFFFFFFF : 0xAAFFFFFF, label );
                                }
                                else
                                {
                                    DrawTextContrast( draw, wpos + ImVec2( x, offset-1 ), local ? 0xFFFFFFFF : 0xAAFFFFFF, label );
                                }
                            }
                            else
                            {
                                ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                                DrawTextContrast( draw, wpos + ImVec2( ( start - m_vd.zvStart ) * pxns, offset-1 ), local ? 0xFFFFFFFF : 0xAAFFFFFF, label );
                                ImGui::PopClipRect();
                            }

                            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset-1 ), wpos + ImVec2( px1, offset + sty ) ) )
                            {
                                m_drawThreadHighlight = thread;
                                ImGui::PopFont();
                                ImGui::BeginTooltip();
                                TextFocused( "CPU:", RealToString( i ) );
                                if( tt )
                                {
                                    ImGui::SameLine();
                                    ImGui::Spacing();
                                    ImGui::SameLine();
                                    TextFocused( "Package:", RealToString( tt->package ) );
                                    ImGui::SameLine();
                                    TextFocused( "Core:", RealToString( tt->core ) );
                                }
                                if( local )
                                {
                                    TextFocused( "Program:", m_worker.GetCaptureProgram().c_str() );
                                    ImGui::SameLine();
                                    TextDisabledUnformatted( "(profiled program)" );
                                    SmallColorBox( GetThreadColor( thread, 0 ) );
                                    ImGui::SameLine();
                                    TextFocused( "Thread:", m_worker.GetThreadName( thread ) );
                                    ImGui::SameLine();
                                    ImGui::TextDisabled( "(%s)", RealToString( thread ) );
                                    m_drawThreadMigrations = thread;
                                    m_cpuDataThread = thread;
                                }
                                else
                                {
                                    if( untracked )
                                    {
                                        TextFocused( "Program:", m_worker.GetCaptureProgram().c_str() );
                                    }
                                    else
                                    {
                                        TextFocused( "Program:", txt );
                                    }
                                    ImGui::SameLine();
                                    if( untracked )
                                    {
                                        TextDisabledUnformatted( "(untracked thread in profiled program)" );
                                    }
                                    else
                                    {
                                        TextDisabledUnformatted( "(external)" );
                                    }
                                    TextFocused( "Thread:", m_worker.GetExternalName( thread ).second );
                                    ImGui::SameLine();
                                    ImGui::TextDisabled( "(%s)", RealToString( thread ) );
                                }
                                ImGui::Separator();
                                TextFocused( "Start time:", TimeToStringExact( start ) );
                                TextFocused( "End time:", TimeToStringExact( end ) );
                                TextFocused( "Activity time:", TimeToString( end - start ) );
                                ImGui::EndTooltip();
                                ImGui::PushFont( m_smallFont );

                                if( local && IsMouseClicked( 0 ) )
                                {
                                    auto& item = m_tc.GetItem( m_worker.GetThreadData( thread ) );
                                    item.SetVisible( true );
                                    item.SetShowFull( true );
                                }
                                if( IsMouseClicked( 2 ) )
                                {
                                    ZoomToRange( start, end );
                                }
                            }
                            ++it;
                        }
                    }
                }

                char buf[64];
                if( tt )
                {
                    sprintf( buf, "[%i:%i] CPU %i", tt->package, tt->core, i );
                }
                else
                {
                    sprintf( buf, "CPU %i", i );
                }
                const auto txtx = ImGui::CalcTextSize( buf ).x;
                DrawTextSuperContrast( draw, wpos + ImVec2( ty, offset-1 ), 0xFFDD88DD, buf );
                if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, offset-1 ), wpos + ImVec2( sty + txtx, offset + sty ) ) )
                {
                    ImGui::PopFont();
                    ImGui::BeginTooltip();
                    TextFocused( "CPU:", RealToString( i ) );
                    if( tt )
                    {
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        TextFocused( "Package:", RealToString( tt->package ) );
                        ImGui::SameLine();
                        TextFocused( "Core:", RealToString( tt->core ) );
                    }
                    TextFocused( "Context switch regions:", RealToString( cs.size() ) );
                    ImGui::EndTooltip();
                    ImGui::PushFont( m_smallFont );
                }
            }
            offset += sstep;
        }
    }

    if( m_drawThreadMigrations != 0 )
    {
        auto ctxSwitch = m_worker.GetContextSwitchData( m_drawThreadMigrations );
        if( ctxSwitch )
        {
            const auto color = HighlightColor( GetThreadColor( m_drawThreadMigrations, -8 ) );

            auto& v = ctxSwitch->v;
            auto it = std::lower_bound( v.begin(), v.end(), m_vd.zvStart, [] ( const auto& l, const auto& r ) { return l.End() < r; } );
            if( it != v.begin() ) --it;
            auto end = std::lower_bound( it, v.end(), m_vd.zvEnd, [] ( const auto& l, const auto& r ) { return l.Start() < r; } );
            if( end == v.end() ) --end;

            while( it < end )
            {
                const auto t0 = it->End();
                const auto cpu0 = it->Cpu();

                ++it;

                const auto t1 = it->Start();
                const auto cpu1 = it->Cpu();

                const auto px0 = ( t0 - m_vd.zvStart ) * pxns;
                const auto px1 = ( t1 - m_vd.zvStart ) * pxns;

                if( t1 - t0 < 2 * nspx )
                {
                    DrawLine( draw, dpos + ImVec2( px0, origOffset + sty * 0.5f + cpu0 * sstep ), dpos + ImVec2( px1, origOffset + sty * 0.5f + cpu1 * sstep ), color );
                }
                else
                {
                    DrawLine( draw, dpos + ImVec2( px0, origOffset + sty * 0.5f + cpu0 * sstep ), dpos + ImVec2( px1, origOffset + sty * 0.5f + cpu1 * sstep ), 0xFF000000, 4.f );
                    DrawLine( draw, dpos + ImVec2( px0, origOffset + sty * 0.5f + cpu0 * sstep ), dpos + ImVec2( px1, origOffset + sty * 0.5f + cpu1 * sstep ), color, 2.f );
                }
            }
        }
    }

    ImGui::PopFont();
    return true;
}

void View::DrawCpuDataWindow()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 700 * scale, 800 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "CPU data", &m_showCpuDataWindow );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }

    struct PidData
    {
        std::vector<uint64_t> tids;
        CpuThreadData data;
    };

    const auto& ctd = m_worker.GetCpuThreadData();
    unordered_flat_map<uint64_t, PidData> pids;
    for( auto& v : ctd )
    {
        uint64_t pid = m_worker.GetPidFromTid( v.first );
        auto it = pids.find( pid );
        if( it == pids.end() )
        {
            it = pids.emplace( pid, PidData {} ).first;
        }
        it->second.tids.emplace_back( v.first );
        it->second.data.runningTime += v.second.runningTime;
        it->second.data.runningRegions += v.second.runningRegions;
        it->second.data.migrations += v.second.migrations;
    }

    TextFocused( "Tracked threads:", RealToString( ctd.size() ) );
    ImGui::SameLine();
    TextFocused( "Tracked processes:", RealToString( pids.size() ) );
    ImGui::Separator();
    ImGui::BeginChild( "##cpudata" );
    if( ImGui::BeginTable( "##cpudata", 5, ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable | ImGuiTableFlags_Sortable | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY ) )
    {
        ImGui::TableSetupScrollFreeze( 0, 1 );
        ImGui::TableSetupColumn( "PID/TID", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
        ImGui::TableSetupColumn( "Name" );
        ImGui::TableSetupColumn( "Running time", ImGuiTableColumnFlags_PreferSortDescending );
        ImGui::TableSetupColumn( "Running regions", ImGuiTableColumnFlags_PreferSortDescending | ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
        ImGui::TableSetupColumn( "CPU migrations", ImGuiTableColumnFlags_PreferSortDescending | ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
        ImGui::TableHeadersRow();

        std::vector<unordered_flat_map<uint64_t, PidData>::iterator> psort;
        psort.reserve( pids.size() );
        for( auto it = pids.begin(); it != pids.end(); ++it ) psort.emplace_back( it );
        const auto& sortspec = *ImGui::TableGetSortSpecs()->Specs;
        switch( sortspec.ColumnIndex )
        {
        case 0:
            if( sortspec.SortDirection == ImGuiSortDirection_Descending )
            {
                pdqsort_branchless( psort.begin(), psort.end(), [] ( const auto& l, const auto& r ) { return l->first > r->first; } );
            }
            else
            {
                pdqsort_branchless( psort.begin(), psort.end(), [] ( const auto& l, const auto& r ) { return l->first < r->first; } );
            }
            break;
        case 1:
            if( sortspec.SortDirection == ImGuiSortDirection_Descending )
            {
                pdqsort_branchless( psort.begin(), psort.end(), [this] ( const auto& l, const auto& r ) { return strcmp( m_worker.GetExternalName( l->second.tids[0] ).first, m_worker.GetExternalName( r->second.tids[0] ).first ) > 0; } );
            }
            else
            {
                pdqsort_branchless( psort.begin(), psort.end(), [this] ( const auto& l, const auto& r ) { return strcmp( m_worker.GetExternalName( l->second.tids[0] ).first, m_worker.GetExternalName( r->second.tids[0] ).first ) < 0; } );
            }
            break;
        case 2:
            if( sortspec.SortDirection == ImGuiSortDirection_Descending )
            {
                pdqsort_branchless( psort.begin(), psort.end(), [] ( const auto& l, const auto& r ) { return l->second.data.runningTime > r->second.data.runningTime; } );
            }
            else
            {
                pdqsort_branchless( psort.begin(), psort.end(), [] ( const auto& l, const auto& r ) { return l->second.data.runningTime < r->second.data.runningTime; } );
            }
            break;
        case 3:
            if( sortspec.SortDirection == ImGuiSortDirection_Descending )
            {
                pdqsort_branchless( psort.begin(), psort.end(), [] ( const auto& l, const auto& r ) { return l->second.data.runningRegions > r->second.data.runningRegions; } );
            }
            else
            {
                pdqsort_branchless( psort.begin(), psort.end(), [] ( const auto& l, const auto& r ) { return l->second.data.runningRegions < r->second.data.runningRegions; } );
            }
            break;
        case 4:
            if( sortspec.SortDirection == ImGuiSortDirection_Descending )
            {
                pdqsort_branchless( psort.begin(), psort.end(), [] ( const auto& l, const auto& r ) { return l->second.data.migrations > r->second.data.migrations; } );
            }
            else
            {
                pdqsort_branchless( psort.begin(), psort.end(), [] ( const auto& l, const auto& r ) { return l->second.data.migrations < r->second.data.migrations; } );
            }
            break;
        default:
            assert( false );
            break;
        }

        const auto thisPid = m_worker.GetPid();
        const auto rtimespan = 1.0 / m_worker.GetLastTime();
        const auto ty = ImGui::GetTextLineHeight();

        auto& style = ImGui::GetStyle();
        const auto framePaddingY = style.FramePadding.y;
        bool drawSeparator = false;
        for( auto& pidit : psort )
        {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            if( drawSeparator ) ImGui::Separator();

            char buf[128];
            auto& pid = *pidit;
            const auto pidMatch = thisPid != 0 && thisPid == pid.first;
            auto name = m_worker.GetExternalName( pid.second.tids[0] ).first;
            if( pidMatch )
            {
                name = m_worker.GetCaptureProgram().c_str();
                ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 0.2f, 1.0f, 0.2f, 1.0f ) );
            }
            const auto pidtxt = pid.first == 0 ? "Unknown" : RealToString( pid.first );
            const auto expand = ImGui::TreeNode( pidtxt );
            if( ImGui::IsItemHovered() )
            {
                if( pidMatch )
                {
                    m_drawThreadMigrations = pid.first;
                    m_cpuDataThread = pid.first;
                }
                m_drawThreadHighlight = pid.first;
            }
            const auto tsz = pid.second.tids.size();
            if( tsz > 1 )
            {
                ImGui::SameLine();
                ImGui::TextDisabled( "(%s)", RealToString( tsz ) );
            }
            ImGui::TableNextColumn();
            if( drawSeparator ) ImGui::Separator();
            ImGui::TextUnformatted( pid.first == 0 ? "???" : name );
            if( ImGui::IsItemHovered() )
            {
                if( pidMatch )
                {
                    m_drawThreadMigrations = pid.first;
                    m_cpuDataThread = pid.first;
                }
                m_drawThreadHighlight = pid.first;
            }
            ImGui::TableNextColumn();
            if( drawSeparator ) ImGui::Separator();
            PrintStringPercent( buf, TimeToString( pid.second.data.runningTime ), double( pid.second.data.runningTime ) * rtimespan * 100 );
            style.FramePadding.y = 0;
            ImGui::ProgressBar( double( pid.second.data.runningTime ) * rtimespan, ImVec2( -1, ty ), buf );
            style.FramePadding.y = framePaddingY;
            ImGui::TableNextColumn();
            if( drawSeparator ) ImGui::Separator();
            ImGui::TextUnformatted( RealToString( pid.second.data.runningRegions ) );
            ImGui::TableNextColumn();
            if( drawSeparator )
            {
                drawSeparator = false;
                ImGui::Separator();
            }
            ImGui::TextUnformatted( RealToString( pid.second.data.migrations ) );
            ImGui::SameLine();
            PrintStringPercent( buf, double( pid.second.data.migrations ) / pid.second.data.runningRegions * 100 );
            TextDisabledUnformatted( buf );
            if( expand )
            {
                switch( sortspec.ColumnIndex )
                {
                case 0:
                    if( sortspec.SortDirection == ImGuiSortDirection_Descending )
                    {
                        pdqsort_branchless( pid.second.tids.begin(), pid.second.tids.end(), []( const auto& l, const auto& r ) { return l > r; } );
                    }
                    else
                    {
                        pdqsort_branchless( pid.second.tids.begin(), pid.second.tids.end() );
                    }
                    break;
                case 1:
                    if( sortspec.SortDirection == ImGuiSortDirection_Descending )
                    {
                        pdqsort_branchless( pid.second.tids.begin(), pid.second.tids.end(), [this] ( const auto& l, const auto& r ) { return strcmp( m_worker.GetExternalName( l ).second, m_worker.GetExternalName( r ).second ) > 0; } );
                    }
                    else
                    {
                        pdqsort_branchless( pid.second.tids.begin(), pid.second.tids.end(), [this] ( const auto& l, const auto& r ) { return strcmp( m_worker.GetExternalName( l ).second, m_worker.GetExternalName( r ).second ) < 0; } );
                    }
                    break;
                case 2:
                    if( sortspec.SortDirection == ImGuiSortDirection_Descending )
                    {
                        pdqsort_branchless( pid.second.tids.begin(), pid.second.tids.end(), [&ctd] ( const auto& l, const auto& r ) { return ctd.find( l )->second.runningTime > ctd.find( r )->second.runningTime; } );
                    }
                    else
                    {
                        pdqsort_branchless( pid.second.tids.begin(), pid.second.tids.end(), [&ctd] ( const auto& l, const auto& r ) { return ctd.find( l )->second.runningTime < ctd.find( r )->second.runningTime; } );
                    }
                    break;
                case 3:
                    if( sortspec.SortDirection == ImGuiSortDirection_Descending )
                    {
                        pdqsort_branchless( pid.second.tids.begin(), pid.second.tids.end(), [&ctd] ( const auto& l, const auto& r ) { return ctd.find( l )->second.runningRegions > ctd.find( r )->second.runningRegions; } );
                    }
                    else
                    {
                        pdqsort_branchless( pid.second.tids.begin(), pid.second.tids.end(), [&ctd] ( const auto& l, const auto& r ) { return ctd.find( l )->second.runningRegions < ctd.find( r )->second.runningRegions; } );
                    }
                    break;
                case 4:
                    if( sortspec.SortDirection == ImGuiSortDirection_Descending )
                    {
                        pdqsort_branchless( pid.second.tids.begin(), pid.second.tids.end(), [&ctd] ( const auto& l, const auto& r ) { return ctd.find( l )->second.migrations > ctd.find( r )->second.migrations; } );
                    }
                    else
                    {
                        pdqsort_branchless( pid.second.tids.begin(), pid.second.tids.end(), [&ctd] ( const auto& l, const auto& r ) { return ctd.find( l )->second.migrations < ctd.find( r )->second.migrations; } );
                    }
                    break;
                default:
                    assert( false );
                    break;
                }
                drawSeparator = true;
                for( auto& tid : pid.second.tids )
                {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    if( drawSeparator ) ImGui::Separator();

                    const auto tidMatch = pidMatch && m_worker.IsThreadLocal( tid );
                    const char* tname;
                    if( tidMatch )
                    {
                        tname = m_worker.GetThreadName( tid );
                        ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 1.0f, 1.0f, 0.2f, 1.0f ) );
                    }
                    else
                    {
                        tname = m_worker.GetExternalName( tid ).second;
                    }
                    const auto& tit = ctd.find( tid );
                    assert( tit != ctd.end() );
                    ImGui::TextUnformatted( RealToString( tid ) );
                    if( ImGui::IsItemHovered() )
                    {
                        if( tidMatch )
                        {
                            m_drawThreadMigrations = tid;
                            m_cpuDataThread = tid;
                        }
                        m_drawThreadHighlight = tid;
                    }
                    ImGui::TableNextColumn();
                    if( drawSeparator ) ImGui::Separator();
                    if( tidMatch )
                    {
                        SmallColorBox( GetThreadColor( tid, 0 ) );
                        ImGui::SameLine();
                    }
                    ImGui::TextUnformatted( tname );
                    if( ImGui::IsItemHovered() )
                    {
                        if( tidMatch )
                        {
                            m_drawThreadMigrations = tid;
                            m_cpuDataThread = tid;
                        }
                        m_drawThreadHighlight = tid;
                    }
                    ImGui::TableNextColumn();
                    if( drawSeparator ) ImGui::Separator();
                    PrintStringPercent( buf, TimeToString( tit->second.runningTime ), double( tit->second.runningTime ) * rtimespan * 100 );
                    style.FramePadding.y = 0;
                    ImGui::ProgressBar( double( tit->second.runningTime ) * rtimespan, ImVec2( -1, ty ), buf );
                    style.FramePadding.y = framePaddingY;
                    ImGui::TableNextColumn();
                    if( drawSeparator ) ImGui::Separator();
                    ImGui::TextUnformatted( RealToString( tit->second.runningRegions ) );
                    ImGui::TableNextColumn();
                    if( drawSeparator )
                    {
                        drawSeparator = false;
                        ImGui::Separator();
                    }
                    ImGui::TextUnformatted( RealToString( tit->second.migrations ) );
                    ImGui::SameLine();
                    PrintStringPercent( buf, double( tit->second.migrations ) / tit->second.runningRegions * 100 );
                    TextDisabledUnformatted( buf );
                    if( tidMatch )
                    {
                        ImGui::PopStyleColor();
                    }
                }
                ImGui::TreePop();
                drawSeparator = true;
            }
            if( pidMatch )
            {
                ImGui::PopStyleColor();
            }
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();
    ImGui::End();
}


}
