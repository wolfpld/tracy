#include <numeric>

#include "imgui.h"

#include "../public/common/TracyStackFrames.hpp"
#include "TracyFilesystem.hpp"
#include "TracyImGui.hpp"
#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracyView.hpp"

namespace tracy
{

extern double s_time;

#ifndef TRACY_NO_STATISTICS
void View::FindZones()
{
    m_findZone.match = m_worker.GetMatchingSourceLocation( m_findZone.pattern, m_findZone.ignoreCase );
    if( m_findZone.match.empty() ) return;

    auto it = m_findZone.match.begin();
    while( it != m_findZone.match.end() )
    {
        if( m_worker.GetZonesForSourceLocation( *it ).zones.empty() )
        {
            it = m_findZone.match.erase( it );
        }
        else
        {
            ++it;
        }
    }
}
#endif

uint64_t View::GetSelectionTarget( const Worker::ZoneThreadData& ev, FindZone::GroupBy groupBy ) const
{
    switch( groupBy )
    {
    case FindZone::GroupBy::Thread:
        return ev.Thread();
    case FindZone::GroupBy::UserText:
    {
        const auto& zone = *ev.Zone();
        if( !m_worker.HasZoneExtra( zone ) ) return std::numeric_limits<uint64_t>::max();
        const auto& extra = m_worker.GetZoneExtra( zone );
        return extra.text.Active() ? extra.text.Idx() : std::numeric_limits<uint64_t>::max();
    }
    case FindZone::GroupBy::ZoneName:
    {
        const auto& zone = *ev.Zone();
        if( !m_worker.HasZoneExtra( zone ) ) return std::numeric_limits<uint64_t>::max();
        const auto& extra = m_worker.GetZoneExtra( zone );
        return extra.name.Active() ? extra.name.Idx() : std::numeric_limits<uint64_t>::max();
    }
    case FindZone::GroupBy::Callstack:
        return m_worker.GetZoneExtra( *ev.Zone() ).callstack.Val();
    case FindZone::GroupBy::Parent:
    {
        const auto parent = GetZoneParent( *ev.Zone(), m_worker.DecompressThread( ev.Thread() ) );
        return parent ? uint64_t( parent->SrcLoc() ) : 0;
    }
    case FindZone::GroupBy::NoGrouping:
        return 0;
    default:
        assert( false );
        return 0;
    }
}

void View::DrawZoneList( int id, const Vector<short_ptr<ZoneEvent>>& zones )
{
    const auto zsz = zones.size();
    char buf[32];
    sprintf( buf, "%i##zonelist", id );
    if( !ImGui::BeginTable( buf, 3, ImGuiTableFlags_NoSavedSettings | ImGuiTableFlags_Resizable | ImGuiTableFlags_Hideable | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_Sortable | ImGuiTableFlags_ScrollY, ImVec2( 0, ImGui::GetTextLineHeightWithSpacing() * std::min<size_t>( zsz + 1, 15 ) ) ) )
    {
        ImGui::TreePop();
        return;
    }
    ImGui::TableSetupScrollFreeze( 0, 1 );
    ImGui::TableSetupColumn( "Time from start" );
    ImGui::TableSetupColumn( "Execution time", ImGuiTableColumnFlags_PreferSortDescending );
    ImGui::TableSetupColumn( "Name", ImGuiTableColumnFlags_NoSort );
    ImGui::TableHeadersRow();

    const Vector<short_ptr<ZoneEvent>>* zonesToIterate = &zones;
    Vector<short_ptr<ZoneEvent>> sortedZones;

    const auto& sortspec = *ImGui::TableGetSortSpecs()->Specs;
    if( sortspec.ColumnIndex != 0 || sortspec.SortDirection != ImGuiSortDirection_Ascending )
    {
        zonesToIterate = &sortedZones;
        sortedZones.reserve_and_use( zones.size() );
        memcpy( sortedZones.data(), zones.data(), zones.size() * sizeof( decltype( *zones.begin() ) ) );

        switch( sortspec.ColumnIndex )
        {
        case 0:
            assert( sortspec.SortDirection != ImGuiSortDirection_Descending );
            std::reverse( sortedZones.begin(), sortedZones.end() );
            break;
        case 1:
            if( m_findZone.selfTime )
            {
                if( sortspec.SortDirection == ImGuiSortDirection_Descending )
                {
                    pdqsort_branchless( sortedZones.begin(), sortedZones.end(), [this]( const auto& lhs, const auto& rhs ) {
                        return m_worker.GetZoneEndDirect( *lhs ) - lhs->Start() - this->GetZoneChildTimeFast( *lhs ) >
                            m_worker.GetZoneEndDirect( *rhs ) - rhs->Start() - this->GetZoneChildTimeFast( *rhs );
                        } );
                }
                else
                {
                    pdqsort_branchless( sortedZones.begin(), sortedZones.end(), [this]( const auto& lhs, const auto& rhs ) {
                        return m_worker.GetZoneEndDirect( *lhs ) - lhs->Start() - this->GetZoneChildTimeFast( *lhs ) <
                            m_worker.GetZoneEndDirect( *rhs ) - rhs->Start() - this->GetZoneChildTimeFast( *rhs );
                        } );
                }
            }
            else if( m_findZone.runningTime )
            {
                if( sortspec.SortDirection == ImGuiSortDirection_Descending )
                {
                    pdqsort_branchless( sortedZones.begin(), sortedZones.end(), [this]( const auto& lhs, const auto& rhs ) {
                        const auto ctx0 = m_worker.GetContextSwitchData( GetZoneThread( *lhs ) );
                        const auto ctx1 = m_worker.GetContextSwitchData( GetZoneThread( *rhs ) );
                        int64_t t0, t1;
                        uint64_t c0, c1;
                        GetZoneRunningTime( ctx0, *lhs, t0, c0 );
                        GetZoneRunningTime( ctx1, *rhs, t1, c1 );
                        return t0 > t1;
                        } );
                }
                else
                {
                    pdqsort_branchless( sortedZones.begin(), sortedZones.end(), [this]( const auto& lhs, const auto& rhs ) {
                        const auto ctx0 = m_worker.GetContextSwitchData( GetZoneThread( *lhs ) );
                        const auto ctx1 = m_worker.GetContextSwitchData( GetZoneThread( *rhs ) );
                        int64_t t0, t1;
                        uint64_t c0, c1;
                        GetZoneRunningTime( ctx0, *lhs, t0, c0 );
                        GetZoneRunningTime( ctx1, *rhs, t1, c1 );
                        return t0 < t1;
                        } );
                }
            }
            else
            {
                if( sortspec.SortDirection == ImGuiSortDirection_Descending )
                {
                    pdqsort_branchless( sortedZones.begin(), sortedZones.end(), [this]( const auto& lhs, const auto& rhs ) {
                        return m_worker.GetZoneEndDirect( *lhs ) - lhs->Start() > m_worker.GetZoneEndDirect( *rhs ) - rhs->Start();
                        } );
                }
                else
                {
                    pdqsort_branchless( sortedZones.begin(), sortedZones.end(), [this]( const auto& lhs, const auto& rhs ) {
                        return m_worker.GetZoneEndDirect( *lhs ) - lhs->Start() < m_worker.GetZoneEndDirect( *rhs ) - rhs->Start();
                        } );
                }
            }
            break;
        case 2:
            if( sortspec.SortDirection == ImGuiSortDirection_Descending )
            {
                pdqsort_branchless( sortedZones.begin(), sortedZones.end(), [this]( const auto& lhs, const auto& rhs ) {
                    const auto hle = m_worker.HasZoneExtra( *lhs );
                    const auto hre = m_worker.HasZoneExtra( *rhs );
                    if( !( hle & hre ) ) return hle > hre;
                    return strcmp( m_worker.GetString( m_worker.GetZoneExtra( *lhs ).name ), m_worker.GetString( m_worker.GetZoneExtra( *rhs ).name ) ) < 0;
                    } );
            }
            else
            {
                pdqsort_branchless( sortedZones.begin(), sortedZones.end(), [this]( const auto& lhs, const auto& rhs ) {
                    const auto hle = m_worker.HasZoneExtra( *lhs );
                    const auto hre = m_worker.HasZoneExtra( *rhs );
                    if( !( hle & hre ) ) return hle < hre;
                    return strcmp( m_worker.GetString( m_worker.GetZoneExtra( *lhs ).name ), m_worker.GetString( m_worker.GetZoneExtra( *rhs ).name ) ) > 0;
                    } );
            }
            break;
        default:
            assert( false );
            break;
        }
    }

    ImGuiListClipper clipper;
    clipper.Begin( zonesToIterate->size() );
    while( clipper.Step() )
    {
        for( auto i=clipper.DisplayStart; i<clipper.DisplayEnd; i++ )
        {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();

            auto ev = (*zonesToIterate)[i].get();
            const auto end = m_worker.GetZoneEndDirect( *ev );
            int64_t timespan;
            if( m_findZone.runningTime )
            {
                const auto ctx = m_worker.GetContextSwitchData( GetZoneThread( *ev ) );
                uint64_t cnt;
                GetZoneRunningTime( ctx, *ev, timespan, cnt );
            }
            else
            {
                timespan = end - ev->Start();
                if( m_findZone.selfTime ) timespan -= GetZoneChildTimeFast( *ev );
            }

            ImGui::PushID( ev );
            if( m_zoneHover == ev ) ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 0, 1, 0, 1 ) );
            if( ImGui::Selectable( TimeToStringExact( ev->Start() ), m_zoneInfoWindow == ev, ImGuiSelectableFlags_SpanAllColumns ) )
            {
                ShowZoneInfo( *ev );
            }
            if( ImGui::IsItemHovered() )
            {
                m_zoneHighlight = ev;
                if( IsMouseClicked( 2 ) )
                {
                    ZoomToZone( *ev );
                }
                ZoneTooltip( *ev );
                m_zoneHover2 = ev;
            }

            ImGui::TableNextColumn();
            ImGui::TextUnformatted( TimeToString( timespan ) );
            ImGui::TableNextColumn();
            if( m_worker.HasZoneExtra( *ev ) )
            {
                const auto& extra = m_worker.GetZoneExtra( *ev );
                if( extra.name.Active() )
                {
                    ImGui::TextUnformatted( m_worker.GetString( extra.name ) );
                }
            }
            if( m_zoneHover == ev ) ImGui::PopStyleColor();
            ImGui::PopID();
        }
    }
    ImGui::EndTable();
    ImGui::TreePop();
}

void View::DrawFindZone()
{
    if( m_shortcut == ShortcutAction::OpenFind ) ImGui::SetNextWindowFocus();

    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 520 * scale, 800 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Find zone", &m_findZone.show, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }
#ifdef TRACY_NO_STATISTICS
    ImGui::TextWrapped( "Collection of statistical data is disabled in this build." );
    ImGui::TextWrapped( "Rebuild without the TRACY_NO_STATISTICS macro to enable zone search." );
#else
    if( !m_worker.AreSourceLocationZonesReady() )
    {
        ImGui::TextWrapped( "Please wait, computing data..." );
        DrawWaitingDots( s_time );
        ImGui::End();
        return;
    }

    bool findClicked = false;

    ImGui::PushItemWidth( -0.01f );
    if( m_shortcut == ShortcutAction::OpenFind )
    {
        ImGui::SetKeyboardFocusHere();
        m_shortcut = ShortcutAction::None;
    }
    else if( ImGui::IsWindowAppearing() )
    {
        ImGui::SetKeyboardFocusHere();
    }
    findClicked |= ImGui::InputTextWithHint( "###findzone", "Enter zone name to search for", m_findZone.pattern, 1024, ImGuiInputTextFlags_EnterReturnsTrue );
    ImGui::PopItemWidth();

    findClicked |= ImGui::Button( ICON_FA_MAGNIFYING_GLASS " Find" );
    ImGui::SameLine();

    if( ImGui::Button( ICON_FA_BAN " Clear" ) )
    {
        m_findZone.Reset();
    }
    ImGui::SameLine();
    ImGui::Checkbox( "Ignore case", &m_findZone.ignoreCase );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    if( ImGui::Checkbox( "Limit range", &m_findZone.range.active ) )
    {
        if( m_findZone.range.active && m_findZone.range.min == 0 && m_findZone.range.max == 0 )
        {
            m_findZone.range.min = m_vd.zvStart;
            m_findZone.range.max = m_vd.zvEnd;
        }
    }
    if( m_findZone.range.active )
    {
        ImGui::SameLine();
        TextColoredUnformatted( 0xFF00FFFF, ICON_FA_TRIANGLE_EXCLAMATION );
        ImGui::SameLine();
        ToggleButton( ICON_FA_RULER " Limits", m_showRanges );
    }

    if( m_findZone.rangeSlim != m_findZone.range )
    {
        m_findZone.ResetMatch();
        m_findZone.rangeSlim = m_findZone.range;
    }

    if( findClicked )
    {
        m_findZone.Reset();
        FindZones();
    }

    if( !m_findZone.match.empty() )
    {
        Achieve( "findZone" );

        const auto rangeMin = m_findZone.range.min;
        const auto rangeMax = m_findZone.range.max;

        ImGui::Separator();
        ImGui::BeginChild( "##findzone" );
        bool expand = ImGui::TreeNodeEx( "Matched source locations", ImGuiTreeNodeFlags_DefaultOpen );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%zu)", m_findZone.match.size() );
        if( expand )
        {
            auto prev = m_findZone.selMatch;
            int idx = 0;
            for( auto& v : m_findZone.match )
            {
                auto& srcloc = m_worker.GetSourceLocation( v );
                auto& zones = m_worker.GetZonesForSourceLocation( v ).zones;
                SmallColorBox( GetSrcLocColor( srcloc, 0 ) );
                ImGui::SameLine();
                ImGui::PushID( idx );
                ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
                ImGui::RadioButton( m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function ), &m_findZone.selMatch, idx++ );
                ImGui::PopStyleVar();
                if( m_findZoneBuzzAnim.Match( idx ) )
                {
                    const auto time = m_findZoneBuzzAnim.Time();
                    const auto indentVal = sin( time * 60.f ) * 10.f * time;
                    ImGui::SameLine( 0, ImGui::GetStyle().ItemSpacing.x + indentVal );
                }
                else
                {
                    ImGui::SameLine();
                }
                const auto fileName = m_worker.GetString( srcloc.file );
                ImGui::TextColored( ImVec4( 0.5, 0.5, 0.5, 1 ), "(%s) %s", RealToString( zones.size() ), LocationToString( fileName, srcloc.line ) );
                if( ImGui::IsItemHovered() )
                {
                    DrawSourceTooltip( fileName, srcloc.line );
                    if( ImGui::IsItemClicked( 1 ) )
                    {
                        if( SourceFileValid( fileName, m_worker.GetCaptureTime(), *this, m_worker ) )
                        {
                            ViewSourceCheckKeyMod( fileName, srcloc.line, m_worker.GetString( srcloc.function ) );
                        }
                        else
                        {
                            m_findZoneBuzzAnim.Enable( idx, 0.5f );
                        }
                    }
                }
                ImGui::PopID();
            }
            ImGui::TreePop();

            if( m_findZone.selMatch != prev )
            {
                m_findZone.ResetMatch();
            }
        }
        if( m_findZone.scheduleResetMatch )
        {
            m_findZone.scheduleResetMatch = false;
            m_findZone.ResetMatch();
        }

        ImGui::Separator();

        auto& zoneData = m_worker.GetZonesForSourceLocation( m_findZone.match[m_findZone.selMatch] );
        auto& zones = zoneData.zones;
        zones.ensure_sorted();
        if( ImGui::TreeNodeEx( "Histogram", ImGuiTreeNodeFlags_DefaultOpen ) )
        {
            const auto ty = ImGui::GetTextLineHeight();

            int64_t tmin = m_findZone.tmin;
            int64_t tmax = m_findZone.tmax;
            int64_t total = m_findZone.total;
            const auto zsz = zones.size();
            if( m_findZone.sortedNum != zsz )
            {
                auto& vec = m_findZone.sorted;
                const auto vszorig = vec.size();
                vec.reserve( zsz );
                size_t i;
                if( m_findZone.runningTime )
                {
                    if( m_findZone.range.active )
                    {
                        for( i=m_findZone.sortedNum; i<zsz; i++ )
                        {
                            auto& zone = *zones[i].Zone();
                            const auto end = zone.End();
                            if( end > rangeMax || zone.Start() < rangeMin ) continue;
                            const auto ctx = m_worker.GetContextSwitchData( m_worker.DecompressThread( zones[i].Thread() ) );
                            if( !ctx ) break;
                            int64_t t;
                            uint64_t cnt;
                            if( !GetZoneRunningTime( ctx, zone, t, cnt ) ) break;
                            vec.push_back_no_space_check( t );
                            total += t;
                            if( t < tmin ) tmin = t;
                            else if( t > tmax ) tmax = t;
                        }
                    }
                    else
                    {
                        for( i=m_findZone.sortedNum; i<zsz; i++ )
                        {
                            auto& zone = *zones[i].Zone();
                            const auto ctx = m_worker.GetContextSwitchData( m_worker.DecompressThread( zones[i].Thread() ) );
                            if( !ctx ) break;
                            int64_t t;
                            uint64_t cnt;
                            if( !GetZoneRunningTime( ctx, zone, t, cnt ) ) break;
                            vec.push_back_no_space_check( t );
                            total += t;
                            if( t < tmin ) tmin = t;
                            else if( t > tmax ) tmax = t;
                        }
                    }
                }
                else if( m_findZone.selfTime )
                {
                    tmin = zoneData.selfMin;
                    tmax = zoneData.selfMax;
                    if( m_findZone.range.active )
                    {
                        for( i=m_findZone.sortedNum; i<zsz; i++ )
                        {
                            auto& zone = *zones[i].Zone();
                            const auto end = zone.End();
                            const auto start = zone.Start();
                            if( end > rangeMax || start < rangeMin ) continue;
                            const auto t = end - start - GetZoneChildTimeFast( zone );
                            vec.push_back_no_space_check( t );
                            total += t;
                        }
                    }
                    else
                    {
                        for( i=m_findZone.sortedNum; i<zsz; i++ )
                        {
                            auto& zone = *zones[i].Zone();
                            const auto end = zone.End();
                            const auto t = end - zone.Start() - GetZoneChildTimeFast( zone );
                            vec.push_back_no_space_check( t );
                            total += t;
                        }
                    }
                }
                else
                {
                    tmin = zoneData.min;
                    tmax = zoneData.max;
                    if( m_findZone.range.active )
                    {
                        for( i=m_findZone.sortedNum; i<zsz; i++ )
                        {
                            auto& zone = *zones[i].Zone();
                            const auto end = zone.End();
                            const auto start = zone.Start();
                            if( end > rangeMax || start < rangeMin ) continue;
                            const auto t = end - start;
                            vec.push_back_no_space_check( t );
                            total += t;
                        }
                    }
                    else
                    {
                        for( i=m_findZone.sortedNum; i<zsz; i++ )
                        {
                            auto& zone = *zones[i].Zone();
                            const auto end = zone.End();
                            const auto t = end - zone.Start();
                            vec.push_back_no_space_check( t );
                            total += t;
                        }
                    }
                }
                auto mid = vec.begin() + vszorig;
#ifdef NO_PARALLEL_SORT
                pdqsort_branchless( mid, vec.end() );
#else
                std::sort( std::execution::par_unseq, mid, vec.end() );
#endif
                std::inplace_merge( vec.begin(), mid, vec.end() );

                const auto vsz = vec.size();
                if( vsz != 0 )
                {
                    m_findZone.average = float( total ) / vsz;
                    m_findZone.median = vec[vsz/2];
                    m_findZone.total = total;
                    m_findZone.sortedNum = i;
                    m_findZone.tmin = tmin;
                    m_findZone.tmax = tmax;
                }
            }

            if( m_findZone.selGroup != m_findZone.Unselected )
            {
                if( m_findZone.selSortNum != m_findZone.sortedNum )
                {
                    const auto selGroup = m_findZone.selGroup;
                    const auto groupBy = m_findZone.groupBy;

                    auto& vec = m_findZone.selSort;
                    vec.reserve( zsz );
                    auto act = m_findZone.selSortActive;
                    int64_t total = m_findZone.selTotal;
                    if( m_findZone.runningTime )
                    {
                        if( m_findZone.range.active )
                        {
                            for( size_t i=m_findZone.selSortNum; i<m_findZone.sortedNum; i++ )
                            {
                                auto& ev = zones[i];
                                if( ev.Zone()->End() > rangeMax || ev.Zone()->Start() < rangeMin ) continue;
                                if( m_filteredZones.contains( &ev ) ) continue;
                                if( selGroup == GetSelectionTarget( ev, groupBy ) )
                                {
                                    const auto ctx = m_worker.GetContextSwitchData( m_worker.DecompressThread( zones[i].Thread() ) );
                                    int64_t t;
                                    uint64_t cnt;
                                    GetZoneRunningTime( ctx, *ev.Zone(), t, cnt );
                                    vec.push_back_no_space_check( t );
                                    act++;
                                    total += t;
                                }
                            }
                        }
                        else
                        {
                            for( size_t i=m_findZone.selSortNum; i<m_findZone.sortedNum; i++ )
                            {
                                auto& ev = zones[i];
                                if( m_filteredZones.contains( &ev ) ) continue;
                                if( selGroup == GetSelectionTarget( ev, groupBy ) )
                                {
                                    const auto ctx = m_worker.GetContextSwitchData( m_worker.DecompressThread( zones[i].Thread() ) );
                                    int64_t t;
                                    uint64_t cnt;
                                    GetZoneRunningTime( ctx, *ev.Zone(), t, cnt );
                                    vec.push_back_no_space_check( t );
                                    act++;
                                    total += t;
                                }
                            }
                        }
                    }
                    else if( m_findZone.selfTime )
                    {
                        if( m_findZone.range.active )
                        {
                            for( size_t i=m_findZone.selSortNum; i<m_findZone.sortedNum; i++ )
                            {
                                auto& ev = zones[i];
                                if( ev.Zone()->End() > rangeMax || ev.Zone()->Start() < rangeMin ) continue;
                                if( m_filteredZones.contains( &ev ) ) continue;
                                if( selGroup == GetSelectionTarget( ev, groupBy ) )
                                {
                                    const auto t = ev.Zone()->End() - ev.Zone()->Start() - GetZoneChildTimeFast( *ev.Zone() );
                                    vec.push_back_no_space_check( t );
                                    act++;
                                    total += t;
                                }
                            }
                        }
                        else
                        {
                            for( size_t i=m_findZone.selSortNum; i<m_findZone.sortedNum; i++ )
                            {
                                auto& ev = zones[i];
                                if( m_filteredZones.contains( &ev ) ) continue;
                                if( selGroup == GetSelectionTarget( ev, groupBy ) )
                                {
                                    const auto t = ev.Zone()->End() - ev.Zone()->Start() - GetZoneChildTimeFast( *ev.Zone() );
                                    vec.push_back_no_space_check( t );
                                    act++;
                                    total += t;
                                }
                            }
                        }
                    }
                    else
                    {
                        if( m_findZone.range.active )
                        {
                            for( size_t i=m_findZone.selSortNum; i<m_findZone.sortedNum; i++ )
                            {
                                auto& ev = zones[i];
                                if( ev.Zone()->End() > rangeMax || ev.Zone()->Start() < rangeMin ) continue;
                                if( m_filteredZones.contains( &ev ) ) continue;
                                if( selGroup == GetSelectionTarget( ev, groupBy ) )
                                {
                                    const auto t = ev.Zone()->End() - ev.Zone()->Start();
                                    vec.push_back_no_space_check( t );
                                    act++;
                                    total += t;
                                }
                            }
                        }
                        else
                        {
                            for( size_t i=m_findZone.selSortNum; i<m_findZone.sortedNum; i++ )
                            {
                                auto& ev = zones[i];
                                if( m_filteredZones.contains( &ev ) ) continue;
                                if( selGroup == GetSelectionTarget( ev, groupBy ) )
                                {
                                    const auto t = ev.Zone()->End() - ev.Zone()->Start();
                                    vec.push_back_no_space_check( t );
                                    act++;
                                    total += t;
                                }
                            }
                        }
                    }
                    if( !vec.empty() )
                    {
                        auto mid = vec.begin() + m_findZone.selSortActive;
                        pdqsort_branchless( mid, vec.end() );
                        std::inplace_merge( vec.begin(), mid, vec.end() );

                        m_findZone.selAverage = float( total ) / act;
                        m_findZone.selMedian = vec[act/2];
                        m_findZone.selTotal = total;
                        m_findZone.selSortNum = m_findZone.sortedNum;
                        m_findZone.selSortActive = act;
                    }
                }
            }

            if( tmin != std::numeric_limits<int64_t>::max() && !m_findZone.sorted.empty() )
            {
                TextDisabledUnformatted( "Minimum values in bin:" );
                ImGui::SameLine();
                ImGui::SetNextItemWidth( ImGui::CalcTextSize( "123456890123456" ).x );
                ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 1, 1 ) );
                ImGui::InputInt( "##minBinVal", &m_findZone.minBinVal );
                if( m_findZone.minBinVal < 1 ) m_findZone.minBinVal = 1;
                ImGui::SameLine();
                if( ImGui::Button( "Reset" ) ) m_findZone.minBinVal = 1;
                ImGui::PopStyleVar();

                SmallCheckbox( "Log values", &m_findZone.logVal );
                ImGui::SameLine();
                if( SmallCheckbox( "Log time", &m_findZone.logTime ) )
                {
                    m_findZone.binCache.numBins = -1;
                }
                ImGui::SameLine();
                SmallCheckbox( "Cumulate time", &m_findZone.cumulateTime );
                ImGui::SameLine();
                DrawHelpMarker( "Show total time taken by calls in each bin instead of call counts." );
                ImGui::SameLine();
                if( SmallCheckbox( "Self time", &m_findZone.selfTime ) )
                {
                    m_findZone.runningTime = false;
                    m_findZone.scheduleResetMatch = true;
                }
                ImGui::SameLine();
                char buf[64];
                PrintStringPercent( buf, 100.f * zoneData.selfTotal / zoneData.total );
                TextDisabledUnformatted( buf );
                if( m_worker.HasContextSwitches() )
                {
                    ImGui::SameLine();
                    if( SmallCheckbox( "Running time", &m_findZone.runningTime ) )
                    {
                        m_findZone.selfTime = false;
                        m_findZone.scheduleResetMatch = true;
                    }
                }

                const auto cumulateTime = m_findZone.cumulateTime;

                if( tmax - tmin > 0 )
                {
                    const auto w = ImGui::GetContentRegionAvail().x;

                    const auto numBins = int64_t( w - 4 );
                    if( numBins > 1 )
                    {
                        const auto s = std::min( m_findZone.highlight.start, m_findZone.highlight.end );
                        const auto e = std::max( m_findZone.highlight.start, m_findZone.highlight.end );

                        const auto& sorted = m_findZone.sorted;

                        auto sortedBegin = sorted.begin();
                        auto sortedEnd = sorted.end();
                        while( sortedBegin != sortedEnd && *sortedBegin == 0 ) ++sortedBegin;

                        if( m_findZone.minBinVal > 1 || m_findZone.range.active )
                        {
                            if( m_findZone.logTime )
                            {
                                const auto tMinLog = log10( tmin );
                                const auto zmax = ( log10( tmax ) - tMinLog ) / numBins;
                                int64_t i;
                                for( i=0; i<numBins; i++ )
                                {
                                    const auto nextBinVal = int64_t( pow( 10.0, tMinLog + ( i+1 ) * zmax ) );
                                    auto nit = std::lower_bound( sortedBegin, sortedEnd, nextBinVal );
                                    const auto distance = std::distance( sortedBegin, nit );
                                    if( distance >= m_findZone.minBinVal ) break;
                                    sortedBegin = nit;
                                }
                                for( int64_t j=numBins-1; j>i; j-- )
                                {
                                    const auto nextBinVal = int64_t( pow( 10.0, tMinLog + ( j-1 ) * zmax ) );
                                    auto nit = std::lower_bound( sortedBegin, sortedEnd, nextBinVal );
                                    const auto distance = std::distance( nit, sortedEnd );
                                    if( distance >= m_findZone.minBinVal ) break;
                                    sortedEnd = nit;
                                }
                            }
                            else
                            {
                                const auto zmax = tmax - tmin;
                                int64_t i;
                                for( i=0; i<numBins; i++ )
                                {
                                    const auto nextBinVal = tmin + ( i+1 ) * zmax / numBins;
                                    auto nit = std::lower_bound( sortedBegin, sortedEnd, nextBinVal );
                                    const auto distance = std::distance( sortedBegin, nit );
                                    if( distance >= m_findZone.minBinVal ) break;
                                    sortedBegin = nit;
                                }
                                for( int64_t j=numBins-1; j>i; j-- )
                                {
                                    const auto nextBinVal = tmin + ( j-1 ) * zmax / numBins;
                                    auto nit = std::lower_bound( sortedBegin, sortedEnd, nextBinVal );
                                    const auto distance = std::distance( nit, sortedEnd );
                                    if( distance >= m_findZone.minBinVal ) break;
                                    sortedEnd = nit;
                                }
                            }

                            if( sortedBegin != sorted.end() )
                            {
                                tmin = *sortedBegin;
                                tmax = *(sortedEnd-1);
                                total = 0;
                                for( auto ptr = sortedBegin; ptr != sortedEnd; ptr++ ) total += *ptr;
                            }
                        }

                        if( numBins > m_findZone.numBins )
                        {
                            m_findZone.numBins = numBins;
                            m_findZone.bins = std::make_unique<int64_t[]>( numBins );
                            m_findZone.binTime = std::make_unique<int64_t[]>( numBins );
                            m_findZone.selBin = std::make_unique<int64_t[]>( numBins );
                            m_findZone.binCache.numBins = -1;
                        }

                        const auto& bins = m_findZone.bins;
                        const auto& binTime = m_findZone.binTime;
                        const auto& selBin = m_findZone.selBin;

                        const auto distBegin = std::distance( sorted.begin(), sortedBegin );
                        const auto distEnd = std::distance( sorted.begin(), sortedEnd );
                        if( m_findZone.binCache.numBins != numBins ||
                            m_findZone.binCache.distBegin != distBegin ||
                            m_findZone.binCache.distEnd != distEnd )
                        {
                            m_findZone.binCache.numBins = numBins;
                            m_findZone.binCache.distBegin = distBegin;
                            m_findZone.binCache.distEnd = distEnd;

                            memset( bins.get(), 0, sizeof( int64_t ) * numBins );
                            memset( binTime.get(), 0, sizeof( int64_t ) * numBins );
                            memset( selBin.get(), 0, sizeof( int64_t ) * numBins );

                            int64_t selectionTime = 0;

                            if( m_findZone.logTime )
                            {
                                const auto tMinLog = log10( tmin );
                                const auto zmax = ( log10( tmax ) - tMinLog ) / numBins;
                                {
                                    auto zit = sortedBegin;
                                    for( int64_t i=0; i<numBins; i++ )
                                    {
                                        const auto nextBinVal = int64_t( pow( 10.0, tMinLog + ( i+1 ) * zmax ) );
                                        auto nit = std::lower_bound( zit, sortedEnd, nextBinVal );
                                        const auto distance = std::distance( zit, nit );
                                        const auto timeSum = std::accumulate( zit, nit, int64_t( 0 ) );
                                        bins[i] = distance;
                                        binTime[i] = timeSum;
                                        if( m_findZone.highlight.active )
                                        {
                                            auto end = nit == zit ? zit : nit-1;
                                            if( *zit >= s && *end <= e ) selectionTime += timeSum;
                                        }
                                        zit = nit;
                                    }
                                    const auto timeSum = std::accumulate( zit, sortedEnd, int64_t( 0 ) );
                                    bins[numBins-1] += std::distance( zit, sortedEnd );
                                    binTime[numBins-1] += timeSum;
                                    if( m_findZone.highlight.active && *zit >= s && *(sortedEnd-1) <= e ) selectionTime += timeSum;
                                }

                                if( m_findZone.selGroup != m_findZone.Unselected )
                                {
                                    auto zit = m_findZone.selSort.begin();
                                    while( zit != m_findZone.selSort.end() && *zit == 0 ) ++zit;
                                    for( int64_t i=0; i<numBins; i++ )
                                    {
                                        const auto nextBinVal = int64_t( pow( 10.0, tMinLog + ( i+1 ) * zmax ) );
                                        auto nit = std::lower_bound( zit, m_findZone.selSort.end(), nextBinVal );
                                        if( cumulateTime )
                                        {
                                            selBin[i] = std::accumulate( zit, nit, int64_t( 0 ) );
                                        }
                                        else
                                        {
                                            selBin[i] = std::distance( zit, nit );
                                        }
                                        zit = nit;
                                    }
                                }
                            }
                            else
                            {
                                const auto zmax = tmax - tmin;
                                auto zit = sortedBegin;
                                for( int64_t i=0; i<numBins; i++ )
                                {
                                    const auto nextBinVal = tmin + ( i+1 ) * zmax / numBins;
                                    auto nit = std::lower_bound( zit, sortedEnd, nextBinVal );
                                    const auto distance = std::distance( zit, nit );
                                    const auto timeSum = std::accumulate( zit, nit, int64_t( 0 ) );
                                    bins[i] = distance;
                                    binTime[i] = timeSum;
                                    if( m_findZone.highlight.active )
                                    {
                                        auto end = nit == zit ? zit : nit-1;
                                        if( *zit >= s && *end <= e ) selectionTime += timeSum;
                                    }
                                    zit = nit;
                                }
                                const auto timeSum = std::accumulate( zit, sortedEnd, int64_t( 0 ) );
                                bins[numBins-1] += std::distance( zit, sortedEnd );
                                binTime[numBins-1] += timeSum;
                                if( m_findZone.highlight.active && *zit >= s && *(sortedEnd-1) <= e ) selectionTime += timeSum;

                                if( m_findZone.selGroup != m_findZone.Unselected )
                                {
                                    auto zit = m_findZone.selSort.begin();
                                    while( zit != m_findZone.selSort.end() && *zit == 0 ) ++zit;
                                    for( int64_t i=0; i<numBins; i++ )
                                    {
                                        const auto nextBinVal = tmin + ( i+1 ) * zmax / numBins;
                                        auto nit = std::lower_bound( zit, m_findZone.selSort.end(), nextBinVal );
                                        if( cumulateTime )
                                        {
                                            selBin[i] = std::accumulate( zit, nit, int64_t( 0 ) );
                                        }
                                        else
                                        {
                                            selBin[i] = std::distance( zit, nit );
                                        }
                                        zit = nit;
                                    }
                                }
                            }

                            m_findZone.selTime = selectionTime;
                        }

                        int maxBin = 0;
                        int64_t maxVal;
                        if( cumulateTime )
                        {
                            maxVal = binTime[0];
                            for( int i=1; i<numBins; i++ )
                            {
                                if( maxVal < binTime[i] )
                                {
                                    maxVal = binTime[i];
                                    maxBin = i;
                                }
                            }
                        }
                        else
                        {
                            maxVal = bins[0];
                            for( int i=1; i<numBins; i++ )
                            {
                                if( maxVal < bins[i] )
                                {
                                    maxVal = bins[i];
                                    maxBin = i;
                                }
                            }
                        }

                        TextFocused( "Total time:", TimeToString( total ) );
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        TextFocused( "Max counts:", cumulateTime ? TimeToString( maxVal ) : RealToString( maxVal ) );
                        TextFocused( "Mean:", TimeToString( m_findZone.average ) );
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        TextFocused( "Median:", TimeToString( m_findZone.median ) );
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        {
                            int64_t t0, t1;
                            if( m_findZone.logTime )
                            {
                                const auto ltmin = log10( tmin );
                                const auto ltmax = log10( tmax );
                                t0 = int64_t( pow( 10, ltmin + double( maxBin )   / numBins * ( ltmax - ltmin ) ) );
                                t1 = int64_t( pow( 10, ltmin + double( maxBin+1 ) / numBins * ( ltmax - ltmin ) ) );
                            }
                            else
                            {
                                t0 = int64_t( tmin + double( maxBin )   / numBins * ( tmax - tmin ) );
                                t1 = int64_t( tmin + double( maxBin+1 ) / numBins * ( tmax - tmin ) );
                            }
                            TextFocused( "Mode:", TimeToString( ( t0 + t1 ) / 2 ) );
                        }
                        if( !m_findZone.range.active && m_findZone.sorted.size() > 1 )
                        {
                            const auto sz = m_findZone.sorted.size();
                            const auto avg = m_findZone.average;
                            const auto ss = zoneData.sumSq - 2. * zoneData.total * avg + avg * avg * sz;
                            const auto sd = sqrt( ss / ( sz - 1 ) );

                            ImGui::SameLine();
                            ImGui::Spacing();
                            ImGui::SameLine();
                            TextFocused( "\xcf\x83:", TimeToString( sd ) );
                            TooltipIfHovered( "Standard deviation" );
                        }

                        TextDisabledUnformatted( "Selection range:" );
                        ImGui::SameLine();
                        if( m_findZone.highlight.active )
                        {
                            const auto s = std::min( m_findZone.highlight.start, m_findZone.highlight.end );
                            const auto e = std::max( m_findZone.highlight.start, m_findZone.highlight.end );
                            ImGui::Text( "%s - %s (%s)", TimeToString( s ), TimeToString( e ), TimeToString( e - s ) );
                        }
                        else
                        {
                            ImGui::TextUnformatted( "none" );
                        }
                        ImGui::SameLine();
                        DrawHelpMarker( "Left draw on histogram to select range. Right click to clear selection." );
                        if( m_findZone.highlight.active )
                        {
                            TextFocused( "Selection time:", TimeToString( m_findZone.selTime ) );
                        }
                        else
                        {
                            TextFocused( "Selection time:", "none" );
                        }
                        if( m_findZone.selGroup != m_findZone.Unselected )
                        {
                            TextFocused( "Zone group time:", TimeToString( m_findZone.groups[m_findZone.selGroup].time ) );
                            TextFocused( "Group mean:", TimeToString( m_findZone.selAverage ) );
                            ImGui::SameLine();
                            ImGui::Spacing();
                            ImGui::SameLine();
                            TextFocused( "Group median:", TimeToString( m_findZone.selMedian ) );
                        }
                        else
                        {
                            TextFocused( "Zone group time:", "none" );
                            TextFocused( "Group mean:", "none" );
                            ImGui::SameLine();
                            ImGui::Spacing();
                            ImGui::SameLine();
                            TextFocused( "Group median:", "none" );
                        }

                        ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
                        ImGui::Checkbox( "###draw1", &m_findZone.drawAvgMed );
                        ImGui::SameLine();
                        ImGui::ColorButton( "c1", ImVec4( 0xFF/255.f, 0x44/255.f, 0x44/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip | ImGuiColorEditFlags_NoDragDrop );
                        ImGui::SameLine();
                        ImGui::TextUnformatted( "Mean time" );
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        ImGui::ColorButton( "c2", ImVec4( 0x44/255.f, 0xAA/255.f, 0xFF/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip | ImGuiColorEditFlags_NoDragDrop );
                        ImGui::SameLine();
                        ImGui::TextUnformatted( "Median time" );
                        ImGui::Checkbox( "###draw2", &m_findZone.drawSelAvgMed );
                        ImGui::SameLine();
                        ImGui::ColorButton( "c3", ImVec4( 0xFF/255.f, 0xAA/255.f, 0x44/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip | ImGuiColorEditFlags_NoDragDrop );
                        ImGui::SameLine();
                        if( m_findZone.selGroup != m_findZone.Unselected )
                        {
                            ImGui::TextUnformatted( "Group mean" );
                        }
                        else
                        {
                            TextDisabledUnformatted( "Group mean" );
                        }
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        ImGui::ColorButton( "c4", ImVec4( 0x44/255.f, 0xDD/255.f, 0x44/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip | ImGuiColorEditFlags_NoDragDrop );
                        ImGui::SameLine();
                        if( m_findZone.selGroup != m_findZone.Unselected )
                        {
                            ImGui::TextUnformatted( "Group median" );
                        }
                        else
                        {
                            TextDisabledUnformatted( "Group median" );
                        }
                        ImGui::PopStyleVar();

                        const auto Height = 200 * scale;
                        const auto wpos = ImGui::GetCursorScreenPos();
                        const auto dpos = wpos + ImVec2( 0.5f, 0.5f );

                        ImGui::InvisibleButton( "##histogram", ImVec2( w, Height + round( ty * 2.5 ) ) );
                        const bool hover = ImGui::IsItemHovered();

                        auto draw = ImGui::GetWindowDrawList();
                        draw->AddRectFilled( wpos, wpos + ImVec2( w, Height ), 0x22FFFFFF );
                        draw->AddRect( wpos, wpos + ImVec2( w, Height ), 0x88FFFFFF );

                        if( m_findZone.logVal )
                        {
                            const auto hAdj = double( Height - 4 ) / log10( maxVal + 1 );
                            for( int i=0; i<numBins; i++ )
                            {
                                const auto val = cumulateTime ? binTime[i] : bins[i];
                                if( val > 0 )
                                {
                                    DrawLine( draw, dpos + ImVec2( 2+i, Height-3 ), dpos + ImVec2( 2+i, Height-3 - log10( val + 1 ) * hAdj ), 0xFF22DDDD );
                                    if( selBin[i] > 0 )
                                    {
                                        DrawLine( draw, dpos + ImVec2( 2+i, Height-3 ), dpos + ImVec2( 2+i, Height-3 - log10( selBin[i] + 1 ) * hAdj ), 0xFFDD7777 );
                                    }
                                }
                            }
                        }
                        else
                        {
                            const auto hAdj = double( Height - 4 ) / maxVal;
                            for( int i=0; i<numBins; i++ )
                            {
                                const auto val = cumulateTime ? binTime[i] : bins[i];
                                if( val > 0 )
                                {
                                    DrawLine( draw, dpos + ImVec2( 2+i, Height-3 ), dpos + ImVec2( 2+i, Height-3 - val * hAdj ), 0xFF22DDDD );
                                    if( selBin[i] > 0 )
                                    {
                                        DrawLine( draw, dpos + ImVec2( 2+i, Height-3 ), dpos + ImVec2( 2+i, Height-3 - selBin[i] * hAdj ), 0xFFDD7777 );
                                    }
                                }
                            }
                        }

                        const auto xoff = 2;
                        const auto yoff = Height + 1;

                        DrawHistogramMinMaxLabel( draw, tmin, tmax, wpos + ImVec2( 0, yoff ), w, ty );

                        const auto ty05 = round( ty * 0.5f );
                        const auto ty025 = round( ty * 0.25f );
                        if( m_findZone.logTime )
                        {
                            const auto ltmin = log10( tmin );
                            const auto ltmax = log10( tmax );
                            const auto start = int( floor( ltmin ) );
                            const auto end = int( ceil( ltmax ) );

                            const auto range = ltmax - ltmin;
                            const auto step = w / range;
                            auto offset = start - ltmin;
                            int tw = 0;
                            int tx = 0;

                            auto tt = int64_t( pow( 10, start ) );

                            static const double logticks[] = { log10( 2 ), log10( 3 ), log10( 4 ), log10( 5 ), log10( 6 ), log10( 7 ), log10( 8 ), log10( 9 ) };

                            for( int i=start; i<=end; i++ )
                            {
                                const auto x = ( i - start + offset ) * step;

                                if( x >= 0 )
                                {
                                    DrawLine( draw, dpos + ImVec2( x, yoff ), dpos + ImVec2( x, yoff + ty05 ), 0x66FFFFFF );
                                    if( tw == 0 || x > tx + tw + ty * 1.1 )
                                    {
                                        tx = x;
                                        auto txt = TimeToString( tt );
                                        draw->AddText( wpos + ImVec2( x, yoff + ty05 ), 0x66FFFFFF, txt );
                                        tw = ImGui::CalcTextSize( txt ).x;
                                    }
                                }

                                for( int j=0; j<8; j++ )
                                {
                                    const auto xoff = x + logticks[j] * step;
                                    if( xoff >= 0 )
                                    {
                                        DrawLine( draw, dpos + ImVec2( xoff, yoff ), dpos + ImVec2( xoff, yoff + ty025 ), 0x66FFFFFF );
                                    }
                                }

                                tt *= 10;
                            }
                        }
                        else
                        {
                            const auto pxns = numBins / double( tmax - tmin );
                            const auto nspx = 1.0 / pxns;
                            const auto scale = std::max<float>( 0.0f, round( log10( nspx ) + 2 ) );
                            const auto step = pow( 10, scale );

                            const auto dx = step * pxns;
                            double x = 0;
                            int tw = 0;
                            int tx = 0;

                            const auto sstep = step / 10.0;
                            const auto sdx = dx / 10.0;

                            static const double linelen[] = { 0.5, 0.25, 0.25, 0.25, 0.25, 0.375, 0.25, 0.25, 0.25, 0.25 };

                            int64_t tt = int64_t( ceil( tmin / sstep ) * sstep );
                            const auto diff = tmin / sstep - int64_t( tmin / sstep );
                            const auto xo = ( diff == 0 ? 0 : ( ( 1 - diff ) * sstep * pxns ) ) + xoff;
                            int iter = int( ceil( ( tmin - int64_t( tmin / step ) * step ) / sstep ) );

                            while( x < numBins )
                            {
                                DrawLine( draw, dpos + ImVec2( xo + x, yoff ), dpos + ImVec2( xo + x, yoff + round( ty * linelen[iter] ) ), 0x66FFFFFF );
                                if( iter == 0 && ( tw == 0 || x > tx + tw + ty * 1.1 ) )
                                {
                                    tx = x;
                                    auto txt = TimeToString( tt );
                                    draw->AddText( wpos + ImVec2( xo + x, yoff + ty05 ), 0x66FFFFFF, txt );
                                    tw = ImGui::CalcTextSize( txt ).x;
                                }

                                iter = ( iter + 1 ) % 10;
                                x += sdx;
                                tt += sstep;
                            }
                        }

                        float ta, tm, tga, tgm;
                        if( m_findZone.logTime )
                        {
                            const auto ltmin = log10( tmin );
                            const auto ltmax = log10( tmax );

                            ta = ( log10( m_findZone.average ) - ltmin ) / float( ltmax - ltmin ) * numBins;
                            tm = ( log10( m_findZone.median ) - ltmin ) / float( ltmax - ltmin ) * numBins;
                            tga = ( log10( m_findZone.selAverage ) - ltmin ) / float( ltmax - ltmin ) * numBins;
                            tgm = ( log10( m_findZone.selMedian ) - ltmin ) / float( ltmax - ltmin ) * numBins;
                        }
                        else
                        {
                            ta = ( m_findZone.average - tmin ) / float( tmax - tmin ) * numBins;
                            tm = ( m_findZone.median - tmin ) / float( tmax - tmin ) * numBins;
                            tga = ( m_findZone.selAverage - tmin ) / float( tmax - tmin ) * numBins;
                            tgm = ( m_findZone.selMedian - tmin ) / float( tmax - tmin ) * numBins;
                        }
                        ta = round( ta );
                        tm = round( tm );
                        tga = round( tga );
                        tgm = round( tgm );

                        if( m_findZone.drawAvgMed )
                        {
                            if( ta == tm )
                            {
                                DrawLine( draw, ImVec2( dpos.x + ta, dpos.y ), ImVec2( dpos.x + ta, dpos.y+Height-2 ), 0xFFFF88FF );
                            }
                            else
                            {
                                DrawLine( draw, ImVec2( dpos.x + ta, dpos.y ), ImVec2( dpos.x + ta, dpos.y+Height-2 ), 0xFF4444FF );
                                DrawLine( draw, ImVec2( dpos.x + tm, dpos.y ), ImVec2( dpos.x + tm, dpos.y+Height-2 ), 0xFFFFAA44 );
                            }
                        }
                        if( m_findZone.drawSelAvgMed && m_findZone.selGroup != m_findZone.Unselected )
                        {
                            DrawLine( draw, ImVec2( dpos.x + tga, dpos.y ), ImVec2( dpos.x + tga, dpos.y+Height-2 ), 0xFF44AAFF );
                            DrawLine( draw, ImVec2( dpos.x + tgm, dpos.y ), ImVec2( dpos.x + tgm, dpos.y+Height-2 ), 0xFF44DD44 );
                        }

                        if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 2, 2 ), wpos + ImVec2( w-2, Height + round( ty * 1.5 ) ) ) )
                        {
                            const auto ltmin = log10( tmin );
                            const auto ltmax = log10( tmax );

                            auto& io = ImGui::GetIO();
                            DrawLine( draw, ImVec2( io.MousePos.x + 0.5f, dpos.y ), ImVec2( io.MousePos.x + 0.5f, dpos.y+Height-2 ), 0x33FFFFFF );

                            const auto bin = int64_t( io.MousePos.x - wpos.x - 2 );
                            int64_t t0, t1;
                            if( m_findZone.logTime )
                            {
                                t0 = int64_t( pow( 10, ltmin + double( bin ) / numBins * ( ltmax - ltmin ) ) );

                                // Hackfix for inability to select data in last bin.
                                // A proper solution would be nice.
                                if( bin+1 == numBins )
                                {
                                    t1 = tmax;
                                }
                                else
                                {
                                    t1 = int64_t( pow( 10, ltmin + double( bin+1 ) / numBins * ( ltmax - ltmin ) ) );
                                }
                            }
                            else
                            {
                                t0 = int64_t( tmin + double( bin )   / numBins * ( tmax - tmin ) );
                                t1 = int64_t( tmin + double( bin+1 ) / numBins * ( tmax - tmin ) );
                            }

                            int64_t tBefore = 0;
                            int64_t cntBefore = 0;
                            for( int i=0; i<bin; i++ )
                            {
                                tBefore += binTime[i];
                                cntBefore += bins[i];
                            }

                            int64_t tAfter = 0;
                            int64_t cntAfter = 0;
                            for( int i=bin+1; i<numBins; i++ )
                            {
                                tAfter += binTime[i];
                                cntAfter += bins[i];
                            }

                            ImGui::BeginTooltip();
                            TextDisabledUnformatted( "Time range:" );
                            ImGui::SameLine();
                            ImGui::Text( "%s - %s", TimeToString( t0 ), TimeToString( t1 ) );
                            TextFocused( "Count:", RealToString( bins[bin] ) );
                            TextFocused( "Count in the left bins:", RealToString( cntBefore ) );
                            TextFocused( "Count in the right bins:", RealToString( cntAfter ) );
                            TextFocused( "Time spent in bin:", TimeToString( binTime[bin] ) );
                            TextFocused( "Time spent in the left bins:", TimeToString( tBefore ) );
                            TextFocused( "Time spent in the right bins:", TimeToString( tAfter ) );
                            ImGui::EndTooltip();

                            if( IsMouseClicked( 1 ) )
                            {
                                m_findZone.highlight.active = false;
                                m_findZone.ResetGroups();
                            }
                            else if( IsMouseClicked( 0 ) )
                            {
                                m_findZone.highlight.active = true;
                                m_findZone.highlight.start = t0;
                                m_findZone.highlight.end = t1;
                                m_findZone.hlOrig_t0 = t0;
                                m_findZone.hlOrig_t1 = t1;
                            }
                            else if( IsMouseDragging( 0 ) )
                            {
                                if( t0 < m_findZone.hlOrig_t0 )
                                {
                                    m_findZone.highlight.start = t0;
                                    m_findZone.highlight.end = m_findZone.hlOrig_t1;
                                }
                                else
                                {
                                    m_findZone.highlight.start = m_findZone.hlOrig_t0;
                                    m_findZone.highlight.end = t1;
                                }
                                m_findZone.ResetGroups();
                            }
                        }

                        if( m_findZone.highlight.active && m_findZone.highlight.start != m_findZone.highlight.end )
                        {
                            const auto s = std::min( m_findZone.highlight.start, m_findZone.highlight.end );
                            const auto e = std::max( m_findZone.highlight.start, m_findZone.highlight.end );

                            float t0, t1;
                            if( m_findZone.logTime )
                            {
                                const auto ltmin = log10( tmin );
                                const auto ltmax = log10( tmax );

                                t0 = ( log10( s ) - ltmin ) / float( ltmax - ltmin ) * numBins;
                                t1 = ( log10( e ) - ltmin ) / float( ltmax - ltmin ) * numBins;
                            }
                            else
                            {
                                t0 = ( s - tmin ) / float( tmax - tmin ) * numBins;
                                t1 = ( e - tmin ) / float( tmax - tmin ) * numBins;
                            }

                            draw->PushClipRect( wpos, wpos + ImVec2( w, Height ), true );
                            draw->AddRectFilled( wpos + ImVec2( 2 + t0, 1 ), wpos + ImVec2( 2 + t1, Height-1 ), 0x22DD8888 );
                            draw->AddRect( wpos + ImVec2( 2 + t0, 1 ), wpos + ImVec2( 2 + t1, Height-1 ), 0x44DD8888 );
                            draw->PopClipRect();
                        }

                        if( ( m_zoneHover && m_findZone.match[m_findZone.selMatch] == m_zoneHover->SrcLoc() ) ||
                            ( m_zoneHover2 && m_findZone.match[m_findZone.selMatch] == m_zoneHover2->SrcLoc() ) )
                        {
                            const auto zoneTime = m_zoneHover ? ( m_worker.GetZoneEnd( *m_zoneHover ) - m_zoneHover->Start() ) : ( m_worker.GetZoneEnd( *m_zoneHover2 ) - m_zoneHover2->Start() );
                            float zonePos;
                            if( m_findZone.logTime )
                            {
                                const auto ltmin = log10( tmin );
                                const auto ltmax = log10( tmax );
                                zonePos = round( ( log10( zoneTime ) - ltmin ) / float( ltmax - ltmin ) * numBins );
                            }
                            else
                            {
                                zonePos = round( ( zoneTime - tmin ) / float( tmax - tmin ) * numBins );
                            }
                            const auto c = uint32_t( ( sin( s_time * 10 ) * 0.25 + 0.75 ) * 255 );
                            const auto color = 0xFF000000 | ( c << 16 ) | ( c << 8 ) | c;
                            DrawLine( draw, ImVec2( dpos.x + zonePos, dpos.y ), ImVec2( dpos.x + zonePos, dpos.y+Height-2 ), color );
                            m_wasActive = true;
                        }
                    }
                }
            }

            ImGui::TreePop();
        }

        ImGui::Separator();
        SmallCheckbox( "Show zone time in frames", &m_findZone.showZoneInFrames );
        ImGui::Separator();

        ImGui::AlignTextToFramePadding();
        TextDisabledUnformatted( "Filter user text:" );
        ImGui::SameLine();
        bool filterChanged = m_userTextFilter.Draw( ICON_FA_FILTER "###resultFilter", 200 );

        ImGui::SameLine();
        if( ImGui::Button( ICON_FA_DELETE_LEFT " Clear###userText" ) )
        {
            m_userTextFilter.Clear();
            filterChanged = true;
        }
        ImGui::Separator();
        if( filterChanged )
        {
            m_filteredZones.clear();
            m_findZone.ResetGroups();
        }

        ImGui::TextUnformatted( "Found zones:" );
        ImGui::SameLine();
        DrawHelpMarker( "Left click to highlight entry." );
        if( m_findZone.selGroup != m_findZone.Unselected )
        {
            ImGui::SameLine();
            if( ImGui::SmallButton( ICON_FA_DELETE_LEFT " Clear" ) )
            {
                m_findZone.selGroup = m_findZone.Unselected;
                m_findZone.ResetSelection();
            }
        }

        bool groupChanged = false;
        ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
        ImGui::TextUnformatted( "Group by:" );
        ImGui::SameLine();
        groupChanged |= ImGui::RadioButton( "Thread", (int*)( &m_findZone.groupBy ), (int)FindZone::GroupBy::Thread );
        ImGui::SameLine();
        groupChanged |= ImGui::RadioButton( "User text", (int*)( &m_findZone.groupBy ), (int)FindZone::GroupBy::UserText );
        ImGui::SameLine();
        groupChanged |= ImGui::RadioButton( "Zone name", (int*)( &m_findZone.groupBy ), (int)FindZone::GroupBy::ZoneName );
        ImGui::SameLine();
        groupChanged |= ImGui::RadioButton( "Call stacks", (int*)( &m_findZone.groupBy ), (int)FindZone::GroupBy::Callstack );
        ImGui::SameLine();
        groupChanged |= ImGui::RadioButton( "Parent", (int*)( &m_findZone.groupBy ), (int)FindZone::GroupBy::Parent );
        ImGui::SameLine();
        groupChanged |= ImGui::RadioButton( "No grouping", (int*)( &m_findZone.groupBy ), (int)FindZone::GroupBy::NoGrouping );
        if( groupChanged )
        {
            m_findZone.selGroup = m_findZone.Unselected;
            m_findZone.ResetGroups();
        }

        ImGui::TextUnformatted( "Sort by:" );
        ImGui::SameLine();
        ImGui::RadioButton( "Order", (int*)( &m_findZone.sortBy ), (int)FindZone::SortBy::Order );
        ImGui::SameLine();
        ImGui::RadioButton( "Count", (int*)( &m_findZone.sortBy ), (int)FindZone::SortBy::Count );
        ImGui::SameLine();
        ImGui::RadioButton( "Time", (int*)( &m_findZone.sortBy ), (int)FindZone::SortBy::Time );
        ImGui::SameLine();
        ImGui::RadioButton( "MTPC", (int*)( &m_findZone.sortBy ), (int)FindZone::SortBy::Mtpc );
        ImGui::PopStyleVar();
        ImGui::SameLine();
        DrawHelpMarker( "Mean time per call" );

        const auto hmin = std::min( m_findZone.highlight.start, m_findZone.highlight.end );
        const auto hmax = std::max( m_findZone.highlight.start, m_findZone.highlight.end );
        const auto groupBy = m_findZone.groupBy;
        const auto highlightActive = m_findZone.highlight.active;
        const auto limitRange = m_findZone.range.active;
        FindZone::Group* group = nullptr;
        constexpr uint64_t invalidGid = std::numeric_limits<uint64_t>::max() - 1;
        uint64_t lastGid = invalidGid;
        auto zptr = zones.data() + m_findZone.processed;
        const auto zend = zones.data() + zones.size();
        while( zptr < zend )
        {
            auto& ev = *zptr;
            const auto end = ev.Zone()->End();
            const auto start = ev.Zone()->Start();
            if( limitRange && ( start < rangeMin || end > rangeMax ) )
            {
                zptr++;
                continue;
            }

            if( m_userTextFilter.IsActive() )
            {
                bool keep = false;
                if ( m_worker.HasZoneExtra( *ev.Zone() ) && m_worker.GetZoneExtra( *ev.Zone() ).text.Active() )
                {
                    auto text = m_worker.GetString( m_worker.GetZoneExtra( *ev.Zone() ).text );
                    if( m_userTextFilter.PassFilter( text ) )
                    {
                        keep = true;
                    }
                }
                if( !keep )
                {
                    m_filteredZones.insert( &ev );
                    zptr++;
                    continue;
                }
            }

            auto timespan = end - start;
            assert( timespan != 0 );
            if( m_findZone.selfTime )
            {
                timespan -= GetZoneChildTimeFast( *ev.Zone() );
            }
            else if( m_findZone.runningTime )
            {
                const auto ctx = m_worker.GetContextSwitchData( m_worker.DecompressThread( ev.Thread() ) );
                if( !ctx ) break;
                int64_t t;
                uint64_t cnt;
                if( !GetZoneRunningTime( ctx, *ev.Zone(), t, cnt ) ) break;
                timespan = t;
            }

            if( highlightActive )
            {
                if( timespan < hmin || timespan > hmax )
                {
                    zptr++;
                    continue;
                }
            }

            zptr++;
            uint64_t gid = 0;
            switch( groupBy )
            {
            case FindZone::GroupBy::Thread:
                gid = ev.Thread();
                break;
            case FindZone::GroupBy::UserText:
            {
                const auto& zone = *ev.Zone();
                if( !m_worker.HasZoneExtra( zone ) )
                {
                    gid = std::numeric_limits<uint64_t>::max();
                }
                else
                {
                    const auto& extra = m_worker.GetZoneExtra( zone );
                    gid = extra.text.Active() ? extra.text.Idx() : std::numeric_limits<uint64_t>::max();
                }
                break;
            }
            case FindZone::GroupBy::ZoneName:
            {
                const auto& zone = *ev.Zone();
                if( !m_worker.HasZoneExtra( zone ) )
                {
                    gid = std::numeric_limits<uint64_t>::max();
                }
                else
                {
                    const auto& extra = m_worker.GetZoneExtra( zone );
                    gid = extra.name.Active() ? extra.name.Idx() : std::numeric_limits<uint64_t>::max();
                }
                break;
            }
            case FindZone::GroupBy::Callstack:
                gid = m_worker.GetZoneExtra( *ev.Zone() ).callstack.Val();
                break;
            case FindZone::GroupBy::Parent:
            {
                const auto parent = GetZoneParent( *ev.Zone(), m_worker.DecompressThread( ev.Thread() ) );
                if( parent ) gid = uint64_t( uint16_t( parent->SrcLoc() ) );
                break;
            }
            case FindZone::GroupBy::NoGrouping:
                break;
            default:
                assert( false );
                break;
            }
            if( lastGid != gid )
            {
                lastGid = gid;
                auto it = m_findZone.groups.find( gid );
                if( it == m_findZone.groups.end() )
                {
                    it = m_findZone.groups.emplace( gid, FindZone::Group { m_findZone.groupId++ } ).first;
                    it->second.zones.reserve( 1024 );
                    if( m_findZone.samples.enabled )
                        it->second.zonesTids.reserve( 1024 );
                }
                group = &it->second;
            }
            group->time += timespan;
            group->zones.push_back_non_empty( ev.Zone() );
            if( m_findZone.samples.enabled )
                group->zonesTids.push_back_non_empty( ev.Thread() );
        }
        m_findZone.processed = zptr - zones.data();

        const bool groupsUpdated = lastGid != invalidGid;
        if( m_findZone.samples.enabled && groupsUpdated )
        {
            m_findZone.samples.scheduleUpdate = true;
        }


        Vector<decltype( m_findZone.groups )::iterator> groups;
        groups.reserve_and_use( m_findZone.groups.size() );
        int idx = 0;
        for( auto it = m_findZone.groups.begin(); it != m_findZone.groups.end(); ++it )
        {
            groups[idx++] = it;
        }

        switch( m_findZone.sortBy )
        {
        case FindZone::SortBy::Order:
            pdqsort_branchless( groups.begin(), groups.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.id < rhs->second.id; } );
            break;
        case FindZone::SortBy::Count:
            pdqsort_branchless( groups.begin(), groups.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.zones.size() > rhs->second.zones.size(); } );
            break;
        case FindZone::SortBy::Time:
            pdqsort_branchless( groups.begin(), groups.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.time > rhs->second.time; } );
            break;
        case FindZone::SortBy::Mtpc:
            pdqsort_branchless( groups.begin(), groups.end(), []( const auto& lhs, const auto& rhs ) { return double( lhs->second.time ) / lhs->second.zones.size() > double( rhs->second.time ) / rhs->second.zones.size(); } );
            break;
        default:
            assert( false );
            break;
        }

        int16_t changeZone = 0;

        if( groupBy == FindZone::GroupBy::Callstack )
        {
            const auto gsz = (int)groups.size();
            if( gsz > 0 )
            {
                if( m_findZone.selCs > gsz ) m_findZone.selCs = gsz;
                const auto group = groups[m_findZone.selCs];

                const bool selHilite = m_findZone.selGroup == group->first;
                if( selHilite ) SetButtonHighlightColor();
                if( ImGui::SmallButton( " " ICON_FA_CHECK " " ) )
                {
                    m_findZone.selGroup = group->first;
                    m_findZone.ResetSelection();
                }
                if( selHilite ) ImGui::PopStyleColor( 3 );
                ImGui::SameLine();
                if( ImGui::SmallButton( " " ICON_FA_CARET_LEFT " " ) )
                {
                    m_findZone.selCs = std::max( m_findZone.selCs - 1, 0 );
                }
                ImGui::SameLine();
                ImGui::Text( "%s / %s", RealToString( m_findZone.selCs + 1 ), RealToString( gsz ) );
                if( ImGui::IsItemClicked() ) ImGui::OpenPopup( "FindZoneCallstackPopup" );
                ImGui::SameLine();
                if( ImGui::SmallButton( " " ICON_FA_CARET_RIGHT " " ) )
                {
                    m_findZone.selCs = std::min<int>( m_findZone.selCs + 1, gsz - 1 );
                }
                if( ImGui::BeginPopup( "FindZoneCallstackPopup" ) )
                {
                    int sel = m_findZone.selCs + 1;
                    ImGui::SetNextItemWidth( 120 * scale );
                    const bool clicked = ImGui::InputInt( "##findZoneCallstack", &sel, 1, 100, ImGuiInputTextFlags_EnterReturnsTrue );
                    if( clicked ) m_findZone.selCs = std::min( std::max( sel, 1 ), int( gsz ) ) - 1;
                    ImGui::EndPopup();
                }

                ImGui::SameLine();
                TextFocused( "Count:", RealToString( group->second.zones.size() ) );
                ImGui::SameLine();
                TextFocused( "Time:", TimeToString( group->second.time ) );
                ImGui::SameLine();
                char buf[64];
                PrintStringPercent( buf, group->second.time * 100.f / zoneData.total );
                TextDisabledUnformatted( buf );

                if( group->first != 0 )
                {
                    ImGui::SameLine();
                    int idx = 0;
                    SmallCallstackButton( " " ICON_FA_ALIGN_JUSTIFY " ", group->first, idx, false );

                    int fidx = 0;
                    ImGui::Spacing();
                    ImGui::Indent();
                    auto& csdata = m_worker.GetCallstack( group->first );
                    for( auto& entry : csdata )
                    {
                        auto frameData = m_worker.GetCallstackFrame( entry );
                        if( !frameData )
                        {
                            ImGui::TextDisabled( "%i.", fidx++ );
                            ImGui::SameLine();
                            ImGui::Text( "%p", (void*)m_worker.GetCanonicalPointer( entry ) );
                        }
                        else
                        {
                            const auto fsz = frameData->size;
                            for( uint8_t f=0; f<fsz; f++ )
                            {
                                const auto& frame = frameData->data[f];
                                auto txt = m_worker.GetString( frame.name );

                                if( fidx == 0 && f != fsz-1 )
                                {
                                    auto test = s_tracyStackFrames;
                                    bool match = false;
                                    do
                                    {
                                        if( strcmp( txt, *test ) == 0 )
                                        {
                                            match = true;
                                            break;
                                        }
                                    }
                                    while( *++test );
                                    if( match ) continue;
                                }
                                if( f == fsz-1 )
                                {
                                    ImGui::TextDisabled( "%i.", fidx++ );
                                }
                                else
                                {
                                    TextDisabledUnformatted( ICON_FA_CARET_RIGHT );
                                }
                                ImGui::SameLine();
                                if( m_vd.shortenName == ShortenName::Never )
                                {
                                    ImGui::TextUnformatted( txt );
                                }
                                else
                                {
                                    const auto normalized = ShortenZoneName( ShortenName::OnlyNormalize, txt );
                                    ImGui::TextUnformatted( normalized );
                                    TooltipNormalizedName( txt, normalized );
                                }
                            }
                        }
                    }
                    ImGui::Unindent();
                }
                else
                {
                    ImGui::Text( "No call stack" );
                }

                ImGui::Spacing();
                if( ImGui::TreeNodeEx( "Zone list" ) )
                {
                    DrawZoneList( group->second.id, group->second.zones );
                }
            }
        }
        else
        {
            TextFocused( "Number of groups:", RealToString( groups.size() ) );
            for( auto& v : groups )
            {
                bool isFiber = false;
                const char* hdrString;
                switch( groupBy )
                {
                case FindZone::GroupBy::Thread:
                {
                    const auto tid = m_worker.DecompressThread( v->first );
                    const auto threadColor = GetThreadColor( tid, 0 );
                    SmallColorBox( threadColor );
                    ImGui::SameLine();
                    hdrString = m_worker.GetThreadName( tid );
                    isFiber = m_worker.IsThreadFiber( tid );
                    break;
                }
                case FindZone::GroupBy::UserText:
                    hdrString = v->first == std::numeric_limits<uint64_t>::max() ? "No user text" : m_worker.GetString( StringIdx( v->first ) );
                    break;
                case FindZone::GroupBy::ZoneName:
                    if( v->first == std::numeric_limits<uint64_t>::max() )
                    {
                        auto& srcloc = m_worker.GetSourceLocation( m_findZone.match[m_findZone.selMatch] );
                        hdrString = m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function );
                    }
                    else
                    {
                        hdrString = m_worker.GetString( StringIdx( v->first ) );
                    }
                    break;
                case FindZone::GroupBy::Callstack:
                    if( v->first == 0 )
                    {
                        hdrString = "No callstack";
                    }
                    else
                    {
                        auto& callstack = m_worker.GetCallstack( v->first );
                        auto& frameData = *m_worker.GetCallstackFrame( *callstack.begin() );
                        hdrString = m_worker.GetString( frameData.data[frameData.size-1].name );
                    }
                    break;
                case FindZone::GroupBy::Parent:
                    if( v->first == 0 )
                    {
                        hdrString = "<no parent>";
                        SmallColorBox( 0 );
                    }
                    else
                    {
                        auto& srcloc = m_worker.GetSourceLocation( int16_t( v->first ) );
                        hdrString = m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function );
                        SmallColorBox( GetSrcLocColor( srcloc, 0 ) );
                    }
                    ImGui::SameLine();
                    break;
                case FindZone::GroupBy::NoGrouping:
                    hdrString = "Zone list";
                    break;
                default:
                    hdrString = nullptr;
                    assert( false );
                    break;
                }
                ImGui::PushID( v->first );
                const bool expand = ImGui::TreeNodeEx( hdrString, ImGuiTreeNodeFlags_OpenOnArrow | ImGuiTreeNodeFlags_OpenOnDoubleClick | ( v->first == m_findZone.selGroup ? ImGuiTreeNodeFlags_Selected : 0 ) );
                if( ImGui::IsItemClicked() )
                {
                    m_findZone.selGroup = v->first;
                    m_findZone.ResetSelection();
                }
                if( m_findZone.groupBy == FindZone::GroupBy::Parent && ImGui::IsItemClicked( 2 ) )
                {
                    changeZone = int16_t( v->first );
                }
                ImGui::PopID();
                if( isFiber )
                {
                    ImGui::SameLine();
                    TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
                }
                ImGui::SameLine();
                ImGui::TextColored( ImVec4( 0.5f, 0.5f, 0.5f, 1.0f ), "(%s) %s", RealToString( v->second.zones.size() ), TimeToString( v->second.time ) );
                if( expand )
                {
                    DrawZoneList( v->second.id, v->second.zones );
                }
            }
        }

        if( m_findZone.samples.enabled && m_findZone.samples.scheduleUpdate && !m_findZone.scheduleResetMatch )
        {
            m_findZone.samples.scheduleUpdate = false;

            const auto& symMap = m_worker.GetSymbolMap();
            m_findZone.samples.counts.clear();
            m_findZone.samples.counts.reserve( symMap.size() );

            struct GroupRange {
                const FindZone::Group* group;
                Vector<short_ptr<ZoneEvent>>::const_iterator begin;
                Vector<short_ptr<ZoneEvent>>::const_iterator end;
            };
            Vector<GroupRange> selectedGroups;
            selectedGroups.reserve( m_findZone.groups.size() );
            for( auto it = m_findZone.groups.begin(); it != m_findZone.groups.end(); ++it )
            {
                assert( it->second.zones.size() == it->second.zonesTids.size() );
                if( ( m_findZone.selGroup == m_findZone.Unselected || it->first == m_findZone.selGroup )
                    && !it->second.zones.empty() )
                {
                    selectedGroups.push_back_no_space_check( GroupRange{&it->second} );
                }
            }

            for( auto& v : symMap )
            {
                bool pass = ( m_statShowKernel || ( v.first >> 63 ) == 0 );
                if( !pass && v.second.size.Val() == 0 )
                {
                    const auto parentAddr = m_worker.GetSymbolForAddress( v.first );
                    if( parentAddr != 0 )
                    {
                        auto pit = symMap.find( parentAddr );
                        if( pit != symMap.end() )
                        {
                            pass = ( m_statShowKernel || ( parentAddr >> 63 ) == 0 );
                        }
                    }
                }
                if( !pass ) continue;

                auto samples = m_worker.GetSamplesForSymbol( v.first );
                if( !samples )  continue;

                auto samplesBegin = samples->begin();
                auto samplesEnd = samples->end();
                if( m_findZone.range.active )
                {
                    const auto rangeMin = m_findZone.range.min;
                    const auto rangeMax = m_findZone.range.max;
                    samplesBegin = std::lower_bound( samplesBegin, samplesEnd, rangeMin, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
                    samplesEnd = std::lower_bound( samplesBegin, samplesEnd, rangeMax, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
                }
                if( samplesBegin == samplesEnd )  continue;

                bool empty = true;
                const auto firstTime = samplesBegin->time.Val();
                const auto lastTime = samplesEnd == samples->end() ? m_worker.GetLastTime() : samplesEnd->time.Val();
                for( auto& g: selectedGroups )
                {
                    const auto& zones = g.group->zones;
                    auto begin = std::lower_bound( zones.begin(), zones.end(), firstTime, [] ( const auto& l, const auto& r ) { return l->Start() < r; } );
                    auto end = std::upper_bound( begin, zones.end(), lastTime, [] ( const auto& l, const auto& r ) { return l <= r->Start(); } );
                    g.begin = begin;
                    g.end = end;
                    empty = empty && (begin == end);
                }
                if (empty) continue;

                uint32_t count = 0;
                for( auto it = samplesBegin; it != samplesEnd; ++it )
                {
                    const auto time = it->time.Val();
                    bool pass = false;
                    for( auto& g: selectedGroups )
                    {
                        while( g.begin != g.end && time > (*g.begin)->End() ) ++g.begin;
                        if( g.begin == g.end ) continue;
                        if( time < (*g.begin)->Start() ) continue;

                        const auto& tids = g.group->zonesTids;
                        const auto firstZone = g.group->zones.begin();
                        for (auto z = g.begin; z != g.end && (*z)->Start() <= time; ++z)
                        {
                            auto zoneIndex = z - firstZone;
                            if( (*z)->End() > time && it->thread == tids[zoneIndex] )
                            {
                                pass = true;
                                break;
                            }
                        }
                    }
                    if( pass ) count ++;
                }
                if( count > 0 )  m_findZone.samples.counts.push_back_no_space_check( SymList { v.first, 0, count } );
            }
        }

        ImGui::Separator();
        const bool hasSamples = m_worker.AreCallstackSamplesReady() && m_worker.GetCallstackSampleCount() > 0;
        if( hasSamples && ImGui::TreeNodeEx( ICON_FA_EYE_DROPPER " Samples", ImGuiTreeNodeFlags_None ) )
        {
            {
                ImGui::Checkbox( ICON_FA_STOPWATCH " Show time", &m_statSampleTime );
                ImGui::SameLine();
                ImGui::Spacing();
                ImGui::SameLine();
                ImGui::Checkbox( ICON_FA_EYE_SLASH " Hide unknown", &m_statHideUnknown );
                ImGui::SameLine();
                ImGui::Spacing();
                ImGui::SameLine();
                ImGui::Checkbox( ICON_FA_SITEMAP " Inlines", &m_statSeparateInlines );
                ImGui::SameLine();
                ImGui::Spacing();
                ImGui::SameLine();
                ImGui::Checkbox( ICON_FA_AT " Address", &m_statShowAddress );
                ImGui::SameLine();
                ImGui::Spacing();
                ImGui::SameLine();
                if( ImGui::Checkbox( ICON_FA_HAT_WIZARD " Include kernel", &m_statShowKernel ))
                {
                    m_findZone.samples.scheduleUpdate = true;
                }
            }

            if( !m_findZone.samples.enabled )
            {
                m_findZone.samples.enabled = true;
                m_findZone.samples.scheduleUpdate = true;
                m_findZone.scheduleResetMatch = true;
            }

            Vector<SymList> data;
            data.reserve( m_findZone.samples.counts.size() );
            for( auto it: m_findZone.samples.counts ) data.push_back_no_space_check( it );
            int64_t timeRange = ( m_findZone.selGroup != m_findZone.Unselected ) ? m_findZone.selTotal : m_findZone.total;
            DrawSamplesStatistics( data, timeRange, AccumulationMode::SelfOnly );

            ImGui::TreePop();
        }
        else
        {
            if( m_findZone.samples.enabled )
            {
                m_findZone.samples.enabled = false;
                m_findZone.samples.scheduleUpdate = false;
                m_findZone.samples.counts = Vector<SymList>();
                for( auto& it: m_findZone.groups ) it.second.zonesTids.clear();
            }
        }

        ImGui::EndChild();

        if( changeZone != 0 )
        {
            auto& srcloc = m_worker.GetSourceLocation( changeZone );
            m_findZone.ShowZone( changeZone, m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function ) );
        }
    }
#endif

    ImGui::End();
}

}
