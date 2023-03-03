#include "TracyFilesystem.hpp"
#include "TracyImGui.hpp"
#include "TracyPrint.hpp"
#include "TracyView.hpp"

namespace tracy
{

extern double s_time;

struct SrcLocZonesSlim
{
    int16_t srcloc;
    size_t numZones;
    int64_t total;
};

void View::AccumulationModeComboBox()
{
    ImGui::TextUnformatted( "Timing" );
    ImGui::SameLine();
    const char* accumulationModeTable = m_statMode == 1 ? "Self only\0With children\0" : "Self only\0With children\0Non-reentrant\0";
    ImGui::SetNextItemWidth( ImGui::CalcTextSize( "Non-reentrant" ).x + ImGui::GetTextLineHeight() * 2 );
    if( m_statMode == 1 && m_statAccumulationMode == AccumulationMode::NonReentrantChildren )
    {
        m_statAccumulationMode = AccumulationMode::SelfOnly;
    }
    int accumulationMode = static_cast<int>( m_statAccumulationMode );
    ImGui::Combo( "##accumulationMode", &accumulationMode, accumulationModeTable );
    m_statAccumulationMode = static_cast<AccumulationMode>( accumulationMode );
}

void View::DrawStatistics()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 1400 * scale, 600 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Statistics", &m_showStatistics, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }
#ifdef TRACY_NO_STATISTICS
    ImGui::TextWrapped( "Collection of statistical data is disabled in this build." );
    ImGui::TextWrapped( "Rebuild without the TRACY_NO_STATISTICS macro to enable statistics view." );
#else
    if( !m_worker.AreSourceLocationZonesReady() && ( !m_worker.AreCallstackSamplesReady() || m_worker.GetCallstackSampleCount() == 0 ) )
    {
        ImGui::TextWrapped( "Please wait, computing data..." );
        DrawWaitingDots( s_time );
        ImGui::End();
        return;
    }

    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 2, 2 ) );
    ImGui::RadioButton( ICON_FA_SYRINGE " Instrumentation", &m_statMode, 0 );
    if( m_worker.AreCallstackSamplesReady() )
    {
        ImGui::SameLine();
        if( m_worker.GetCallstackSampleCount() > 0 )
        {
            ImGui::Spacing();
            ImGui::SameLine();
            ImGui::RadioButton( ICON_FA_EYE_DROPPER " Sampling", &m_statMode, 1 );
        }
        else if( m_worker.GetSymbolsCount() > 0 )
        {
            ImGui::Spacing();
            ImGui::SameLine();
            ImGui::RadioButton( ICON_FA_PUZZLE_PIECE " Symbols", &m_statMode, 1 );
        }
    }
    if( m_worker.GetGpuZoneCount() > 0 )
    {
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        ImGui::RadioButton( ICON_FA_EYE " GPU", &m_statMode, 2 );
    }
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    ImGui::SeparatorEx( ImGuiSeparatorFlags_Vertical );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();


    Vector<SrcLocZonesSlim> srcloc;

    if( m_statMode == 0 )
    {
        if( !m_worker.AreSourceLocationZonesReady() )
        {
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::PopStyleVar();
            ImGui::TextWrapped( "Please wait, computing data..." );
            DrawWaitingDots( s_time );
            ImGui::End();
            return;
        }

        const auto filterActive = m_statisticsFilter.IsActive();
        auto& slz = m_worker.GetSourceLocationZones();
        srcloc.reserve( slz.size() );
        uint32_t slzcnt = 0;
        if( m_statRange.active )
        {
            const auto min = m_statRange.min;
            const auto max = m_statRange.max;
            const auto st = max - min;
            for( auto it = slz.begin(); it != slz.end(); ++it )
            {
                if( it->second.total != 0 && it->second.min <= st )
                {
                    if( !filterActive )
                    {
                        auto cit = m_statCache.find( it->first );
                        if( cit != m_statCache.end() && cit->second.range == m_statRange && cit->second.accumulationMode == m_statAccumulationMode && cit->second.sourceCount == it->second.zones.size() )
                        {
                            if( cit->second.count != 0 )
                            {
                                slzcnt++;
                                srcloc.push_back_no_space_check( SrcLocZonesSlim { it->first, cit->second.count, cit->second.total } );
                            }
                        }
                        else
                        {
                            size_t cnt = 0;
                            int64_t total = 0;
                            for( auto& v : it->second.zones )
                            {
                                auto& z = *v.Zone();
                                const auto start = z.Start();
                                const auto end = z.End();
                                if( start >= min && end <= max )
                                {
                                    const auto zt = end - start;
                                    if( m_statAccumulationMode == AccumulationMode::SelfOnly )
                                    {
                                        total += zt - GetZoneChildTimeFast( z );
                                        cnt++;
                                    }
                                    else if( m_statAccumulationMode == AccumulationMode::AllChildren || !IsZoneReentry( z ) )
                                    {
                                        total += zt;
                                        cnt++;
                                    }
                                }
                            }
                            if( cnt != 0 )
                            {
                                slzcnt++;
                                srcloc.push_back_no_space_check( SrcLocZonesSlim { it->first, cnt, total } );
                            }
                            m_statCache[it->first] = StatisticsCache { RangeSlim { m_statRange.min, m_statRange.max, m_statRange.active }, m_statAccumulationMode, it->second.zones.size(), cnt, total };
                        }
                    }
                    else
                    {
                        slzcnt++;
                        auto& sl = m_worker.GetSourceLocation( it->first );
                        auto name = m_worker.GetString( sl.name.active ? sl.name : sl.function );
                        if( m_statisticsFilter.PassFilter( name ) )
                        {
                            auto cit = m_statCache.find( it->first );
                            if( cit != m_statCache.end() && cit->second.range == m_statRange && cit->second.accumulationMode == m_statAccumulationMode && cit->second.sourceCount == it->second.zones.size() )
                            {
                                if( cit->second.count != 0 )
                                {
                                    srcloc.push_back_no_space_check( SrcLocZonesSlim { it->first, cit->second.count, cit->second.total } );
                                }
                            }
                            else
                            {
                                size_t cnt = 0;
                                int64_t total = 0;
                                for( auto& v : it->second.zones )
                                {
                                    auto& z = *v.Zone();
                                    const auto start = z.Start();
                                    const auto end = z.End();
                                    if( start >= min && end <= max )
                                    {
                                        const auto zt = end - start;
                                        if( m_statAccumulationMode == AccumulationMode::SelfOnly )
                                        {
                                            total += zt - GetZoneChildTimeFast( z );
                                            cnt++;
                                        }
                                        else if( m_statAccumulationMode == AccumulationMode::AllChildren || !IsZoneReentry( z ) )
                                        {
                                            total += zt;
                                            cnt++;
                                        }
                                    }
                                }
                                if( cnt != 0 )
                                {
                                    srcloc.push_back_no_space_check( SrcLocZonesSlim { it->first, cnt, total } );
                                }
                                m_statCache[it->first] = StatisticsCache { RangeSlim { m_statRange.min, m_statRange.max, m_statRange.active }, m_statAccumulationMode, it->second.zones.size(), cnt, total };
                            }
                        }
                    }
                }
            }
        }
        else
        {
            for( auto it = slz.begin(); it != slz.end(); ++it )
            {
                if( it->second.total != 0 )
                {
                    slzcnt++;
                    size_t count;
                    int64_t total;
                    switch( m_statAccumulationMode )
                    {
                    case AccumulationMode::SelfOnly:
                        count = it->second.zones.size();
                        total = it->second.selfTotal;
                        break;
                    case AccumulationMode::AllChildren:
                        count = it->second.zones.size();
                        total = it->second.total;
                        break;
                    case AccumulationMode::NonReentrantChildren:
                        count = it->second.nonReentrantCount;
                        total = it->second.nonReentrantTotal;
                        break;
                    }
                    if( !filterActive )
                    {
                        srcloc.push_back_no_space_check( SrcLocZonesSlim { it->first, count, total } );
                    }
                    else
                    {
                        auto& sl = m_worker.GetSourceLocation( it->first );
                        auto name = m_worker.GetString( sl.name.active ? sl.name : sl.function );
                        if( m_statisticsFilter.PassFilter( name ) )
                        {
                            srcloc.push_back_no_space_check( SrcLocZonesSlim { it->first, count, total } );
                        }
                    }
                }
            }
        }

        TextFocused( "Total zone count:", RealToString( slzcnt ) );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextFocused( "Visible zones:", RealToString( srcloc.size() ) );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        AccumulationModeComboBox();
    }
    else if( m_statMode == 1 )
    {
        ImGui::Checkbox( ICON_FA_STOPWATCH " Show time", &m_statSampleTime );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        if( m_statRange.active )
        {
            ImGui::BeginDisabled();
            m_statAccumulationMode = AccumulationMode::SelfOnly;
            AccumulationModeComboBox();
            ImGui::EndDisabled();
        }
        else
        {
            AccumulationModeComboBox();
        }
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        ImGui::Checkbox( ICON_FA_EYE_SLASH " Hide unknown", &m_statHideUnknown );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        ImGui::Checkbox( ICON_FA_PUZZLE_PIECE " Show all", &m_showAllSymbols );
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
        ImGui::TextUnformatted( "Location:" );
        ImGui::SameLine();
        const char* locationTable = "Entry\0Sample\0Smart\0";
        ImGui::SetNextItemWidth( ImGui::CalcTextSize( "Sample" ).x + ImGui::GetTextLineHeight() * 2 );
        ImGui::Combo( "##location", &m_statSampleLocation, locationTable );
    }
    else
    {
        assert( m_statMode == 2 );
        if( !m_worker.AreGpuSourceLocationZonesReady() )
        {
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::PopStyleVar();
            ImGui::TextWrapped( "Please wait, computing data..." );
            DrawWaitingDots( s_time );
            ImGui::End();
            return;
        }

        const auto filterActive = m_statisticsFilter.IsActive();
        auto& slz = m_worker.GetGpuSourceLocationZones();
        srcloc.reserve( slz.size() );
        uint32_t slzcnt = 0;
        if( m_statRange.active )
        {
            const auto min = m_statRange.min;
            const auto max = m_statRange.max;
            const auto st = max - min;
            for( auto it = slz.begin(); it != slz.end(); ++it )
            {
                if( it->second.total != 0 && it->second.min <= st )
                {
                    if( !filterActive )
                    {
                        auto cit = m_gpuStatCache.find( it->first );
                        if( cit != m_gpuStatCache.end() && cit->second.range == m_statRange && cit->second.accumulationMode == m_statAccumulationMode && cit->second.sourceCount == it->second.zones.size() )
                        {
                            if( cit->second.count != 0 )
                            {
                                slzcnt++;
                                srcloc.push_back_no_space_check( SrcLocZonesSlim { it->first, cit->second.count, cit->second.total } );
                            }
                        }
                        else
                        {
                            size_t cnt = 0;
                            int64_t total = 0;
                            for( auto& v : it->second.zones )
                            {
                                auto& z = *v.Zone();
                                const auto start = z.GpuStart();
                                const auto end = z.GpuEnd();
                                if( start >= min && end <= max )
                                {
                                    const auto zt = end - start;
                                    total += zt;
                                    cnt++;
                                }
                            }
                            if( cnt != 0 )
                            {
                                slzcnt++;
                                srcloc.push_back_no_space_check( SrcLocZonesSlim { it->first, cnt, total } );
                            }
                            m_gpuStatCache[it->first] = StatisticsCache { RangeSlim { m_statRange.min, m_statRange.max, m_statRange.active }, m_statAccumulationMode, it->second.zones.size(), cnt, total };
                        }
                    }
                    else
                    {
                        slzcnt++;
                        auto& sl = m_worker.GetSourceLocation( it->first );
                        auto name = m_worker.GetString( sl.name.active ? sl.name : sl.function );
                        if( m_statisticsFilter.PassFilter( name ) )
                        {
                            auto cit = m_gpuStatCache.find( it->first );
                            if( cit != m_gpuStatCache.end() && cit->second.range == m_statRange && cit->second.accumulationMode == m_statAccumulationMode && cit->second.sourceCount == it->second.zones.size() )
                            {
                                if( cit->second.count != 0 )
                                {
                                    srcloc.push_back_no_space_check( SrcLocZonesSlim { it->first, cit->second.count, cit->second.total } );
                                }
                            }
                            else
                            {
                                size_t cnt = 0;
                                int64_t total = 0;
                                for( auto& v : it->second.zones )
                                {
                                    auto& z = *v.Zone();
                                    const auto start = z.GpuStart();
                                    const auto end = z.GpuEnd();
                                    if( start >= min && end <= max )
                                    {
                                        const auto zt = end - start;
                                        total += zt;
                                        cnt++;
                                    }
                                }
                                if( cnt != 0 )
                                {
                                    srcloc.push_back_no_space_check( SrcLocZonesSlim { it->first, cnt, total } );
                                }
                                m_gpuStatCache[it->first] = StatisticsCache { RangeSlim { m_statRange.min, m_statRange.max, m_statRange.active }, m_statAccumulationMode, it->second.zones.size(), cnt, total };
                            }
                        }
                    }
                }
            }
        }
        else
        {
            for( auto it = slz.begin(); it != slz.end(); ++it )
            {
                if( it->second.total != 0 )
                {
                    slzcnt++;
                    size_t count = it->second.zones.size();
                    int64_t total = it->second.total;
                    if( !filterActive )
                    {
                        srcloc.push_back_no_space_check( SrcLocZonesSlim { it->first, count, total } );
                    }
                    else
                    {
                        auto& sl = m_worker.GetSourceLocation( it->first );
                        auto name = m_worker.GetString( sl.name.active ? sl.name : sl.function );
                        if( m_statisticsFilter.PassFilter( name ) )
                        {
                            srcloc.push_back_no_space_check( SrcLocZonesSlim { it->first, count, total } );
                        }
                    }
                }
            }
        }

        TextFocused( "Total zone count:", RealToString( slzcnt ) );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextFocused( "Visible zones:", RealToString( srcloc.size() ) );
    }

    ImGui::Separator();
    ImGui::AlignTextToFramePadding();
    TextDisabledUnformatted( "Filter results" );
    ImGui::SameLine();
    m_statisticsFilter.Draw( ICON_FA_FILTER "###resultFilter", 200 );
    ImGui::SameLine();
    if( ImGui::Button( ICON_FA_DELETE_LEFT " Clear" ) )
    {
        m_statisticsFilter.Clear();
    }
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    if( m_statMode == 1 )
    {
        TextDisabledUnformatted( "Image name" );
        ImGui::SameLine();
        m_statisticsImageFilter.Draw( ICON_FA_FILTER "###imageFilter", 200 );
        ImGui::SameLine();
        if( ImGui::BeginCombo( "###imageCombo", nullptr, ImGuiComboFlags_NoPreview | ImGuiComboFlags_HeightLarge ) )
        {
            unordered_flat_set<StringIdx, StringIdxHasher, StringIdxComparator> set;
            std::vector<const char*> imgNames;
            for( auto& v : m_worker.GetSymbolMap() )
            {
                auto it = set.find( v.second.imageName );
                if( it == set.end() )
                {
                    set.emplace( v.second.imageName );
                }
            }
            imgNames.reserve( set.size() );
            for( auto& img : set )
            {
                imgNames.emplace_back( m_worker.GetString( img ) );
            }
            std::sort( imgNames.begin(), imgNames.end(), [] ( const auto& lhs, const auto& rhs ) { return strcmp( lhs, rhs ) < 0; } );
            for( auto& img : imgNames )
            {
                bool sel = false;
                if( ImGui::Selectable( img, &sel ) )
                {
                    auto len = std::min<size_t>( 255, strlen( img ) );
                    memcpy( m_statisticsImageFilter.InputBuf, img, len );
                    m_statisticsImageFilter.InputBuf[len] = 0;
                    m_statisticsImageFilter.Build();
                }
            }
            ImGui::EndCombo();
        }
        ImGui::SameLine();
        if( ImGui::Button( ICON_FA_DELETE_LEFT " Clear###image" ) )
        {
            m_statisticsImageFilter.Clear();
        }
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        ImGui::Checkbox( ICON_FA_HAT_WIZARD " Include kernel", &m_statShowKernel );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
    }
    if( m_statMode == 1 && !m_worker.AreSymbolSamplesReady() )
    {
        m_statRange.active = false;
        bool val = false;
        ImGui::PushItemFlag( ImGuiItemFlags_Disabled, true );
        ImGui::PushStyleVar( ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * 0.5f );
        ImGui::Checkbox( "Limit range", &val );
        ImGui::PopItemFlag();
        ImGui::PopStyleVar();
        TooltipIfHovered( "Waiting for background tasks to finish" );
    }
    else
    {
        if( ImGui::Checkbox( "Limit range", &m_statRange.active ) )
        {
            if( m_statRange.active && m_statRange.min == 0 && m_statRange.max == 0 )
            {
                m_statRange.min = m_vd.zvStart;
                m_statRange.max = m_vd.zvEnd;
            }
        }
        if( m_statRange.active )
        {
            ImGui::SameLine();
            TextColoredUnformatted( 0xFF00FFFF, ICON_FA_TRIANGLE_EXCLAMATION );
            ImGui::SameLine();
            ToggleButton( ICON_FA_RULER " Limits", m_showRanges );
        }
    }

    ImGui::Separator();
    ImGui::PopStyleVar();

    int64_t timeRange;
    if( m_statRange.active )
    {
        const auto st = m_statRange.max - m_statRange.min;
        timeRange = st == 0 ? 1 : st;
    }
    else
    {
        timeRange = m_worker.GetLastTime() - m_worker.GetFirstTime();
    }

    if( m_statMode == 0 || m_statMode == 2 )
    {
        if( srcloc.empty() )
        {
            ImGui::TextUnformatted( "No entries to be displayed." );
        }
        else
        {
            ImGui::BeginChild( "##statistics" );
            if( ImGui::BeginTable( "##statistics", 5, ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable | ImGuiTableFlags_Sortable | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY ) )
            {
                ImGui::TableSetupScrollFreeze( 0, 1 );
                ImGui::TableSetupColumn( "Name", ImGuiTableColumnFlags_NoHide );
                ImGui::TableSetupColumn( "Location", ImGuiTableColumnFlags_NoSort );
                ImGui::TableSetupColumn( "Total time", ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_PreferSortDescending | ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
                ImGui::TableSetupColumn( "Counts", ImGuiTableColumnFlags_PreferSortDescending | ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
                ImGui::TableSetupColumn( "MTPC", ImGuiTableColumnFlags_PreferSortDescending | ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
                ImGui::TableHeadersRow();

                const auto& sortspec = *ImGui::TableGetSortSpecs()->Specs;
                switch( sortspec.ColumnIndex )
                {
                case 0:
                    if( sortspec.SortDirection == ImGuiSortDirection_Ascending )
                    {
                        pdqsort_branchless( srcloc.begin(), srcloc.end(), [this]( const auto& lhs, const auto& rhs ) { return strcmp( m_worker.GetZoneName( m_worker.GetSourceLocation( lhs.srcloc ) ), m_worker.GetZoneName( m_worker.GetSourceLocation( rhs.srcloc ) ) ) < 0; } );
                    }
                    else
                    {
                        pdqsort_branchless( srcloc.begin(), srcloc.end(), [this]( const auto& lhs, const auto& rhs ) { return strcmp( m_worker.GetZoneName( m_worker.GetSourceLocation( lhs.srcloc ) ), m_worker.GetZoneName( m_worker.GetSourceLocation( rhs.srcloc ) ) ) > 0; } );
                    }
                    break;
                case 2:
                    if( sortspec.SortDirection == ImGuiSortDirection_Ascending )
                    {
                        pdqsort_branchless( srcloc.begin(), srcloc.end(), []( const auto& lhs, const auto& rhs ) { return lhs.total < rhs.total; } );
                    }
                    else
                    {
                        pdqsort_branchless( srcloc.begin(), srcloc.end(), []( const auto& lhs, const auto& rhs ) { return lhs.total > rhs.total; } );
                    }
                    break;
                case 3:
                    if( sortspec.SortDirection == ImGuiSortDirection_Ascending )
                    {
                        pdqsort_branchless( srcloc.begin(), srcloc.end(), []( const auto& lhs, const auto& rhs ) { return lhs.numZones < rhs.numZones; } );
                    }
                    else
                    {
                        pdqsort_branchless( srcloc.begin(), srcloc.end(), []( const auto& lhs, const auto& rhs ) { return lhs.numZones > rhs.numZones; } );
                    }
                    break;
                case 4:
                    if( sortspec.SortDirection == ImGuiSortDirection_Ascending )
                    {
                        pdqsort_branchless( srcloc.begin(), srcloc.end(), []( const auto& lhs, const auto& rhs ) { return lhs.total / lhs.numZones < rhs.total / rhs.numZones; } );
                    }
                    else
                    {
                        pdqsort_branchless( srcloc.begin(), srcloc.end(), []( const auto& lhs, const auto& rhs ) { return lhs.total / lhs.numZones > rhs.total / rhs.numZones; } );
                    }
                    break;
                default:
                    assert( false );
                    break;
                }

                for( auto& v : srcloc )
                {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();

                    ImGui::PushID( v.srcloc );
                    auto& srcloc = m_worker.GetSourceLocation( v.srcloc );
                    auto name = m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function );
                    SmallColorBox( GetSrcLocColor( srcloc, 0 ) );
                    ImGui::SameLine();
                    if( m_statMode == 0 )
                    {
                        if( ImGui::Selectable( name, m_findZone.show && !m_findZone.match.empty() && m_findZone.match[m_findZone.selMatch] == v.srcloc, ImGuiSelectableFlags_SpanAllColumns ) )
                        {
                            m_findZone.ShowZone( v.srcloc, name );
                        }
                    }
                    else
                    {
                        ImGui::TextUnformatted( name );
                    }
                    ImGui::TableNextColumn();
                    float indentVal = 0.f;
                    if( m_statBuzzAnim.Match( v.srcloc ) )
                    {
                        const auto time = m_statBuzzAnim.Time();
                        indentVal = sin( time * 60.f ) * 10.f * time;
                        ImGui::Indent( indentVal );
                    }
                    const auto file = m_worker.GetString( srcloc.file );

                    TextDisabledUnformatted( LocationToString( file, srcloc.line ) );
                    if( ImGui::IsItemHovered() )
                    {
                        DrawSourceTooltip( file, srcloc.line );
                        if( ImGui::IsItemClicked( 1 ) )
                        {
                            if( SourceFileValid( file, m_worker.GetCaptureTime(), *this, m_worker ) )
                            {
                                ViewSource( file, srcloc.line );
                            }
                            else
                            {
                                m_statBuzzAnim.Enable( v.srcloc, 0.5f );
                            }
                        }
                    }
                    if( indentVal != 0.f )
                    {
                        ImGui::Unindent( indentVal );
                    }
                    ImGui::TableNextColumn();
                    const auto time = v.total;
                    ImGui::TextUnformatted( TimeToString( time ) );
                    ImGui::SameLine();
                    char buf[64];
                    PrintStringPercent( buf, 100. * time / timeRange );
                    TextDisabledUnformatted( buf );
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted( RealToString( v.numZones ) );
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted( TimeToString( time / v.numZones ) );
                    ImGui::PopID();
                }
                ImGui::EndTable();
            }
            ImGui::EndChild();
        }
    }
    else
    {
        assert( m_statMode == 1 );
        const auto& symMap = m_worker.GetSymbolMap();
        const auto& symStat = m_worker.GetSymbolStats();

        Vector<SymList> data;
        if( m_showAllSymbols )
        {
            data.reserve( symMap.size() );
            if( m_statisticsFilter.IsActive() || m_statisticsImageFilter.IsActive() || !m_statShowKernel )
            {
                for( auto& v : symMap )
                {
                    const auto name = m_worker.GetString( v.second.name );
                    const auto image = m_worker.GetString( v.second.imageName );
                    bool pass = ( m_statShowKernel || ( v.first >> 63 ) == 0 ) && m_statisticsFilter.PassFilter( name ) && m_statisticsImageFilter.PassFilter( image );
                    if( !pass && v.second.size.Val() == 0 )
                    {
                        const auto parentAddr = m_worker.GetSymbolForAddress( v.first );
                        if( parentAddr != 0 )
                        {
                            auto pit = symMap.find( parentAddr );
                            if( pit != symMap.end() )
                            {
                                const auto parentName = m_worker.GetString( pit->second.name );
                                pass = ( m_statShowKernel || ( parentAddr >> 63 ) == 0 ) && m_statisticsFilter.PassFilter( parentName ) && m_statisticsImageFilter.PassFilter( image );
                            }
                        }
                    }
                    if( pass )
                    {
                        auto it = symStat.find( v.first );
                        if( it == symStat.end() )
                        {
                            data.push_back_no_space_check( SymList { v.first, 0, 0 } );
                        }
                        else
                        {
                            if( m_statRange.active )
                            {
                                auto samples = m_worker.GetSamplesForSymbol( v.first );
                                if( samples )
                                {
                                    auto it = std::lower_bound( samples->begin(), samples->end(), m_statRange.min, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
                                    if( it != samples->end() )
                                    {
                                        auto end = std::lower_bound( it, samples->end(), m_statRange.max, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
                                        const auto count = uint32_t( end - it );
                                        data.push_back_no_space_check( SymList { v.first, 0, count } );
                                    }
                                    else
                                    {
                                        data.push_back_no_space_check( SymList { v.first, 0, 0 } );
                                    }
                                }
                                else
                                {
                                    data.push_back_no_space_check( SymList { v.first, 0, 0 } );
                                }
                            }
                            else
                            {
                                data.push_back_no_space_check( SymList { v.first, it->second.incl, it->second.excl } );
                            }
                        }
                    }
                }
            }
            else
            {
                for( auto& v : symMap )
                {
                    auto it = symStat.find( v.first );
                    if( it == symStat.end() )
                    {
                        data.push_back_no_space_check( SymList { v.first, 0, 0 } );
                    }
                    else
                    {
                        if( m_statRange.active )
                        {
                            auto samples = m_worker.GetSamplesForSymbol( v.first );
                            if( samples )
                            {
                                auto it = std::lower_bound( samples->begin(), samples->end(), m_statRange.min, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
                                if( it != samples->end() )
                                {
                                    auto end = std::lower_bound( it, samples->end(), m_statRange.max, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
                                    const auto count = uint32_t( end - it );
                                    data.push_back_no_space_check( SymList { v.first, 0, count } );
                                }
                                else
                                {
                                    data.push_back_no_space_check( SymList { v.first, 0, 0 } );
                                }
                            }
                            else
                            {
                                data.push_back_no_space_check( SymList { v.first, 0, 0 } );
                            }
                        }
                        else
                        {
                            data.push_back_no_space_check( SymList { v.first, it->second.incl, it->second.excl } );
                        }
                    }
                }
            }
        }
        else
        {
            data.reserve( symStat.size() );
            if( m_statisticsFilter.IsActive() || m_statisticsImageFilter.IsActive() || !m_statShowKernel )
            {
                for( auto& v : symStat )
                {
                    auto sit = symMap.find( v.first );
                    if( sit != symMap.end() )
                    {
                        const auto name = m_worker.GetString( sit->second.name );
                        const auto image = m_worker.GetString( sit->second.imageName );
                        bool pass = ( m_statShowKernel || ( v.first >> 63 ) == 0 ) && m_statisticsFilter.PassFilter( name ) && m_statisticsImageFilter.PassFilter( image );
                        if( !pass && sit->second.size.Val() == 0 )
                        {
                            const auto parentAddr = m_worker.GetSymbolForAddress( v.first );
                            if( parentAddr != 0 )
                            {
                                auto pit = symMap.find( parentAddr );
                                if( pit != symMap.end() )
                                {
                                    const auto parentName = m_worker.GetString( pit->second.name );
                                    pass = ( m_statShowKernel || ( parentAddr >> 63 ) == 0 ) && m_statisticsFilter.PassFilter( parentName ) && m_statisticsImageFilter.PassFilter( image );
                                }
                            }
                        }
                        if( pass )
                        {
                            if( m_statRange.active )
                            {
                                auto samples = m_worker.GetSamplesForSymbol( v.first );
                                if( samples )
                                {
                                    auto it = std::lower_bound( samples->begin(), samples->end(), m_statRange.min, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
                                    if( it != samples->end() )
                                    {
                                        auto end = std::lower_bound( it, samples->end(), m_statRange.max, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
                                        const auto count = uint32_t( end - it );
                                        data.push_back_no_space_check( SymList { v.first, 0, count } );
                                    }
                                }
                            }
                            else
                            {
                                data.push_back_no_space_check( SymList { v.first, v.second.incl, v.second.excl } );
                            }
                        }
                    }
                }
            }
            else
            {
                if( m_statRange.active )
                {
                    for( auto& v : symStat )
                    {
                        auto samples = m_worker.GetSamplesForSymbol( v.first );
                        if( samples )
                        {
                            auto it = std::lower_bound( samples->begin(), samples->end(), m_statRange.min, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
                            if( it != samples->end() )
                            {
                                auto end = std::lower_bound( it, samples->end(), m_statRange.max, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
                                const auto count = uint32_t( end - it );
                                data.push_back_no_space_check( SymList { v.first, 0, count } );
                            }
                        }
                    }
                }
                else
                {
                    for( auto& v : symStat )
                    {
                        data.push_back_no_space_check( SymList { v.first, v.second.incl, v.second.excl } );
                    }
                }
            }
        }

        DrawSamplesStatistics( data, timeRange, m_statAccumulationMode );
    }
#endif
    ImGui::End();
}

}
