#include <inttypes.h>
#include <random>

#include "TracyFilesystem.hpp"
#include "TracyImGui.hpp"
#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracyTimelineItemGpu.hpp"
#include "TracyUtility.hpp"
#include "TracyView.hpp"

namespace tracy
{

void View::DrawOptions()
{
    ImGui::Begin( "Options", &m_showOptions, ImGuiWindowFlags_AlwaysAutoResize );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }

    const auto scale = GetScale();
    bool val = m_vd.drawEmptyLabels;
    ImGui::Checkbox( ICON_FA_EXPAND " Draw empty labels", &val );
    m_vd.drawEmptyLabels = val;
    val = m_vd.drawFrameTargets;
    ImGui::Checkbox( ICON_FA_FLAG_CHECKERED " Draw frame targets", &val );
    m_vd.drawFrameTargets = val;
    ImGui::Indent();
    int tmp = m_vd.frameTarget;
    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
    ImGui::SetNextItemWidth( 90 * scale );
    if( ImGui::InputInt( "Target FPS", &tmp ) )
    {
        if( tmp < 1 ) tmp = 1;
        m_vd.frameTarget = tmp;
    }
    ImGui::SameLine();
    TextDisabledUnformatted( TimeToString( 1000*1000*1000 / tmp ) );
    ImGui::PopStyleVar();
    ImGui::PushFont( m_smallFont );
    SmallColorBox( 0xFF2222DD );
    ImGui::SameLine( 0, 0 );
    ImGui::Text( "  <  %i  <  ", tmp / 2 );
    ImGui::SameLine( 0, 0 );
    SmallColorBox( 0xFF22DDDD );
    ImGui::SameLine( 0, 0 );
    ImGui::Text( "  <  %i  <  ", tmp );
    ImGui::SameLine( 0, 0 );
    SmallColorBox( 0xFF22DD22 );
    ImGui::SameLine( 0, 0 );
    ImGui::Text( "  <  %i  <  ", tmp * 2 );
    ImGui::SameLine( 0, 0 );
    SmallColorBox( 0xFFDD9900 );
    ImGui::PopFont();
    ImGui::Unindent();
    if( m_worker.HasContextSwitches() )
    {
        ImGui::Separator();
        val = m_vd.drawContextSwitches;
        ImGui::Checkbox( ICON_FA_PERSON_HIKING " Draw context switches", &val );
        m_vd.drawContextSwitches = val;
        ImGui::Indent();
        val = m_vd.darkenContextSwitches;
        SmallCheckbox( ICON_FA_MOON " Darken inactive threads", &val );
        m_vd.darkenContextSwitches = val;
        ImGui::Unindent();
        val = m_vd.drawCpuData;
        ImGui::Checkbox( ICON_FA_SLIDERS " Draw CPU data", &val );
        m_vd.drawCpuData = val;
        ImGui::Indent();
        val = m_vd.drawCpuUsageGraph;
        SmallCheckbox( ICON_FA_SIGNATURE " Draw CPU usage graph", &val );
        m_vd.drawCpuUsageGraph = val;
        ImGui::Unindent();
    }

    if( m_worker.GetCallstackSampleCount() != 0 )
    {
        val = m_vd.drawSamples;
        ImGui::Checkbox( ICON_FA_EYE_DROPPER " Draw stack samples", &val );
        m_vd.drawSamples = val;
    }

    const auto& gpuData = m_worker.GetGpuData();
    if( !gpuData.empty() )
    {
        ImGui::Separator();
        val = m_vd.drawGpuZones;
        ImGui::Checkbox( ICON_FA_EYE " Draw GPU zones", &val );
        m_vd.drawGpuZones = val;
        const auto expand = ImGui::TreeNode( "GPU zones" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%zu)", gpuData.size() );
        if( expand )
        {
            for( size_t i=0; i<gpuData.size(); i++ )
            {
                const auto& timeline = gpuData[i]->threadData.begin()->second.timeline;
                m_tc.GetItem( gpuData[i] ).VisibilityCheckbox();
                ImGui::SameLine();
                if( gpuData[i]->threadData.size() == 1 )
                {
                    ImGui::TextDisabled( "%s top level zones", RealToString( timeline.size() ) );
                }
                else
                {
                    ImGui::TextDisabled( "%s threads", RealToString( gpuData[i]->threadData.size() ) );
                }
                if( gpuData[i]->name.Active() )
                {
                    char buf[64];
                    auto& item = (TimelineItemGpu&)( m_tc.GetItem( gpuData[i] ) );
                    sprintf( buf, "%s context %i", GpuContextNames[(int)gpuData[i]->type], item.GetIdx() );
                    ImGui::PushFont( m_smallFont );
                    ImGui::TextUnformatted( buf );
                    ImGui::PopFont();
                }
                if( !gpuData[i]->hasCalibration )
                {
                    ImGui::TreePush( (void*)nullptr );
                    auto& drift = GpuDrift( gpuData[i] );
                    ImGui::SetNextItemWidth( 120 * scale );
                    ImGui::PushID( i );
                    ImGui::InputInt( "Drift (ns/s)", &drift );
                    ImGui::PopID();
                    if( timeline.size() > 1 )
                    {
                        ImGui::SameLine();
                        if( ImGui::Button( ICON_FA_ROBOT " Auto" ) )
                        {
                            size_t lastidx = 0;
                            if( timeline.is_magic() )
                            {
                                auto& tl = *((Vector<GpuEvent>*)&timeline);
                                for( size_t j=tl.size()-1; j > 0; j-- )
                                {
                                    if( tl[j].GpuEnd() >= 0 )
                                    {
                                        lastidx = j;
                                        break;
                                    }
                                }
                            }
                            else
                            {
                                for( size_t j=timeline.size()-1; j > 0; j-- )
                                {
                                    if( timeline[j]->GpuEnd() >= 0 )
                                    {
                                        lastidx = j;
                                        break;
                                    }
                                }
                            }

                            enum { NumSlopes = 10000 };
                            std::random_device rd;
                            std::default_random_engine gen( rd() );
                            std::uniform_int_distribution<size_t> dist( 0, lastidx - 1 );
                            float slopes[NumSlopes];
                            size_t idx = 0;
                            if( timeline.is_magic() )
                            {
                                auto& tl = *((Vector<GpuEvent>*)&timeline);
                                do
                                {
                                    const auto p0 = dist( gen );
                                    const auto p1 = dist( gen );
                                    if( p0 != p1 )
                                    {
                                        slopes[idx++] = float( 1.0 - double( tl[p1].GpuStart() - tl[p0].GpuStart() ) / double( tl[p1].CpuStart() - tl[p0].CpuStart() ) );
                                    }
                                }
                                while( idx < NumSlopes );
                            }
                            else
                            {
                                do
                                {
                                    const auto p0 = dist( gen );
                                    const auto p1 = dist( gen );
                                    if( p0 != p1 )
                                    {
                                        slopes[idx++] = float( 1.0 - double( timeline[p1]->GpuStart() - timeline[p0]->GpuStart() ) / double( timeline[p1]->CpuStart() - timeline[p0]->CpuStart() ) );
                                    }
                                }
                                while( idx < NumSlopes );
                            }
                            std::sort( slopes, slopes+NumSlopes );
                            drift = int( 1000000000 * -slopes[NumSlopes/2] );
                        }
                    }
                    ImGui::TreePop();
                }
            }
            ImGui::TreePop();
        }
    }

    ImGui::Separator();
    val = m_vd.drawZones;
    ImGui::Checkbox( ICON_FA_MICROCHIP " Draw CPU zones", &val );
    ImGui::Indent();
    m_vd.drawZones = val;

#ifndef TRACY_NO_STATISTICS
    if( m_worker.AreGhostZonesReady() && m_worker.GetGhostZonesCount() != 0 )
    {
        val = m_vd.ghostZones;
        SmallCheckbox( ICON_FA_GHOST " Draw ghost zones", &val );
        m_vd.ghostZones = val;
    }
#endif

    int ival = m_vd.dynamicColors;
    ImGui::TextUnformatted( ICON_FA_PALETTE " Zone colors" );
    ImGui::SameLine();
    bool forceColors = m_vd.forceColors;
    if( SmallCheckbox( "Ignore custom", &forceColors ) ) m_vd.forceColors = forceColors;
    ImGui::Indent();
    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
    ImGui::RadioButton( "Static", &ival, 0 );
    ImGui::RadioButton( "Thread dynamic", &ival, 1 );
    ImGui::RadioButton( "Source location dynamic", &ival, 2 );
    ImGui::PopStyleVar();
    ImGui::Unindent();
    m_vd.dynamicColors = ival;
    ival = (int)m_vd.shortenName;
    ImGui::TextUnformatted( ICON_FA_RULER_HORIZONTAL " Zone name shortening" );
    ImGui::Indent();
    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
    ImGui::RadioButton( "Disabled", &ival, (uint8_t)ShortenName::Never );
    ImGui::RadioButton( "Minimal length", &ival, (uint8_t)ShortenName::Always );
    ImGui::RadioButton( "Only normalize", &ival, (uint8_t)ShortenName::OnlyNormalize );
    ImGui::RadioButton( "As needed", &ival, (uint8_t)ShortenName::NoSpace );
    ImGui::RadioButton( "As needed + normalize", &ival, (uint8_t)ShortenName::NoSpaceAndNormalize );
    ImGui::PopStyleVar();
    ImGui::Unindent();
    m_vd.shortenName = (ShortenName)ival;
    ImGui::Unindent();

    if( !m_worker.GetLockMap().empty() )
    {
        size_t lockCnt = 0;
        size_t singleCnt = 0;
        size_t multiCntCont = 0;
        size_t multiCntUncont = 0;
        for( const auto& l : m_worker.GetLockMap() )
        {
            if( l.second->valid && !l.second->timeline.empty() )
            {
                lockCnt++;
                if( l.second->threadList.size() == 1 )
                {
                    singleCnt++;
                }
                else if( l.second->isContended )
                {
                    multiCntCont++;
                }
                else
                {
                    multiCntUncont++;
                }
            }
        }

        ImGui::Separator();
        val = m_vd.drawLocks;
        ImGui::Checkbox( ICON_FA_LOCK " Draw locks", &val );
        m_vd.drawLocks = val;
        ImGui::SameLine();
        val = m_vd.onlyContendedLocks;
        ImGui::Checkbox( "Only contended", &val );
        m_vd.onlyContendedLocks = val;
        const auto expand = ImGui::TreeNode( "Locks" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%zu)", lockCnt );
        TooltipIfHovered( "Locks with no recorded events are counted, but not listed." );
        if( expand )
        {
            ImGui::SameLine();
            if( ImGui::SmallButton( "Select all" ) )
            {
                for( const auto& l : m_worker.GetLockMap() )
                {
                    Vis( l.second ) = true;
                }
            }
            ImGui::SameLine();
            if( ImGui::SmallButton( "Unselect all" ) )
            {
                for( const auto& l : m_worker.GetLockMap() )
                {
                    Vis( l.second ) = false;
                }
            }
            ImGui::SameLine();
            DrawHelpMarker( "Right click on lock name to open lock information window." );

            const bool multiExpand = ImGui::TreeNodeEx( "Contended locks present in multiple threads", ImGuiTreeNodeFlags_DefaultOpen );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%zu)", multiCntCont );
            if( multiExpand )
            {
                ImGui::SameLine();
                if( ImGui::SmallButton( "Select all" ) )
                {
                    for( const auto& l : m_worker.GetLockMap() )
                    {
                        if( l.second->threadList.size() != 1 && l.second->isContended ) Vis( l.second ) = true;
                    }
                }
                ImGui::SameLine();
                if( ImGui::SmallButton( "Unselect all" ) )
                {
                    for( const auto& l : m_worker.GetLockMap() )
                    {
                        if( l.second->threadList.size() != 1 && l.second->isContended ) Vis( l.second ) = false;
                    }
                }

                for( const auto& l : m_worker.GetLockMap() )
                {
                    if( l.second->valid && !l.second->timeline.empty() && l.second->threadList.size() != 1 && l.second->isContended )
                    {
                        auto& sl = m_worker.GetSourceLocation( l.second->srcloc );
                        auto fileName = m_worker.GetString( sl.file );

                        char buf[1024];
                        if( l.second->customName.Active() )
                        {
                            sprintf( buf, "%" PRIu32 ": %s", l.first, m_worker.GetString( l.second->customName ) );
                        }
                        else
                        {
                            sprintf( buf, "%" PRIu32 ": %s", l.first, m_worker.GetString( m_worker.GetSourceLocation( l.second->srcloc ).function ) );
                        }
                        SmallCheckbox( buf, &Vis( l.second ) );
                        if( ImGui::IsItemHovered() )
                        {
                            m_lockHoverHighlight = l.first;

                            if( ImGui::IsItemClicked( 1 ) )
                            {
                                m_lockInfoWindow = l.first;
                            }
                        }
                        if( m_optionsLockBuzzAnim.Match( l.second->srcloc ) )
                        {
                            const auto time = m_optionsLockBuzzAnim.Time();
                            const auto indentVal = sin( time * 60.f ) * 10.f * time;
                            ImGui::SameLine( 0, ImGui::GetStyle().ItemSpacing.x + indentVal );
                        }
                        else
                        {
                            ImGui::SameLine();
                        }
                        ImGui::TextDisabled( "(%s) %s", RealToString( l.second->timeline.size() ), LocationToString( fileName, sl.line ) );
                        if( ImGui::IsItemHovered() )
                        {
                            DrawSourceTooltip( fileName, sl.line, 1, 1 );
                            if( ImGui::IsItemClicked( 1 ) )
                            {
                                if( SourceFileValid( fileName, m_worker.GetCaptureTime(), *this, m_worker ) )
                                {
                                    ViewSource( fileName, sl.line );
                                }
                                else
                                {
                                    m_optionsLockBuzzAnim.Enable( l.second->srcloc, 0.5f );
                                }
                            }
                        }
                    }
                }
                ImGui::TreePop();
            }
            const bool multiUncontExpand = ImGui::TreeNodeEx( "Uncontended locks present in multiple threads", 0 );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%zu)", multiCntUncont );
            if( multiUncontExpand )
            {
                ImGui::SameLine();
                if( ImGui::SmallButton( "Select all" ) )
                {
                    for( const auto& l : m_worker.GetLockMap() )
                    {
                        if( l.second->threadList.size() != 1 && !l.second->isContended ) Vis( l.second ) = true;
                    }
                }
                ImGui::SameLine();
                if( ImGui::SmallButton( "Unselect all" ) )
                {
                    for( const auto& l : m_worker.GetLockMap() )
                    {
                        if( l.second->threadList.size() != 1 && !l.second->isContended ) Vis( l.second ) = false;
                    }
                }

                for( const auto& l : m_worker.GetLockMap() )
                {
                    if( l.second->valid && !l.second->timeline.empty() && l.second->threadList.size() != 1 && !l.second->isContended )
                    {
                        auto& sl = m_worker.GetSourceLocation( l.second->srcloc );
                        auto fileName = m_worker.GetString( sl.file );

                        char buf[1024];
                        if( l.second->customName.Active() )
                        {
                            sprintf( buf, "%" PRIu32 ": %s", l.first, m_worker.GetString( l.second->customName ) );
                        }
                        else
                        {
                            sprintf( buf, "%" PRIu32 ": %s", l.first, m_worker.GetString( m_worker.GetSourceLocation( l.second->srcloc ).function ) );
                        }
                        SmallCheckbox( buf, &Vis( l.second ) );
                        if( ImGui::IsItemHovered() )
                        {
                            m_lockHoverHighlight = l.first;

                            if( ImGui::IsItemClicked( 1 ) )
                            {
                                m_lockInfoWindow = l.first;
                            }
                        }
                        if( m_optionsLockBuzzAnim.Match( l.second->srcloc ) )
                        {
                            const auto time = m_optionsLockBuzzAnim.Time();
                            const auto indentVal = sin( time * 60.f ) * 10.f * time;
                            ImGui::SameLine( 0, ImGui::GetStyle().ItemSpacing.x + indentVal );
                        }
                        else
                        {
                            ImGui::SameLine();
                        }
                        ImGui::TextDisabled( "(%s) %s", RealToString( l.second->timeline.size() ), LocationToString( fileName, sl.line ) );
                        if( ImGui::IsItemHovered() )
                        {
                            DrawSourceTooltip( fileName, sl.line, 1, 1 );
                            if( ImGui::IsItemClicked( 1 ) )
                            {
                                if( SourceFileValid( fileName, m_worker.GetCaptureTime(), *this, m_worker ) )
                                {
                                    ViewSource( fileName, sl.line );
                                }
                                else
                                {
                                    m_optionsLockBuzzAnim.Enable( l.second->srcloc, 0.5f );
                                }
                            }
                        }
                    }
                }
                ImGui::TreePop();
            }
            const auto singleExpand = ImGui::TreeNodeEx( "Locks present in a single thread", 0 );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%zu)", singleCnt );
            if( singleExpand )
            {
                ImGui::SameLine();
                if( ImGui::SmallButton( "Select all" ) )
                {
                    for( const auto& l : m_worker.GetLockMap() )
                    {
                        if( l.second->threadList.size() == 1 ) Vis( l.second ) = true;
                    }
                }
                ImGui::SameLine();
                if( ImGui::SmallButton( "Unselect all" ) )
                {
                    for( const auto& l : m_worker.GetLockMap() )
                    {
                        if( l.second->threadList.size() == 1 ) Vis( l.second ) = false;
                    }
                }

                for( const auto& l : m_worker.GetLockMap() )
                {
                    if( l.second->valid && !l.second->timeline.empty() && l.second->threadList.size() == 1 )
                    {
                        auto& sl = m_worker.GetSourceLocation( l.second->srcloc );
                        auto fileName = m_worker.GetString( sl.file );

                        char buf[1024];
                        if( l.second->customName.Active() )
                        {
                            sprintf( buf, "%" PRIu32 ": %s", l.first, m_worker.GetString( l.second->customName ) );
                        }
                        else
                        {
                            sprintf( buf, "%" PRIu32 ": %s", l.first, m_worker.GetString( m_worker.GetSourceLocation( l.second->srcloc ).function ) );
                        }
                        SmallCheckbox( buf, &Vis( l.second ) );
                        if( ImGui::IsItemHovered() )
                        {
                            m_lockHoverHighlight = l.first;

                            if( ImGui::IsItemClicked( 1 ) )
                            {
                                m_lockInfoWindow = l.first;
                            }
                        }
                        if( m_optionsLockBuzzAnim.Match( l.second->srcloc ) )
                        {
                            const auto time = m_optionsLockBuzzAnim.Time();
                            const auto indentVal = sin( time * 60.f ) * 10.f * time;
                            ImGui::SameLine( 0, ImGui::GetStyle().ItemSpacing.x + indentVal );
                        }
                        else
                        {
                            ImGui::SameLine();
                        }
                        ImGui::TextDisabled( "(%s) %s", RealToString( l.second->timeline.size() ), LocationToString( fileName, sl.line ) );
                        if( ImGui::IsItemHovered() )
                        {
                            DrawSourceTooltip( fileName, sl.line, 1, 1 );
                            if( ImGui::IsItemClicked( 1 ) )
                            {
                                if( SourceFileValid( fileName, m_worker.GetCaptureTime(), *this, m_worker ) )
                                {
                                    ViewSource( fileName, sl.line );
                                }
                                else
                                {
                                    m_optionsLockBuzzAnim.Enable( l.second->srcloc, 0.5f );
                                }
                            }
                        }
                    }
                }
                ImGui::TreePop();
            }
            ImGui::TreePop();
        }
    }

    if( !m_worker.GetPlots().empty() )
    {
        ImGui::Separator();
        val = m_vd.drawPlots;
        ImGui::Checkbox( ICON_FA_SIGNATURE " Draw plots", &val );
        m_vd.drawPlots = val;

        ImGui::SameLine();
        int pH = m_vd.plotHeight;
        ImGui::SliderInt("Plot heights", &pH, 30, 200);
        m_vd.plotHeight = pH;

        const auto expand = ImGui::TreeNode( "Plots" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%zu)", m_worker.GetPlots().size() );
        if( expand )
        {
            ImGui::SameLine();
            if( ImGui::SmallButton( "Select all" ) )
            {
                for( const auto& p : m_worker.GetPlots() )
                {
                    m_tc.GetItem( p ).SetVisible( true );
                }
            }
            ImGui::SameLine();
            if( ImGui::SmallButton( "Unselect all" ) )
            {
                for( const auto& p : m_worker.GetPlots() )
                {
                    m_tc.GetItem( p ).SetVisible( false );
                }
            }

            for( const auto& p : m_worker.GetPlots() )
            {
                SmallColorBox( GetPlotColor( *p, m_worker ) );
                ImGui::SameLine();
                m_tc.GetItem( p ).VisibilityCheckbox();
                ImGui::SameLine();
                ImGui::TextDisabled( "%s data points", RealToString( p->data.size() ) );
            }
            ImGui::TreePop();
        }
    }

    ImGui::Separator();
    auto expand = ImGui::TreeNode( ICON_FA_SHUFFLE " Visible threads:" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(%zu)", m_threadOrder.size() );
    if( expand )
    {
        auto& crash = m_worker.GetCrashEvent();

        ImGui::SameLine();
        if( ImGui::SmallButton( "Select all" ) )
        {
            for( const auto& t : m_threadOrder )
            {
                m_tc.GetItem( t ).SetVisible( true );
            }
        }
        ImGui::SameLine();
        if( ImGui::SmallButton( "Unselect all" ) )
        {
            for( const auto& t : m_threadOrder )
            {
                m_tc.GetItem( t ).SetVisible( false );
            }
        }
        ImGui::SameLine();
        if( ImGui::SmallButton( "Sort" ) )
        {
            std::sort( m_threadOrder.begin(), m_threadOrder.end(), [this] ( const auto& lhs, const auto& rhs ) {
                if( lhs->groupHint != rhs->groupHint ) return lhs->groupHint < rhs->groupHint;
                return strcmp( m_worker.GetThreadName( lhs->id ), m_worker.GetThreadName( rhs->id ) ) < 0;
            } );
        }

        const auto wposx = ImGui::GetCursorScreenPos().x;
        m_threadDnd.clear();
        int idx = 0;
        for( const auto& t : m_threadOrder )
        {
            m_threadDnd.push_back( ImGui::GetCursorScreenPos().y );
            ImGui::PushID( idx );
            const auto threadName = m_worker.GetThreadName( t->id );
            const auto threadColor = GetThreadColor( t->id, 0 );
            SmallColorBox( threadColor );
            ImGui::SameLine();
            m_tc.GetItem( t ).VisibilityCheckbox();
            if( ImGui::BeginDragDropSource( ImGuiDragDropFlags_SourceNoHoldToOpenOthers ) )
            {
                ImGui::SetDragDropPayload( "ThreadOrder", &idx, sizeof(int) );
                ImGui::TextUnformatted( ICON_FA_SHUFFLE );
                ImGui::SameLine();
                SmallColorBox( threadColor );
                ImGui::SameLine();
                ImGui::TextUnformatted( threadName );
                ImGui::EndDragDropSource();
            }
            ImGui::PopID();
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s)", RealToString( t->id ) );
            if( crash.thread == t->id )
            {
                ImGui::SameLine();
                TextColoredUnformatted( ImVec4( 1.f, 0.2f, 0.2f, 1.f ), ICON_FA_SKULL );
                if( ImGui::IsItemHovered() )
                {
                    ImGui::BeginTooltip();
                    ImGui::TextUnformatted( "Crashed" );
                    ImGui::EndTooltip();
                    if( IsMouseClicked( 0 ) )
                    {
                        m_showInfo = true;
                    }
                    if( IsMouseClicked( 2 ) )
                    {
                        CenterAtTime( crash.time );
                    }
                }
            }
            if( t->isFiber )
            {
                ImGui::SameLine();
                TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
            }
            ImGui::SameLine();
            ImGui::TextDisabled( "%s top level zones", RealToString( t->timeline.size() ) );
            idx++;
        }
        if( m_threadDnd.size() > 1 )
        {
            const auto w = ImGui::GetContentRegionAvail().x;
            const auto dist = m_threadDnd[1] - m_threadDnd[0];
            const auto half = dist * 0.5f;
            m_threadDnd.push_back( m_threadDnd.back() + dist );

            int target = -1;
            int source;
            for( size_t i=0; i<m_threadDnd.size(); i++ )
            {
                if( ImGui::BeginDragDropTargetCustom( ImRect( wposx, m_threadDnd[i] - half, wposx + w, m_threadDnd[i] + half ), i+1 ) )
                {
                    auto draw = ImGui::GetWindowDrawList();
                    draw->AddLine( ImVec2( wposx, m_threadDnd[i] ), ImVec2( wposx + w, m_threadDnd[i] ), ImGui::GetColorU32(ImGuiCol_DragDropTarget), 2.f );
                    if( auto payload = ImGui::AcceptDragDropPayload( "ThreadOrder", ImGuiDragDropFlags_AcceptNoDrawDefaultRect ) )
                    {
                        target = (int)i;
                        source = *(int*)payload->Data;
                    }
                    ImGui::EndDragDropTarget();
                }
            }
            if( target >= 0 && target != source )
            {
                const auto srcval = m_threadOrder[source];
                if( target < source )
                {
                    assert( source < (int)m_threadOrder.size() );
                    m_threadOrder.erase( m_threadOrder.begin() + source );
                    m_threadOrder.insert( m_threadOrder.begin() + target, srcval );
                }
                else
                {
                    assert( target <= (int)m_threadOrder.size() );
                    m_threadOrder.insert( m_threadOrder.begin() + target, srcval );
                    m_threadOrder.erase( m_threadOrder.begin() + source );
                }
            }
        }
        ImGui::TreePop();
    }

    if( m_worker.AreFramesUsed() )
    {
        ImGui::Separator();
        expand = ImGui::TreeNode( ICON_FA_IMAGES " Visible frame sets:" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%zu)", m_worker.GetFrames().size() );
        if( expand )
        {
            ImGui::SameLine();
            if( ImGui::SmallButton( "Select all" ) )
            {
                for( const auto& fd : m_worker.GetFrames() )
                {
                    Vis( fd ) = true;
                }
            }
            ImGui::SameLine();
            if( ImGui::SmallButton( "Unselect all" ) )
            {
                for( const auto& fd : m_worker.GetFrames() )
                {
                    Vis( fd ) = false;
                }
            }

            int idx = 0;
            for( const auto& fd : m_worker.GetFrames() )
            {
                ImGui::PushID( idx++ );
                SmallCheckbox( GetFrameSetName( *fd ), &Vis( fd ) );
                ImGui::PopID();
                ImGui::SameLine();
                ImGui::TextDisabled( "%s %sframes", RealToString( fd->frames.size() ), fd->continuous ? "" : "discontinuous " );
            }
            ImGui::TreePop();
        }
    }
    ImGui::End();
}

}
