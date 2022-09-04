#include "TracyImGui.hpp"
#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracyView.hpp"

namespace tracy
{

extern double s_time;

void View::DrawNotificationArea()
{
    if( m_sendQueueWarning.enabled )
    {
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 0, 0.5, 1, 1 ), ICON_FA_SATELLITE_DISH );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted( "The client is slow to answer queries." );
            ImGui::TextUnformatted( "" );
            ImGui::TextWrapped( "Such behavior is typically caused by the symbol resolution performed client-side. If this is a problem, you may try the following options:" );
            ImGui::BulletText( "Disable inline-symbol resolution with TRACY_NO_CALLSTACK_INLINES" );
            ImGui::BulletText( "Disable call stack sampling with TRACY_NO_SAMPLING" );
            ImGui::BulletText( "Change sampling frequency with TRACY_SAMPLING_HZ" );
            ImGui::BulletText( "Disable symbol resolution altogether with TRACY_NO_CALLSTACK" );
            ImGui::TextWrapped( "For more information, please refer to the manual." );
            ImGui::EndTooltip();
            if( IsMouseClicked( 0 ) ) m_sendQueueWarning.enabled = false;
        }
    }
    auto& io = ImGui::GetIO();
    const auto ty = ImGui::GetTextLineHeight();
    if( m_worker.IsConnected() )
    {
        size_t sqs;
        {
            std::shared_lock<std::shared_mutex> lock( m_worker.GetMbpsDataLock() );
            sqs = m_worker.GetSendQueueSize();
        }
        if( sqs != 0 )
        {
            ImGui::SameLine();
            TextColoredUnformatted( ImVec4( 1, 0, 0, 1 ), ICON_FA_SATELLITE_DISH );
            if( ImGui::IsItemHovered() )
            {
                ImGui::BeginTooltip();
                TextFocused( "Query backlog:", RealToString( sqs ) );
                ImGui::EndTooltip();
            }
        }
        else
        {
            const auto sif = m_worker.GetSendInFlight();
            if( sif != 0 )
            {
                ImGui::SameLine();
                TextColoredUnformatted( ImVec4( 1, 0.75f, 0, 1 ), ICON_FA_SATELLITE_DISH );
                if( ImGui::IsItemHovered() )
                {
                    ImGui::BeginTooltip();
                    TextFocused( "Queries in flight:", RealToString( sif ) );
                    ImGui::EndTooltip();
                }
            }
        }
    }
    auto& crash = m_worker.GetCrashEvent();
    if( crash.thread != 0 )
    {
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 1, 0, 0, 1 ), ICON_FA_SKULL );
        if( ImGui::IsItemHovered() )
        {
            CrashTooltip();
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
    if( m_worker.AreSamplesInconsistent() )
    {
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 1, 0.5, 0, 1 ), ICON_FA_EYE_DROPPER );
        TooltipIfHovered( "Sampling data and ghost zones may be displayed wrongly due to data inconsistency. Save and reload the trace to fix this." );
    }
    if( m_vd.drawEmptyLabels )
    {
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 1, 0.5, 0, 1 ), ICON_FA_EXPAND );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted( "Displaying empty labels." );
            ImGui::EndTooltip();
            if( IsMouseClicked( 0 ) ) m_vd.drawEmptyLabels = false;
        }
    }
    if( !m_vd.drawContextSwitches )
    {
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 1, 0.5, 0, 1 ), ICON_FA_PERSON_HIKING );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted( "Context switches are hidden." );
            ImGui::EndTooltip();
            if( IsMouseClicked( 0 ) ) m_vd.drawContextSwitches = true;
        }
    }
    if( !m_vd.drawCpuData )
    {
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 1, 0.5, 0, 1 ), ICON_FA_SLIDERS );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted( "CPU data is hidden." );
            ImGui::EndTooltip();
            if( IsMouseClicked( 0 ) ) m_vd.drawCpuData = true;
        }
    }
    if( !m_vd.drawGpuZones )
    {
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 1, 0.5, 0, 1 ), ICON_FA_EYE );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted( "GPU zones are hidden." );
            ImGui::EndTooltip();
            if( IsMouseClicked( 0 ) ) m_vd.drawGpuZones = true;
        }
    }
    if( !m_vd.drawZones )
    {
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 1, 0.5, 0, 1 ), ICON_FA_MICROCHIP );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted( "CPU zones are hidden." );
            ImGui::EndTooltip();
            if( IsMouseClicked( 0 ) ) m_vd.drawZones = true;
        }
    }
#ifndef TRACY_NO_STATISTICS
    if( !m_vd.ghostZones )
    {
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 1, 0.5, 0, 1 ), ICON_FA_GHOST );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted( "Ghost zones are hidden." );
            ImGui::EndTooltip();
            if( IsMouseClicked( 0 ) ) m_vd.ghostZones = true;
        }
    }
#endif
    if( !m_vd.drawLocks )
    {
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 1, 0.5, 0, 1 ), ICON_FA_LOCK );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted( "Locks are hidden." );
            ImGui::EndTooltip();
            if( IsMouseClicked( 0 ) ) m_vd.drawLocks = true;
        }
    }
    if( !m_vd.drawPlots )
    {
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 1, 0.5, 0, 1 ), ICON_FA_SIGNATURE );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted( "Plots are hidden." );
            ImGui::EndTooltip();
            if( IsMouseClicked( 0 ) ) m_vd.drawPlots = true;
        }
    }
    {
        bool hidden = false;
        for( auto& v : m_visMap )
        {
            if( !v.second )
            {
                hidden = true;
                break;
            }
        }
        if( !hidden )
        {
            for( auto& v : m_tc.GetItemMap() )
            {
                if( !v.second->IsVisible() )
                {
                    hidden = true;
                    break;
                }
            }
        }

        if( hidden )
        {
            ImGui::SameLine();
            TextColoredUnformatted( ImVec4( 1, 0.5, 0, 1 ), ICON_FA_EYE_LOW_VISION );
            if( ImGui::IsItemHovered() )
            {
                ImGui::BeginTooltip();
                ImGui::TextUnformatted( "Some timeline entries are hidden." );
                ImGui::EndTooltip();
                if( IsMouseClicked( 0 ) ) m_showOptions = true;
            }
        }
    }
    if( !m_worker.IsBackgroundDone() )
    {
        ImGui::SameLine();
        TextDisabledUnformatted( ICON_FA_LIST_CHECK );
        ImGui::SameLine();
        const auto pos = ImGui::GetCursorPos();
        ImGui::TextUnformatted( "  " );
        ImGui::GetWindowDrawList()->AddCircleFilled( pos + ImVec2( 0, ty * 0.75f ), ty * ( 0.2f + ( sin( s_time * 8 ) + 1 ) * 0.125f ), 0xFF888888, 10 );
        auto rmin = ImGui::GetItemRectMin();
        rmin.x -= ty * 0.5f;
        const auto rmax = ImGui::GetItemRectMax();
        if( ImGui::IsMouseHoveringRect( rmin, rmax ) )
        {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted( "Processing background tasks" );
            ImGui::EndTooltip();
        }
    }
    if( m_saveThreadState.load( std::memory_order_relaxed ) == SaveThreadState::Saving )
    {
        ImGui::SameLine();
        ImGui::TextUnformatted( ICON_FA_FLOPPY_DISK " Saving trace..." );
        m_notificationTime = 0;
    }
    else if( m_notificationTime > 0 )
    {
        m_notificationTime -= std::min( io.DeltaTime, 0.25f );
        ImGui::SameLine();
        TextDisabledUnformatted( m_notificationText.c_str() );
    }

    ImGui::PushFont( m_smallFont );
    const auto wpos = ImGui::GetWindowPos();
    const auto w = ImGui::GetContentRegionAvail().x;
    const auto fps = RealToString( int( io.Framerate + 0.5f ) );
    const auto fpssz = ImGui::CalcTextSize( fps ).x;
    ImGui::GetWindowDrawList()->AddText( wpos + ImVec2( w-fpssz, 0 ), 0x88FFFFFF, fps );
    ImGui::PopFont();
}

}
