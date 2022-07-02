#ifndef TRACY_NO_FILESELECTOR
#  include "../nfd/nfd.h"
#endif

#include "TracyPrint.hpp"
#include "TracyView.hpp"

namespace tracy
{

bool View::DrawConnection()
{
    const auto scale = GetScale();
    const auto ty = ImGui::GetTextLineHeight();
    const auto cs = ty * 0.9f;
    const auto isConnected = m_worker.IsConnected();

    {
        std::shared_lock<std::shared_mutex> lock( m_worker.GetMbpsDataLock() );
        TextFocused( isConnected ? "Connected to:" : "Disconnected:", m_worker.GetAddr().c_str() );
        const auto& mbpsVector = m_worker.GetMbpsData();
        const auto mbps = mbpsVector.back();
        char buf[64];
        if( mbps < 0.1f )
        {
            sprintf( buf, "%6.2f Kbps", mbps * 1000.f );
        }
        else
        {
            sprintf( buf, "%6.2f Mbps", mbps );
        }
        ImGui::Dummy( ImVec2( cs, 0 ) );
        ImGui::SameLine();
        ImGui::PlotLines( buf, mbpsVector.data(), mbpsVector.size(), 0, nullptr, 0, std::numeric_limits<float>::max(), ImVec2( 150 * scale, 0 ) );
        TextDisabledUnformatted( "Ratio" );
        ImGui::SameLine();
        ImGui::Text( "%.1f%%", m_worker.GetCompRatio() * 100.f );
        ImGui::SameLine();
        TextDisabledUnformatted( "Real:" );
        ImGui::SameLine();
        ImGui::Text( "%6.2f Mbps", mbps / m_worker.GetCompRatio() );
        TextFocused( "Data transferred:", MemSizeToString( m_worker.GetDataTransferred() ) );
        TextFocused( "Query backlog:", RealToString( m_worker.GetSendQueueSize() ) );
    }

    const auto wpos = ImGui::GetWindowPos() + ImGui::GetWindowContentRegionMin();
    ImGui::GetWindowDrawList()->AddCircleFilled( wpos + ImVec2( 1 + cs * 0.5, 3 + ty * 1.75 ), cs * 0.5, isConnected ? 0xFF2222CC : 0xFF444444, 10 );

    {
        std::lock_guard<std::mutex> lock( m_worker.GetDataLock() );
        ImGui::SameLine();
        TextFocused( "+", RealToString( m_worker.GetSendInFlight() ) );
        const auto sz = m_worker.GetFrameCount( *m_frames );
        if( sz > 1 )
        {
            const auto dt = m_worker.GetFrameTime( *m_frames, sz - 2 );
            const auto fps = 1000000000.f / dt;
            TextDisabledUnformatted( "FPS:" );
            ImGui::SameLine();
            ImGui::Text( "%6.1f", fps );
            ImGui::SameLine();
            TextFocused( "Frame time:", TimeToString( dt ) );
        }
    }

    const auto& fis = m_worker.GetFrameImages();
    if( !fis.empty() )
    {
        const auto fiScale = scale * 0.5f;
        const auto& fi = fis.back();
        if( fi != m_frameTextureConnPtr )
        {
            if( !m_frameTextureConn ) m_frameTextureConn = MakeTexture();
            UpdateTexture( m_frameTextureConn, m_worker.UnpackFrameImage( *fi ), fi->w, fi->h );
            m_frameTextureConnPtr = fi;
        }
        ImGui::Separator();
        if( fi->flip )
        {
            ImGui::Image( m_frameTextureConn, ImVec2( fi->w * fiScale, fi->h * fiScale ), ImVec2( 0, 1 ), ImVec2( 1, 0 ) );
        }
        else
        {
            ImGui::Image( m_frameTextureConn, ImVec2( fi->w * fiScale, fi->h * fiScale ) );
        }
    }

    ImGui::Separator();
    if( ImGui::Button( ICON_FA_SAVE " Save trace" ) && m_saveThreadState.load( std::memory_order_relaxed ) == SaveThreadState::Inert )
    {
#ifndef TRACY_NO_FILESELECTOR
        nfdu8filteritem_t filter = { "Tracy Profiler trace file", "tracy" };
        nfdu8char_t* fn;
        auto res = NFD_SaveDialogU8( &fn, &filter, 1, nullptr, nullptr );
        if( res == NFD_OKAY )
#else
        const char* fn = "trace.tracy";
#endif
        {
            const auto sz = strlen( fn );
            if( sz < 7 || memcmp( fn + sz - 6, ".tracy", 6 ) != 0 )
            {
                char tmp[1024];
                sprintf( tmp, "%s.tracy", fn );
                m_filenameStaging = tmp;
            }
            else
            {
                m_filenameStaging = fn;
            }
#ifndef TRACY_NO_FILESELECTOR
            NFD_FreePathU8( fn );
#endif
        }
    }

    ImGui::SameLine( 0, 2 * ty );
    const char* stopStr = ICON_FA_PLUG " Stop";
    std::lock_guard<std::mutex> lock( m_worker.GetDataLock() );
    if( !m_disconnectIssued && m_worker.IsConnected() )
    {
        if( ImGui::Button( stopStr ) )
        {
            m_worker.Disconnect();
            m_disconnectIssued = true;
        }
    }
    else
    {
        ImGui::BeginDisabled();
        ImGui::Button( stopStr );
        ImGui::EndDisabled();
    }

    ImGui::SameLine();
    if( ImGui::Button( ICON_FA_EXCLAMATION_TRIANGLE " Discard" ) )
    {
        ImGui::OpenPopup( "Confirm trace discard" );
    }

    if( ImGui::BeginPopupModal( "Confirm trace discard", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
    {
        ImGui::PushFont( m_bigFont );
        TextCentered( ICON_FA_EXCLAMATION_TRIANGLE );
        ImGui::PopFont();
        ImGui::TextUnformatted( "All unsaved profiling data will be lost!" );
        ImGui::TextUnformatted( "Are you sure you want to proceed?" );
        ImGui::Separator();
        if( ImGui::Button( "Yes" ) )
        {
            ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
            return false;
        }
        ImGui::SameLine();
        if( ImGui::Button( "Reconnect" ) )
        {
            ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
            m_reconnectRequested = true;
            return false;
        }
        ImGui::SameLine( 0, ty * 2 );
        if( ImGui::Button( "No", ImVec2( ty * 6, 0 ) ) )
        {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    if( m_worker.IsConnected() )
    {
        const auto& params = m_worker.GetParameters();
        if( !params.empty() )
        {
            ImGui::Separator();
            if( ImGui::TreeNode( "Trace parameters" ) )
            {
                if( ImGui::BeginTable( "##traceparams", 2, ImGuiTableFlags_Borders ) )
                {
                    ImGui::TableSetupColumn( "Name" );
                    ImGui::TableSetupColumn( "Value", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
                    ImGui::TableHeadersRow();
                    size_t idx = 0;
                    for( auto& p : params )
                    {
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn();
                        ImGui::TextUnformatted( m_worker.GetString( p.name ) );
                        ImGui::TableNextColumn();
                        ImGui::PushID( idx );
                        if( p.isBool )
                        {
                            bool val = p.val;
                            if( ImGui::Checkbox( "", &val ) )
                            {
                                m_worker.SetParameter( idx, int32_t( val ) );
                            }
                        }
                        else
                        {
                            auto val = int( p.val );
                            if( ImGui::InputInt( "", &val, 1, 100, ImGuiInputTextFlags_EnterReturnsTrue ) )
                            {
                                m_worker.SetParameter( idx, int32_t( val ) );
                            }
                        }
                        ImGui::PopID();
                        idx++;
                    }
                    ImGui::EndTable();
                }
                ImGui::TreePop();
            }
        }
    }

    return true;
}

}
