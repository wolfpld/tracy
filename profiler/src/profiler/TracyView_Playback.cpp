#include "TracyImGui.hpp"
#include "TracyPrint.hpp"
#include "TracyTexture.hpp"
#include "TracyView.hpp"

namespace tracy
{

void View::SetPlaybackFrame( uint32_t idx )
{
    const auto frameSet = m_worker.GetFramesBase();
    const auto& frameImages = m_worker.GetFrameImages();
    assert( idx < frameImages.size() );

    m_playback.frame = idx;

    if( idx == frameImages.size() - 1 )
    {
        m_playback.pause = true;
    }
    else
    {
        const auto t0 = m_worker.GetFrameBegin( *frameSet, frameImages[idx]->frameRef );
        const auto t1 = m_worker.GetFrameBegin( *frameSet, frameImages[idx+1]->frameRef );
        m_playback.timeLeft = ( t1 - t0 ) / 1000000000.f;
    }
}

static const char* PlaybackWindowButtons[] = {
    ICON_FA_PLAY " Play",
    ICON_FA_PAUSE " Pause",
};

enum { PlaybackWindowButtonsCount = sizeof( PlaybackWindowButtons ) / sizeof( *PlaybackWindowButtons ) };

void View::DrawPlayback()
{
    ImGui::Begin( "Playback", &m_showPlayback, ImGuiWindowFlags_AlwaysAutoResize );
    if( !m_showPlayback ) m_playback.pause = true;
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }

    const auto scale = GetScale();
    const auto frameSet = m_worker.GetFramesBase();
    const auto& frameImages = m_worker.GetFrameImages();
    const auto& fi = frameImages[m_playback.frame];
    const auto ficnt = m_worker.GetFrameImageCount();

    const auto tstart = m_worker.GetFrameBegin( *frameSet, fi->frameRef );

    if( !m_playback.texture )
    {
        m_playback.texture = MakeTexture();
    }
    if( m_playback.currFrame != m_playback.frame )
    {
        m_playback.currFrame = m_playback.frame;
        UpdateTexture( m_playback.texture, m_worker.UnpackFrameImage( *fi ), fi->w, fi->h );

        if( m_playback.sync )
        {
            const auto end = m_worker.GetFrameEnd( *frameSet, fi->frameRef );
            m_zoomAnim.active = false;
            m_vd.zvStart = tstart;
            m_vd.zvEnd = end;
            m_viewMode = ViewMode::Paused;
            m_viewModeHeuristicTry = false;
        }
    }

    if( !m_playback.pause )
    {
        Achieve( "frameImages" );

        auto time = ImGui::GetIO().DeltaTime * m_playback.speed;
        while( !m_playback.pause && time > 0 )
        {
            const auto dt = std::min( time, m_playback.timeLeft );
            time -= dt;
            m_playback.timeLeft -= dt;
            if( m_playback.timeLeft == 0 )
            {
                SetPlaybackFrame( m_playback.frame + 1 );
            }
        }
    }

    if( m_playback.zoom )
    {
        if( fi->flip )
        {
            ImGui::Image( m_playback.texture, ImVec2( fi->w * 2 * scale, fi->h * 2 * scale ), ImVec2( 0, 1 ), ImVec2( 1, 0 ) );
        }
        else
        {
            ImGui::Image( m_playback.texture, ImVec2( fi->w * 2 * scale, fi->h * 2 * scale ) );
        }
    }
    else
    {
        if( fi->flip )
        {
            ImGui::Image( m_playback.texture, ImVec2( fi->w * scale, fi->h * scale ), ImVec2( 0, 1 ), ImVec2( 1, 0 ) );
        }
        else
        {
            ImGui::Image( m_playback.texture, ImVec2( fi->w * scale, fi->h * scale ) );
        }
    }
    const auto wheel = ImGui::GetIO().MouseWheel;
    bool changed = false;
    int tmp = m_playback.frame + 1;
    if( wheel && ImGui::IsItemHovered() )
    {
        tmp -= (int)wheel;
        changed = true;
    }
    changed |= ImGui::SliderInt( "Frame image", &tmp, 1, ficnt, "%d" );
    ImGui::SetItemUsingMouseWheel();
    if( wheel && ImGui::IsItemHovered() )
    {
        if( ImGui::IsItemActive() )
        {
            ImGui::ClearActiveID();
        }
        else
        {
            tmp -= (int)wheel;
            changed = true;
        }
    }
    if( changed )
    {
        if( tmp < 1 ) tmp = 1;
        else if( (uint32_t)tmp > ficnt ) tmp = ficnt;
        SetPlaybackFrame( uint32_t( tmp - 1 ) );
        m_playback.pause = true;
    }
    ImGui::SliderFloat( "Playback speed", &m_playback.speed, 0.1f, 4, "%.2f" );

    const auto th = ImGui::GetTextLineHeight();
    float bw = 0;
    for( int i=0; i<PlaybackWindowButtonsCount; i++ )
    {
        bw = std::max( bw, ImGui::CalcTextSize( PlaybackWindowButtons[i] ).x );
    }
    bw += th;

    if( ImGui::Button( " " ICON_FA_CARET_LEFT " " ) )
    {
        if( m_playback.frame > 0 )
        {
            SetPlaybackFrame( m_playback.frame - 1 );
            m_playback.pause = true;
        }
    }
    ImGui::SameLine();
    if( ImGui::Button( " " ICON_FA_CARET_RIGHT " " ) )
    {
        if( m_playback.frame < ficnt - 1 )
        {
            SetPlaybackFrame( m_playback.frame + 1 );
            m_playback.pause = true;
        }
    }
    ImGui::SameLine();
    if( m_playback.pause )
    {
        if( ImGui::Button( PlaybackWindowButtons[0], ImVec2( bw, 0 ) ) && m_playback.frame != frameImages.size() - 1 )
        {
            m_playback.pause = false;
        }
    }
    else
    {
        if( ImGui::Button( PlaybackWindowButtons[1], ImVec2( bw, 0 ) ) )
        {
            m_playback.pause = true;
        }
    }
    ImGui::SameLine();
    if( ImGui::Checkbox( "Sync timeline", &m_playback.sync ) )
    {
        if( m_playback.sync )
        {
            m_vd.zvStart = m_worker.GetFrameBegin( *frameSet, fi->frameRef );
            m_vd.zvEnd = m_worker.GetFrameEnd( *frameSet, fi->frameRef );
            m_zoomAnim.active = false;
            m_viewMode = ViewMode::Paused;
            m_viewModeHeuristicTry = false;
        }
    }
    ImGui::SameLine();
    ImGui::Checkbox( "Zoom 2\xc3\x97", &m_playback.zoom );
    TextFocused( "Timestamp:", TimeToString( tstart ) );
    TooltipIfHovered( TimeToStringExact( tstart ) );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    TextFocused( "Frame:", RealToString( GetFrameNumber( *frameSet, fi->frameRef ) ) );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    char buf[64];
    auto ptr = PrintFloat( buf, buf+62, 4.f * fi->csz / ( size_t( fi->w ) * size_t( fi->h ) / 2 ), 2 );
    memcpy( ptr, " bpp", 5 );
    TextFocused( "Ratio:", buf );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ptr = PrintFloat( buf, buf+62, 100.f * fi->csz / ( size_t( fi->w ) * size_t( fi->h ) / 2 ), 2 );
        memcpy( ptr, "%", 2 );
        ImGui::TextUnformatted( buf );
        ImGui::EndTooltip();
    }
    ImGui::End();
}

}
