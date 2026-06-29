#include "TracyImGui.hpp"
#include "TracyPrint.hpp"
#include "TracyTexture.hpp"
#include "TracyView.hpp"

namespace tracy
{

int View::GetPlaybackFrameBegin() const
{
    return m_playback.limitRange ? m_playback.range.first : 0;
}

int View::GetPlaybackFrameEnd() const
{
    return m_playback.limitRange ? m_playback.range.second + 1 : m_worker.GetFrameImageCount();
}

std::pair<int, int> View::GetPlaybackFrameRangeFromTime( int64_t tmin, int64_t tmax, bool requireCoverage ) const
{
    const auto& frameImages = m_worker.GetFrameImages();
    const int count = (int)frameImages.size();
    if( count == 0 ) return { -1, -1 };

    const auto& frameSet = *m_worker.GetFramesBase();
    const auto cmp = [this, &frameSet]( int64_t t, const auto& fi ) { return t < m_worker.GetFrameBegin( frameSet, fi->frameRef ); };

    auto it = std::upper_bound( frameImages.begin(), frameImages.end(), tmax, cmp );
    auto hi = (int)std::distance( frameImages.begin(), it ) - 1;
    if( hi < 0 ) return { 0, 0 };

    it = std::upper_bound( frameImages.begin(), it, tmin, cmp );
    auto lo = std::max<int>( 0, (int)std::distance( frameImages.begin(), it ) - 1 );

    if( requireCoverage )
    {
        const auto lo0 = m_worker.GetFrameBegin( frameSet, frameImages[lo]->frameRef );
        if( lo0 < tmin )
        {
            const auto lo1 = m_worker.GetFrameEnd( frameSet, frameImages[lo]->frameRef );
            const auto span = lo1 - lo0;
            const auto overlap = std::min( lo1, tmax ) - tmin;
            if( overlap * 4 < span * 3 ) lo++;
        }
        const auto hi1 = m_worker.GetFrameEnd( frameSet, frameImages[hi]->frameRef );
        if( hi1 > tmax )
        {
            const auto hi0 = m_worker.GetFrameBegin( frameSet, frameImages[hi]->frameRef );
            const auto span = hi1 - hi0;
            const auto overlap = tmax - std::max( hi0, tmin );
            if( overlap * 4 < span * 3 ) hi--;
        }
        if( lo > hi ) return { 0, 0 };
    }

    return { lo, hi };
}

void View::SetPlaybackFrame( uint32_t idx, bool mayExtend )
{
    const auto frameSet = m_worker.GetFramesBase();
    const auto& frameImages = m_worker.GetFrameImages();
    auto begin = GetPlaybackFrameBegin();
    auto end = GetPlaybackFrameEnd();
    if( mayExtend && ( idx < begin || idx >= end ) )
    {
        m_playback.limitRange = false;
        begin = GetPlaybackFrameBegin();
        end = GetPlaybackFrameEnd();
    }
    assert( idx >= begin && idx < end );

    m_playback.frame = idx;

    if( end - begin <= 1 || ( idx == end - 1 && !m_playback.loop ) )
    {
        m_playback.pause = true;
    }
    else
    {
        if( idx == end - 1 ) idx--;
        const auto t0 = m_worker.GetFrameBegin( *frameSet, frameImages[idx]->frameRef );
        const auto t1 = m_worker.GetFrameBegin( *frameSet, frameImages[idx+1]->frameRef );
        m_playback.timeLeft = ( t1 - t0 ) / 1000000000.f;
    }
}

static const char* PlaybackWindowButtons[] = {
    ICON_FA_PLAY " Play",
    ICON_FA_PAUSE " Pause",
};

constexpr size_t PlaybackWindowButtonsCount = sizeof( PlaybackWindowButtons ) / sizeof( *PlaybackWindowButtons );

void View::DrawPlayback()
{
    ImGui::Begin( "Playback", &m_showPlayback, ImGuiWindowFlags_AlwaysAutoResize );
    if( !m_showPlayback ) m_playback.pause = true;
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }

    const auto scale = GetScale();
    const auto frameSet = m_worker.GetFramesBase();
    const auto& frameImages = m_worker.GetFrameImages();
    const auto& fi = frameImages[m_playback.frame];
    const auto begin = GetPlaybackFrameBegin();
    const auto end = GetPlaybackFrameEnd();

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
                if( m_playback.frame + 1 == end )
                {
                    assert( m_playback.loop );
                    SetPlaybackFrame( begin, false );
                }
                else
                {
                    SetPlaybackFrame( m_playback.frame + 1, false );
                }
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
    changed |= ImGui::SliderInt( "Frame image", &tmp, begin + 1, end, "%d" );
    ImGui::SetItemKeyOwner( ImGuiKey_MouseWheelY );
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
        if( (uint32_t)tmp < begin + 1 ) tmp = begin + 1;
        else if( (uint32_t)tmp > end ) tmp = end;
        SetPlaybackFrame( uint32_t( tmp - 1 ), false );
        m_playback.pause = true;
    }
    ImGui::SliderFloat( "Playback speed", &m_playback.speed, 0.1f, 4, "%.2f" );
    ImGui::SameLine();
    if( ImGui::SmallButton( "Reset##speed" ) ) m_playback.speed = 1;

    const auto th = ImGui::GetTextLineHeight();
    float bw = 0;
    for( int i=0; i<PlaybackWindowButtonsCount; i++ )
    {
        bw = std::max( bw, ImGui::CalcTextSize( PlaybackWindowButtons[i] ).x );
    }
    bw += th;

    if( ImGui::Button( " " ICON_FA_CARET_LEFT " " ) )
    {
        if( m_playback.frame > begin )
        {
            SetPlaybackFrame( m_playback.frame - 1, false );
            m_playback.pause = true;
        }
    }
    ImGui::SameLine();
    if( ImGui::Button( " " ICON_FA_CARET_RIGHT " " ) )
    {
        if( m_playback.frame < end - 1 )
        {
            SetPlaybackFrame( m_playback.frame + 1, false );
            m_playback.pause = true;
        }
    }
    ImGui::SameLine();
    if( m_playback.pause )
    {
        const auto disabled = !m_playback.loop && ( m_playback.frame == end - 1 );
        if( disabled ) ImGui::BeginDisabled();
        if( ImGui::Button( PlaybackWindowButtons[0], ImVec2( bw, 0 ) ) ) m_playback.pause = false;
        if( disabled ) ImGui::EndDisabled();
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
    ImGui::SameLine();
    ImGui::Checkbox( "Loop", &m_playback.loop );
    bool limitChanged = SmallCheckbox( "Limit frame range", &m_playback.limitRange );
    if( m_playback.limitRange )
    {
        if( m_playback.range.first < 0 ) m_playback.range = { 0, m_worker.GetFrameImageCount() - 1 };

        ImGui::SameLine();
        if( ImGui::SmallButton( ICON_FA_COPY " Copy from" ) ) ImGui::OpenPopup( "playbackCopyFrom" );
        ImGui::SameLine();
        if( ImGui::SmallButton( "Reset##range" ) ) m_playback.range = { 0, m_worker.GetFrameImageCount() - 1 };
        if( ImGui::BeginPopup( "playbackCopyFrom" ) )
        {
            if( m_annotations.empty() )
            {
                TextDisabledUnformatted( ICON_FA_NOTE_STICKY " Annotation" );
            }
            else if( ImGui::BeginMenu( ICON_FA_NOTE_STICKY " Annotation" ) )
            {
                for( auto& v : m_annotations )
                {
                    SmallColorBox( v->color );
                    ImGui::SameLine();
                    if( ImGui::MenuItem( v->text.empty() ? "<unnamed>" : v->text.c_str() ) )
                    {
                        m_playback.range = GetPlaybackFrameRangeFromTime( v->range.min, v->range.max, m_playback.requireCoverage );
                        limitChanged = true;
                    }
                    ImGui::SameLine();
                    ImGui::TextDisabled( "%s - %s (%s)", TimeToStringExact( v->range.min ), TimeToStringExact( v->range.max ), TimeToString( v->range.max - v->range.min ) );
                }
                ImGui::EndMenu();
            }
            for( auto& r : m_ranges )
            {
                if( r.range->min == 0 && r.range->max == 0 )
                {
                    TextDisabledUnformatted( r.name );
                }
                else if( ImGui::MenuItem( r.name ) )
                {
                    m_playback.range = GetPlaybackFrameRangeFromTime( r.range->min, r.range->max, m_playback.requireCoverage );
                    limitChanged = true;
                }
            }
            ImGui::Separator();
            SmallCheckbox( "Require frame coverage", &m_playback.requireCoverage );
            ImGui::EndPopup();
        }

        ImGui::Indent();
        int r0 = m_playback.range.first + 1;
        int r1 = m_playback.range.second + 1;
        if( ImGui::DragIntRange2( "##range", &r0, &r1, 1, 1, m_worker.GetFrameImageCount(), "%d" ) )
        {
            m_playback.range = { r0 - 1, r1 - 1 };
            limitChanged = true;
        }
        ImGui::Unindent();

        if( limitChanged )
        {
            if( m_playback.frame < m_playback.range.first )
            {
                m_playback.pause = true;
                SetPlaybackFrame( m_playback.range.first, false );
            }
            else if( m_playback.frame > m_playback.range.second )
            {
                m_playback.pause = true;
                SetPlaybackFrame( m_playback.range.second, false );
            }
        }
    }
    ImGui::Separator();
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
