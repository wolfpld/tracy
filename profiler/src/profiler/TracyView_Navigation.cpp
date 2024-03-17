#include "TracyView.hpp"

namespace tracy
{

void View::ZoomToZone( const ZoneEvent& ev )
{
    const auto end = m_worker.GetZoneEnd( ev );
    if( end - ev.Start() <= 0 ) return;
    ZoomToRange( ev.Start(), end );
}

void View::ZoomToZone( const GpuEvent& ev )
{
    const auto end = m_worker.GetZoneEnd( ev );
    if( end - ev.GpuStart() <= 0 ) return;
    auto ctx = GetZoneCtx( ev );
    if( !ctx )
    {
        ZoomToRange( ev.GpuStart(), end );
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
        ZoomToRange( AdjustGpuTime( ev.GpuStart(), begin, drift ), AdjustGpuTime( end, begin, drift ) );
    }
}

void View::ZoomToRange( int64_t start, int64_t end, bool pause )
{
    if( start == end )
    {
        end = start + 1;
    }

    if( pause )
    {
        m_viewMode = ViewMode::Paused;
        m_viewModeHeuristicTry = false;
    }
    m_highlightZoom.active = false;
    if( !m_playback.pause && m_playback.sync ) m_playback.pause = true;

    m_zoomAnim.active = true;
    if( m_viewMode == ViewMode::LastRange )
    {
        const auto rangeCurr = m_vd.zvEnd - m_vd.zvStart;
        const auto rangeDest = end - start;
        m_zoomAnim.start0 = m_vd.zvStart;
        m_zoomAnim.start1 = m_vd.zvStart - ( rangeDest - rangeCurr );
        m_zoomAnim.end0 = m_vd.zvEnd;
        m_zoomAnim.end1 = m_vd.zvEnd;
    }
    else
    {
        m_zoomAnim.start0 = m_vd.zvStart;
        m_zoomAnim.start1 = start;
        m_zoomAnim.end0 = m_vd.zvEnd;
        m_zoomAnim.end1 = end;
    }
    m_zoomAnim.progress = 0;
}

void View::ZoomToPrevFrame()
{
    if( m_vd.zvStart >= m_worker.GetFrameBegin( *m_frames, 0 ) )
    {
        size_t frame;
        if( m_frames->continuous )
        {
            frame = (size_t)m_worker.GetFrameRange( *m_frames, m_vd.zvStart, m_vd.zvStart ).first;
        }
        else
        {
            frame = (size_t)m_worker.GetFrameRange( *m_frames, m_vd.zvStart, m_vd.zvStart ).second;
        }

        if( frame > 0 )
        {
            frame--;
            const auto fbegin = m_worker.GetFrameBegin( *m_frames, frame );
            const auto fend = m_worker.GetFrameEnd( *m_frames, frame );
            ZoomToRange( fbegin, fend );
        }
    }
}

void View::ZoomToNextFrame()
{
    int64_t start;
    if( m_zoomAnim.active )
    {
        start = m_zoomAnim.start1;
    }
    else
    {
        start = m_vd.zvStart;
    }

    size_t frame;
    if( start < m_worker.GetFrameBegin( *m_frames, 0 ) )
    {
        frame = 0;
    }
    else
    {
        frame = (size_t)m_worker.GetFrameRange( *m_frames, start, start ).first + 1;
    }
    if( frame >= m_worker.GetFrameCount( *m_frames ) ) return;

    const auto fbegin = m_worker.GetFrameBegin( *m_frames, frame );
    const auto fend = m_worker.GetFrameEnd( *m_frames, frame );
    ZoomToRange( fbegin, fend );
}

void View::CenterAtTime( int64_t t )
{
    const auto hr = std::max<uint64_t>( 1, ( m_vd.zvEnd - m_vd.zvStart ) / 2 );
    ZoomToRange( t - hr, t + hr );
}

void View::SetViewToLastFrames()
{
    const int total = m_worker.GetFrameCount( *m_frames );

    m_vd.zvStart = m_worker.GetFrameBegin( *m_frames, std::max( 0, total - 4 ) );
    if( total == 1 )
    {
        m_vd.zvEnd = m_worker.GetLastTime();
    }
    else
    {
        m_vd.zvEnd = m_worker.GetFrameBegin( *m_frames, total - 1 );
    }
    if( m_vd.zvEnd == m_vd.zvStart )
    {
        m_vd.zvEnd = m_worker.GetLastTime();
    }
}

}
