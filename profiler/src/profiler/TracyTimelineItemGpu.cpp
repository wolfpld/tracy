#include "TracyImGui.hpp"
#include "TracyPopcnt.hpp"
#include "TracyPrint.hpp"
#include "TracyTimelineContext.hpp"
#include "TracyTimelineItemGpu.hpp"
#include "TracyUtility.hpp"
#include "TracyView.hpp"
#include "TracyWorker.hpp"

namespace tracy
{

TimelineItemGpu::TimelineItemGpu( View& view, Worker& worker, GpuCtxData* gpu )
    : TimelineItem( view, worker, gpu, false )
    , m_gpu( gpu )
    , m_idx( view.GetNextGpuIdx() )
{
}

bool TimelineItemGpu::IsEmpty() const
{
    return m_gpu->threadData.empty();
}

const char* TimelineItemGpu::HeaderLabel() const
{
    static char buf[4096];
    if( m_gpu->name.Active() )
    {
        sprintf( buf, "%s", m_worker.GetString( m_gpu->name ) );
    }
    else
    {
        sprintf( buf, "%s context %i", GpuContextNames[(int)m_gpu->type], m_idx );
    }
    return buf;
}

void TimelineItemGpu::HeaderTooltip( const char* label ) const
{
    const bool dynamicColors = m_view.GetViewData().dynamicColors;
    const bool isMultithreaded =
        ( m_gpu->type == GpuContextType::Vulkan ) ||
        ( m_gpu->type == GpuContextType::OpenCL ) ||
        ( m_gpu->type == GpuContextType::Direct3D12 );

    char buf[64];
    sprintf( buf, "%s context %i", GpuContextNames[(int)m_gpu->type], m_idx );

    ImGui::BeginTooltip();
    if( m_gpu->name.Active() ) TextFocused( "Name:", m_worker.GetString( m_gpu->name ) );
    ImGui::TextUnformatted( buf );
    ImGui::Separator();
    if( !isMultithreaded )
    {
        SmallColorBox( GetThreadColor( m_gpu->thread, 0, dynamicColors ) );
        ImGui::SameLine();
        TextFocused( "Thread:", m_worker.GetThreadName( m_gpu->thread ) );
    }
    else
    {
        if( m_gpu->threadData.size() == 1 )
        {
            auto it = m_gpu->threadData.begin();
            auto tid = it->first;
            if( tid == 0 )
            {
                if( !it->second.timeline.empty() )
                {
                    if( it->second.timeline.is_magic() )
                    {
                        auto& tl = *(Vector<GpuEvent>*)&it->second.timeline;
                        tid = m_worker.DecompressThread( tl.begin()->Thread() );
                    }
                    else
                    {
                        tid = m_worker.DecompressThread( (*it->second.timeline.begin())->Thread() );
                    }
                }
            }
            SmallColorBox( GetThreadColor( tid, 0, dynamicColors ) );
            ImGui::SameLine();
            TextFocused( "Thread:", m_worker.GetThreadName( tid ) );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s)", RealToString( tid ) );
            if( m_worker.IsThreadFiber( tid ) )
            {
                ImGui::SameLine();
                TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
            }
        }
        else
        {
            ImGui::TextDisabled( "Threads:" );
            ImGui::Indent();
            for( auto& td : m_gpu->threadData )
            {
                SmallColorBox( GetThreadColor( td.first, 0, dynamicColors ) );
                ImGui::SameLine();
                ImGui::TextUnformatted( m_worker.GetThreadName( td.first ) );
                ImGui::SameLine();
                ImGui::TextDisabled( "(%s)", RealToString( td.first ) );
            }
            ImGui::Unindent();
        }
    }
    const auto t0 = RangeBegin();
    if( t0 != std::numeric_limits<int64_t>::max() )
    {
        TextFocused( "Appeared at", TimeToString( t0 ) );
    }
    TextFocused( "Zone count:", RealToString( m_gpu->count ) );
    if( m_gpu->period != 1.f )
    {
        TextFocused( "Timestamp accuracy:", TimeToString( m_gpu->period ) );
    }
    if( m_gpu->overflow != 0 )
    {
        ImGui::Separator();
        ImGui::TextUnformatted( "GPU timer overflow has been detected." );
        TextFocused( "Timer resolution:", RealToString( 63 - TracyLzcnt( m_gpu->overflow ) ) );
        ImGui::SameLine();
        TextDisabledUnformatted( "bits" );
    }
    ImGui::EndTooltip();
}

void TimelineItemGpu::HeaderExtraContents( const TimelineContext& ctx, int offset, float labelWidth )
{
    if( m_gpu->name.Active() )
    {
        auto draw = ImGui::GetWindowDrawList();
        const auto ty = ImGui::GetTextLineHeight();

        char buf[64];
        sprintf( buf, "%s context %i", GpuContextNames[(int)m_gpu->type], m_idx );
        draw->AddText( ctx.wpos + ImVec2( ty * 1.5f + labelWidth, offset ), HeaderColorInactive(), buf );
    }
}

int64_t TimelineItemGpu::RangeBegin() const
{
    int64_t t = std::numeric_limits<int64_t>::max();
    for( auto& td : m_gpu->threadData )
    {
        int64_t t0;
        if( td.second.timeline.is_magic() )
        {
            t0 = ((Vector<GpuEvent>*)&td.second.timeline)->front().GpuStart();
        }
        else
        {
            t0 = td.second.timeline.front()->GpuStart();
        }
        if( t0 >= 0 )
        {
            t = std::min( t, t0 );
        }
    }
    return t;
}

int64_t TimelineItemGpu::RangeEnd() const
{
    int64_t t = std::numeric_limits<int64_t>::min();
    for( auto& td : m_gpu->threadData )
    {
        int64_t t0;
        if( td.second.timeline.is_magic() )
        {
            t0 = ((Vector<GpuEvent>*)&td.second.timeline)->front().GpuStart();
        }
        else
        {
            t0 = td.second.timeline.front()->GpuStart();
        }
        if( t0 >= 0 )
        {
            if( td.second.timeline.is_magic() )
            {
                t = std::max( t, std::min( m_worker.GetLastTime(), m_worker.GetZoneEnd( ((Vector<GpuEvent>*)&td.second.timeline)->back() ) ) );
            }
            else
            {
                t = std::max( t, std::min( m_worker.GetLastTime(), m_worker.GetZoneEnd( *td.second.timeline.back() ) ) );
            }
        }
    }
    return t;
}

bool TimelineItemGpu::DrawContents( const TimelineContext& ctx, int& offset )
{
    return m_view.DrawGpu( ctx, *m_gpu, offset );
}

}
