#include <algorithm>

#include "TracyImGui.hpp"
#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracyTimelineContext.hpp"
#include "TracyTimelineDraw.hpp"
#include "TracyView.hpp"

namespace tracy
{

const char* View::DecodeContextSwitchReasonCode( uint8_t reason )
{
    switch( reason )
    {
    case 0: return "Executive";
    case 1: return "FreePage";
    case 2: return "PageIn";
    case 3: return "PoolAllocation";
    case 4: return "DelayExecution";
    case 5: return "Suspended";
    case 6: return "UserRequest";
    case 7: return "WrExecutive";
    case 8: return "WrFreePage";
    case 9: return "WrPageIn";
    case 10: return "WrPoolAllocation";
    case 11: return "WrDelayExecution";
    case 12: return "WrSuspended";
    case 13: return "WrUserRequest";
    case 14: return "WrEventPair";
    case 15: return "WrQueue";
    case 16: return "WrLpcReceive";
    case 17: return "WrLpcReply";
    case 18: return "WrVirtualMemory";
    case 19: return "WrPageOut";
    case 20: return "WrRendezvous";
    case 21: return "WrKeyedEvent";
    case 22: return "WrTerminated";
    case 23: return "WrProcessInSwap";
    case 24: return "WrCpuRateControl";
    case 25: return "WrCalloutStack";
    case 26: return "WrKernel";
    case 27: return "WrResource";
    case 28: return "WrPushLock";
    case 29: return "WrMutex";
    case 30: return "WrQuantumEnd";
    case 31: return "WrDispatchInt";
    case 32: return "WrPreempted";
    case 33: return "WrYieldExecution";
    case 34: return "WrFastMutex";
    case 35: return "WrGuardedMutex";
    case 36: return "WrRundown";
    case 37: return "WrAlertByThreadId";
    case 38: return "WrDeferredPreempt";
    case 39: return "WrPhysicalFault";
    case 40: return "MaximumWaitReason";
    default: return "unknown";
    }
}

const char* View::DecodeContextSwitchReason( uint8_t reason )
{
    switch( reason )
    {
    case 0: return "(Thread is waiting for the scheduler)";
    case 1: return "(Thread is waiting for a free virtual memory page)";
    case 2: return "(Thread is waiting for a virtual memory page to arrive in memory)";
    case 4: return "(Thread execution is delayed)";
    case 5: return "(Thread execution is suspended)";
    case 6: return "(Thread is waiting on object - WaitForSingleObject, etc.)";
    case 7: return "(Thread is waiting for the scheduler)";
    case 8: return "(Thread is waiting for a free virtual memory page)";
    case 9: return "(Thread is waiting for a virtual memory page to arrive in memory)";
    case 11: return "(Thread execution is delayed)";
    case 12: return "(Thread execution is suspended)";
    case 13: return "(Thread is waiting for window messages)";
    case 15: return "(Thread is waiting on KQUEUE)";
    case 24: return "(CPU rate limiting)";
    case 34: return "(Waiting for a Fast Mutex)";
    default: return "";
    }
}

const char* View::DecodeContextSwitchStateCode( uint8_t state )
{
    switch( state )
    {
    case 0: return "Initialized";
    case 1: return "Ready";
    case 2: return "Running";
    case 3: return "Standby";
    case 4: return "Terminated";
    case 5: return "Waiting";
    case 6: return "Transition";
    case 7: return "DeferredReady";
    case 101: return "D (disk sleep)";
    case 102: return "I (idle)";
    case 103: return "R (running)";
    case 104: return "S (sleeping)";
    case 105: return "T (stopped)";
    case 106: return "t (tracing stop)";
    case 107: return "W";
    case 108: return "X (dead)";
    case 109: return "Z (zombie)";
    case 110: return "P (parked)";
    default: return "unknown";
    }
}

const char* View::DecodeContextSwitchState( uint8_t state )
{
    switch( state )
    {
    case 0: return "(Thread has been initialized, but has not yet started)";
    case 1: return "(Thread is waiting to use a processor because no processor is free. The thread is prepared to run on the next available processor)";
    case 2: return "(Thread is currently using a processor)";
    case 3: return "(Thread is about to use a processor)";
    case 4: return "(Thread has finished executing and has exited)";
    case 5: return "(Thread is not ready to use the processor because it is waiting for a peripheral operation to complete or a resource to become free)";
    case 6: return "(Thread is waiting for a resource, other than the processor, before it can execute)";
    case 7: return "(Thread has been selected to run on a specific processor but have not yet beed scheduled)";
    case 101: return "(Uninterruptible sleep, usually IO)";
    case 102: return "(Idle kernel thread)";
    case 103: return "(Running or on run queue)";
    case 104: return "(Interruptible sleep, waiting for an event to complete)";
    case 105: return "(Stopped by job control signal)";
    case 106: return "(Stopped by debugger during the tracing)";
    case 107: return "(Paging)";
    case 108: return "(Dead task is scheduling one last time)";
    case 109: return "(Zombie process)";
    case 110: return "(Parked)";
    default: return "";
    }
}

void View::DrawContextSwitchList( const TimelineContext& ctx, const std::vector<ContextSwitchDraw>& drawList, const Vector<ContextSwitchData>& ctxSwitch, int offset, int endOffset, bool isFiber )
{
    constexpr float MinCtxSize = 4;

    const auto vStart = ctx.vStart;
    const auto& wpos = ctx.wpos;
    const auto pxns = ctx.pxns;
    const auto hover = ctx.hover;
    const auto w = ctx.w;
    const auto ty = round( ctx.ty * 0.75f );

    const auto lineSize = 2 * GetScale();
    auto draw = ImGui::GetWindowDrawList();
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );
    const auto ty05 = round( ty * 0.5f );

    double minpx = -10;

    for( auto& v : drawList )
    {
        const auto it = ctxSwitch.begin() + v.idx;
        const auto& ev = *it;
        switch( v.type )
        {
        case ContextSwitchDrawType::Waiting:
        {
            const auto& prev = *(it-1);
            const bool migration = prev.Cpu() != ev.Cpu();
            const auto px0 = std::max( { ( prev.End() - vStart ) * pxns, -10.0, double( minpx ) } );
            const auto pxw = ( ev.WakeupVal() - vStart ) * pxns;
            const auto px1 = std::min( ( ev.Start() - vStart ) * pxns, w + 10.0 );
            const auto color = migration ? 0xFFEE7711 : 0xFF2222AA;
            if( m_vd.darkenContextSwitches )
            {
                draw->AddRectFilled( dpos + ImVec2( px0, offset + ty05 ), dpos + ImVec2( px1, endOffset ), 0x661C2321 );
            }
            DrawLine( draw, dpos + ImVec2( px0, offset + ty05 - 0.5f ), dpos + ImVec2( std::min( pxw, w+10.0 ), offset + ty05 - 0.5f ), color, lineSize );
            if( ev.WakeupVal() != ev.Start() )
            {
                DrawLine( draw, dpos + ImVec2( std::max( pxw, 10.0 ), offset + ty05 - 0.5f ), dpos + ImVec2( px1, offset + ty05 - 0.5f ), 0xFF2280A0, lineSize );
            }

            if( hover )
            {
                bool tooltip = false;
                if( ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( pxw, offset + ty ) ) )
                {
                    ImGui::BeginTooltip();
                    if( isFiber )
                    {
                        TextFocused( "Fiber is", "yielding" );
                        TextFocused( "Yield time:", TimeToString( ev.Start() - prev.End() ) );
                    }
                    else
                    {
                        TextFocused( "Thread is", migration ? "migrating CPUs" : "waiting" );
                        TextFocused( "Waiting time:", TimeToString( ev.WakeupVal() - prev.End() ) );
                        if( migration )
                        {
                            TextFocused( "CPU:", RealToString( prev.Cpu() ) );
                            ImGui::SameLine();
                            TextFocused( ICON_FA_RIGHT_LONG, RealToString( ev.Cpu() ) );
                        }
                        else
                        {
                            TextFocused( "CPU:", RealToString( ev.Cpu() ) );
                        }
                        if( prev.Reason() != 100 )
                        {
                            TextFocused( "Wait reason:", DecodeContextSwitchReasonCode( prev.Reason() ) );
                            ImGui::SameLine();
                            ImGui::PushFont( m_smallFont );
                            ImGui::AlignTextToFramePadding();
                            TextDisabledUnformatted( DecodeContextSwitchReason( prev.Reason() ) );
                            ImGui::PopFont();
                        }
                        TextFocused( "Wait state:", DecodeContextSwitchStateCode( prev.State() ) );
                        ImGui::SameLine();
                        ImGui::PushFont( m_smallFont );
                        ImGui::AlignTextToFramePadding();
                        TextDisabledUnformatted( DecodeContextSwitchState( prev.State() ) );
                        ImGui::PopFont();
                    }
                    tooltip = true;

                    if( IsMouseClicked( 2 ) )
                    {
                        ZoomToRange( prev.End(), ev.WakeupVal() );
                    }
                }
                else if( ev.WakeupVal() != ev.Start() && ImGui::IsMouseHoveringRect( wpos + ImVec2( pxw, offset ), wpos + ImVec2( px1, offset + ty ) ) )
                {
                    assert( !isFiber );
                    ImGui::BeginTooltip();
                    TextFocused( "Thread is", "waking up" );
                    TextFocused( "Scheduling delay:", TimeToString( ev.Start() - ev.WakeupVal() ) );
                    TextFocused( "CPU:", RealToString( ev.Cpu() ) );
                    if( IsMouseClicked( 2 ) )
                    {
                        ZoomToRange( prev.End(), ev.WakeupVal() );
                    }
                    tooltip = true;
                }
                if( tooltip )
                {
                    const auto waitStack = v.data;
                    if( waitStack )
                    {
                            ImGui::Separator();
                            TextDisabledUnformatted( ICON_FA_HOURGLASS_HALF " Wait stack:" );
                            CallstackTooltipContents( waitStack );
                            if( ImGui::IsMouseClicked( 0 ) )
                            {
                                m_callstackInfoWindow = waitStack;
                            }
                    }
                    ImGui::EndTooltip();
                }
            }
            break;
        }
        case ContextSwitchDrawType::Folded:
        {
            const auto num = v.data;
            const auto px0 = std::max( ( ev.Start() - vStart ) * pxns, -10.0 );
            const auto eit = it + num - 1;
            const auto end = eit->IsEndValid() ? eit->End() : eit->Start();
            const auto px1ns = end - vStart;
            minpx = std::min( std::max( px1ns * pxns, px0+MinCtxSize ), double( w + 10 ) );
            if( num == 1 )
            {
                DrawLine( draw, dpos + ImVec2( px0, offset + ty05 - 0.5f ), dpos + ImVec2( minpx, offset + ty05 - 0.5f ), 0xFF22DD22, lineSize );
                if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( minpx, offset + ty + 1 ) ) )
                {
                    ImGui::BeginTooltip();
                    if( isFiber )
                    {
                        const auto tid = m_worker.DecompressThread( ev.Thread() );
                        TextFocused( "Fiber is", "running" );
                        TextFocused( "Activity time:", TimeToString( end - ev.Start() ) );
                        TextFocused( "Thread:", m_worker.GetThreadName( tid ) );
                        ImGui::SameLine();
                        ImGui::TextDisabled( "(%s)", RealToString( tid ) );
                    }
                    else
                    {
                        TextFocused( "Thread is", "running" );
                        TextFocused( "Activity time:", TimeToString( end - ev.Start() ) );
                        TextFocused( "CPU:", RealToString( ev.Cpu() ) );
                    }
                    ImGui::EndTooltip();

                    if( IsMouseClicked( 2 ) )
                    {
                        ZoomToRange( ev.Start(), end );
                    }
                }
            }
            else
            {
                DrawZigZag( draw, wpos + ImVec2( 0, offset + ty05 ), px0, minpx, ty/4, 0xFF888888 );
                if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( minpx, offset + ty + 1 ) ) )
                {
                    ImGui::BeginTooltip();
                    TextFocused( isFiber ? "Fiber is" : "Thread is", "changing activity multiple times" );
                    TextFocused( "Number of running regions:", RealToString( num ) );
                    TextFocused( "Time:", TimeToString( end - ev.Start() ) );
                    ImGui::EndTooltip();

                    if( IsMouseClicked( 2 ) )
                    {
                        ZoomToRange( ev.Start(), end );
                    }
                }
            }
            break;
        }
        case ContextSwitchDrawType::Running:
        {
            const auto end = ev.IsEndValid() ? ev.End() : ev.Start();
            const auto px0 = std::max( { ( ev.Start() - vStart ) * pxns, -10.0, double( minpx ) } );
            const auto px1 = std::min( ( end - vStart ) * pxns, w + 10.0 );
            DrawLine( draw, dpos + ImVec2( px0, offset + ty05 - 0.5f ), dpos + ImVec2( px1, offset + ty05 - 0.5f ), 0xFF22DD22, lineSize );
            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + ty + 1 ) ) )
            {
                ImGui::BeginTooltip();
                if( isFiber )
                {
                    const auto tid = m_worker.DecompressThread( ev.Thread() );
                    TextFocused( "Fiber is", "running" );
                    TextFocused( "Activity time:", TimeToString( end - ev.Start() ) );
                    TextFocused( "Thread:", m_worker.GetThreadName( tid ) );
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(%s)", RealToString( tid ) );
                }
                else
                {
                    TextFocused( "Thread is", "running" );
                    TextFocused( "Activity time:", TimeToString( end - ev.Start() ) );
                    TextFocused( "CPU:", RealToString( ev.Cpu() ) );
                }
                ImGui::EndTooltip();

                if( IsMouseClicked( 2 ) )
                {
                    ZoomToRange( ev.Start(), end );
                }
            }
            break;
        }
        default:
            assert( false );
            break;
        };
    }
}

void View::DrawWaitStacks()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 1400 * scale, 500 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Wait stacks", &m_showWaitStacks );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }
#ifdef TRACY_NO_STATISTICS
    ImGui::TextWrapped( "Rebuild without the TRACY_NO_STATISTICS macro to enable wait stacks." );
#else
    uint64_t totalCount = 0;
    unordered_flat_map<uint32_t, uint64_t> stacks;
    for( auto& t : m_threadOrder )
    {
        if( WaitStackThread( t->id ) )
        {
            auto it = t->ctxSwitchSamples.begin();
            auto end = t->ctxSwitchSamples.end();
            if( m_waitStackRange.active )
            {
                it = std::lower_bound( it, end, m_waitStackRange.min, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
                end = std::lower_bound( it, end, m_waitStackRange.max, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
            }
            totalCount += std::distance( it, end );
            while( it != end )
            {
                auto cs = it->callstack.Val();
                auto cit = stacks.find( cs );
                if( cit == stacks.end() )
                {
                    stacks.emplace( cs, 1 );
                }
                else
                {
                    cit->second++;
                }
                ++it;
            }
        }
    }

    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 2, 2 ) );
    if( ImGui::RadioButton( ICON_FA_TABLE " List", m_waitStackMode == 0 ) ) m_waitStackMode = 0;
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    if( ImGui::RadioButton( ICON_FA_TREE " Bottom-up tree", m_waitStackMode == 1 ) ) m_waitStackMode = 1;
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    if( ImGui::RadioButton( ICON_FA_TREE " Top-down tree", m_waitStackMode == 2 ) ) m_waitStackMode = 2;
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    ImGui::SeparatorEx( ImGuiSeparatorFlags_Vertical );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    TextFocused( "Total wait stacks:", RealToString( m_worker.GetContextSwitchSampleCount() ) );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    TextFocused( "Selected:", RealToString( totalCount ) );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    ImGui::SeparatorEx( ImGuiSeparatorFlags_Vertical );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    if( ImGui::Checkbox( "Limit range", &m_waitStackRange.active ) )
    {
        if( m_waitStackRange.active && m_waitStackRange.min == 0 && m_waitStackRange.max == 0 )
        {
            m_waitStackRange.min = m_vd.zvStart;
            m_waitStackRange.max = m_vd.zvEnd;
        }
    }
    if( m_waitStackRange.active )
    {
        ImGui::SameLine();
        TextColoredUnformatted( 0xFF00FFFF, ICON_FA_TRIANGLE_EXCLAMATION );
        ImGui::SameLine();
        ToggleButton( ICON_FA_RULER " Limits", m_showRanges );
    }
    ImGui::PopStyleVar();

    bool threadsChanged = false;
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
                WaitStackThread( t->id ) = true;
            }
            threadsChanged = true;
        }
        ImGui::SameLine();
        if( ImGui::SmallButton( "Unselect all" ) )
        {
            for( const auto& t : m_threadOrder )
            {
                WaitStackThread( t->id ) = false;
            }
            threadsChanged = true;
        }

        int idx = 0;
        for( const auto& t : m_threadOrder )
        {
            if( t->ctxSwitchSamples.empty() ) continue;
            ImGui::PushID( idx++ );
            const auto threadColor = GetThreadColor( t->id, 0 );
            SmallColorBox( threadColor );
            ImGui::SameLine();
            if( SmallCheckbox( m_worker.GetThreadName( t->id ), &WaitStackThread( t->id ) ) )
            {
                threadsChanged = true;
            }
            ImGui::PopID();
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s)", RealToString( t->ctxSwitchSamples.size() ) );
            if( crash.thread == t->id )
            {
                ImGui::SameLine();
                TextColoredUnformatted( ImVec4( 1.f, 0.2f, 0.2f, 1.f ), ICON_FA_SKULL " Crashed" );
            }
            if( t->isFiber )
            {
                ImGui::SameLine();
                TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
            }
        }
        ImGui::TreePop();
    }
    if( threadsChanged ) m_waitStack = 0;

    ImGui::Separator();
    ImGui::BeginChild( "##waitstacks" );
    if( stacks.empty() )
    {
        ImGui::TextUnformatted( "No wait stacks to display." );
    }
    else
    {
        switch( m_waitStackMode )
        {
        case 0:
        {
            TextDisabledUnformatted( "Wait stack:" );
            ImGui::SameLine();
            if( ImGui::SmallButton( " " ICON_FA_CARET_LEFT " " ) )
            {
                m_waitStack = std::max( m_waitStack - 1, 0 );
            }
            ImGui::SameLine();
            ImGui::Text( "%s / %s", RealToString( m_waitStack + 1 ), RealToString( stacks.size() ) );
            if( ImGui::IsItemClicked() ) ImGui::OpenPopup( "WaitStacksPopup" );
            ImGui::SameLine();
            if( ImGui::SmallButton( " " ICON_FA_CARET_RIGHT " " ) )
            {
                m_waitStack = std::min<int>( m_waitStack + 1, stacks.size() - 1 );
            }
            if( ImGui::BeginPopup( "WaitStacksPopup" ) )
            {
                int sel = m_waitStack + 1;
                ImGui::SetNextItemWidth( 120 * scale );
                const bool clicked = ImGui::InputInt( "##waitStack", &sel, 1, 100, ImGuiInputTextFlags_EnterReturnsTrue );
                if( clicked ) m_waitStack = std::min( std::max( sel, 1 ), int( stacks.size() ) ) - 1;
                ImGui::EndPopup();
            }
            ImGui::SameLine();
            ImGui::Spacing();
            ImGui::SameLine();
            Vector<decltype(stacks.begin())> data;
            data.reserve( stacks.size() );
            for( auto it = stacks.begin(); it != stacks.end(); ++it ) data.push_back( it );
            pdqsort_branchless( data.begin(), data.end(), []( const auto& l, const auto& r ) { return l->second > r->second; } );
            TextFocused( "Counts:", RealToString( data[m_waitStack]->second ) );
            ImGui::SameLine();
            char buf[64];
            PrintStringPercent( buf, 100. * data[m_waitStack]->second / totalCount );
            TextDisabledUnformatted( buf );
            ImGui::Separator();
            DrawCallstackTable( data[m_waitStack]->first, false );
            break;
        }
        case 1:
        {
            SmallCheckbox( ICON_FA_LAYER_GROUP " Group by function name", &m_groupWaitStackBottomUp );
            auto tree = GetCallstackFrameTreeBottomUp( stacks, m_groupCallstackTreeByNameBottomUp );
            if( !tree.empty() )
            {
                int idx = 0;
                DrawFrameTreeLevel( tree, idx );
            }
            else
            {
                TextDisabledUnformatted( "No call stacks to show" );
            }
            break;
        }
        case 2:
        {
            SmallCheckbox( ICON_FA_LAYER_GROUP " Group by function name", &m_groupWaitStackTopDown );
            auto tree = GetCallstackFrameTreeTopDown( stacks, m_groupCallstackTreeByNameTopDown );
            if( !tree.empty() )
            {
                int idx = 0;
                DrawFrameTreeLevel( tree, idx );
            }
            else
            {
                TextDisabledUnformatted( "No call stacks to show" );
            }
            break;
        }
        default:
            assert( false );
            break;
        }
    }
#endif
    ImGui::EndChild();
    ImGui::End();
}

}
