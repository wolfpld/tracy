#include <algorithm>

#include "TracyImGui.hpp"
#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracyTimelineContext.hpp"
#include "TracyTimelineDraw.hpp"
#include "TracyView.hpp"
#include "tracy_pdqsort.h"

namespace tracy
{

const char* View::DecodeContextSwitchReasonCode( uint8_t reason )
{
    switch( reason )
    {
    case ContextSwitchData::Win32_Executive: return "Executive";
    case ContextSwitchData::Win32_FreePage: return "FreePage";
    case ContextSwitchData::Win32_PageIn: return "PageIn";
    case ContextSwitchData::Win32_PoolAllocation: return "PoolAllocation";
    case ContextSwitchData::Win32_DelayExecution: return "DelayExecution";
    case ContextSwitchData::Win32_Suspended: return "Suspended";
    case ContextSwitchData::Win32_UserRequest: return "UserRequest";
    case ContextSwitchData::Win32_WrExecutive: return "WrExecutive";
    case ContextSwitchData::Win32_WrFreePage: return "WrFreePage";
    case ContextSwitchData::Win32_WrPageIn: return "WrPageIn";
    case ContextSwitchData::Win32_WrPoolAllocation: return "WrPoolAllocation";
    case ContextSwitchData::Win32_WrDelayExecution: return "WrDelayExecution";
    case ContextSwitchData::Win32_WrSuspended: return "WrSuspended";
    case ContextSwitchData::Win32_WrUserRequest: return "WrUserRequest";
    case ContextSwitchData::Win32_WrEventPair: return "WrEventPair";
    case ContextSwitchData::Win32_WrQueue: return "WrQueue";
    case ContextSwitchData::Win32_WrLpcReceive: return "WrLpcReceive";
    case ContextSwitchData::Win32_WrLpcReply: return "WrLpcReply";
    case ContextSwitchData::Win32_WrVirtualMemory: return "WrVirtualMemory";
    case ContextSwitchData::Win32_WrPageOut: return "WrPageOut";
    case ContextSwitchData::Win32_WrRendezvous: return "WrRendezvous";
    case ContextSwitchData::Win32_WrKeyedEvent: return "WrKeyedEvent";
    case ContextSwitchData::Win32_WrTerminated: return "WrTerminated";
    case ContextSwitchData::Win32_WrProcessInSwap: return "WrProcessInSwap";
    case ContextSwitchData::Win32_WrCpuRateControl: return "WrCpuRateControl";
    case ContextSwitchData::Win32_WrCalloutStack: return "WrCalloutStack";
    case ContextSwitchData::Win32_WrKernel: return "WrKernel";
    case ContextSwitchData::Win32_WrResource: return "WrResource";
    case ContextSwitchData::Win32_WrPushLock: return "WrPushLock";
    case ContextSwitchData::Win32_WrMutex: return "WrMutex";
    case ContextSwitchData::Win32_WrQuantumEnd: return "WrQuantumEnd";
    case ContextSwitchData::Win32_WrDispatchInt: return "WrDispatchInt";
    case ContextSwitchData::Win32_WrPreempted: return "WrPreempted";
    case ContextSwitchData::Win32_WrYieldExecution: return "WrYieldExecution";
    case ContextSwitchData::Win32_WrFastMutex: return "WrFastMutex";
    case ContextSwitchData::Win32_WrGuardedMutex: return "WrGuardedMutex";
    case ContextSwitchData::Win32_WrRundown: return "WrRundown";
    case ContextSwitchData::Win32_WrAlertByThreadId: return "WrAlertByThreadId";
    case ContextSwitchData::Win32_WrDeferredPreempt: return "WrDeferredPreempt";
    case ContextSwitchData::Win32_WrPhysicalFault: return "WrPhysicalFault";
    case ContextSwitchData::Win32_WrIoRing: return "WrIoRing";
    case ContextSwitchData::Win32_WrMdlCache: return "WrMdlCache";
    case ContextSwitchData::Win32_WrRcu: return "WrRcu";
    default: return "unknown";
    }
}

const char* View::DecodeContextSwitchReason( uint8_t reason )
{
    switch( reason )
    {
    case ContextSwitchData::Win32_Executive: return "(Thread is waiting for the scheduler)";
    case ContextSwitchData::Win32_FreePage: return "(Thread is waiting for a free virtual memory page)";
    case ContextSwitchData::Win32_PageIn: return "(Thread is waiting for a virtual memory page to arrive in memory)";    
    case ContextSwitchData::Win32_PoolAllocation: return "(Thread is waiting for a system allocation)";
    case ContextSwitchData::Win32_DelayExecution: return "(Thread execution is delayed)";
    case ContextSwitchData::Win32_Suspended: return "(Thread execution is suspended)";
    case ContextSwitchData::Win32_UserRequest: return "(Thread is waiting on object - WaitForSingleObject, etc.)";
    case ContextSwitchData::Win32_WrExecutive: return "(Thread is waiting for the scheduler)";
    case ContextSwitchData::Win32_WrFreePage: return "(Thread is waiting for a free virtual memory page)";
    case ContextSwitchData::Win32_WrPageIn: return "(Thread is waiting for a virtual memory page to arrive in memory)";
    case ContextSwitchData::Win32_WrPoolAllocation: return "(Thread is waiting for a system allocation)";
    case ContextSwitchData::Win32_WrDelayExecution: return "(Thread execution is delayed)";
    case ContextSwitchData::Win32_WrSuspended: return "(Thread execution is suspended)";
    case ContextSwitchData::Win32_WrUserRequest: return "(Thread is waiting for window messages)";
    case ContextSwitchData::Win32_WrEventPair: return "(Thread is waiting for a client/server event pair)";
    case ContextSwitchData::Win32_WrQueue: return "(Thread is waiting on KQUEUE, which was empty. Usuall has to do with I/O completion.)";
    case ContextSwitchData::Win32_WrLpcReceive: return "(Thread is waiting for a local procedure call to arrive)";
    case ContextSwitchData::Win32_WrLpcReply: return "(Thread is waiting for a local procedure call reply to arrive)";
    case ContextSwitchData::Win32_WrVirtualMemory: return "(Thread is waiting for the system to allocate virtual memory)";
    case ContextSwitchData::Win32_WrPageOut: return "(Thread is waiting for a virtual memory page to be written to disk)";
    case ContextSwitchData::Win32_WrRendezvous: return "(Thread is waiting for a rendezvous.)";
    case ContextSwitchData::Win32_WrKeyedEvent: return "(Thread is waiting for a keyed event)";
    case ContextSwitchData::Win32_WrTerminated: return "(Waiting for thread termination.)";
    case ContextSwitchData::Win32_WrProcessInSwap: return "(Waiting for a process to be swapped in.)";
    case ContextSwitchData::Win32_WrCpuRateControl: return "(CPU rate limiting)";
    case ContextSwitchData::Win32_WrCalloutStack: return "(Waiting for the thread callout routine to finish due to stack being resized.)";
    case ContextSwitchData::Win32_WrKernel: return "(Waiting for a kernel operation)";
    case ContextSwitchData::Win32_WrResource: return "(Kernel is waiting for a resource, usually related to drivers loading, hardware changes or network connections.)";
    case ContextSwitchData::Win32_WrPushLock: return "(Waiting for a driver PushLock to be released.)";
    case ContextSwitchData::Win32_WrMutex: return "(Waiting for a Mutex object. This could be related to Inter Process Synchronization.)";
    case ContextSwitchData::Win32_WrQuantumEnd: return "(Thread has used up all of its quantum and another thread was ready to be scheduled.)";
    case ContextSwitchData::Win32_WrDispatchInt: return "(A software interrupt was dispatched and another thread was scheduled while processing DPCs.)";
    case ContextSwitchData::Win32_WrPreempted: return "(Thread was preempted to run another thread with higher priority.)";
    case ContextSwitchData::Win32_WrYieldExecution: return "(Thread yielded its quantum, most likely through SwitchToThread or Sleep(0).)";
    case ContextSwitchData::Win32_WrFastMutex: return "(Waiting for a Fast Mutex held by the driver. Raises the IRQ level.)";
    case ContextSwitchData::Win32_WrGuardedMutex: return "(Waiting for a Guarded Mutex held by the driver.)";
    case ContextSwitchData::Win32_WrRundown: return "(Driver waiting for rundown. Some kernel shared object is most likely being reloaded.)";
    case ContextSwitchData::Win32_WrAlertByThreadId: return "(Waiting for a synchronization primitive that does not use WaitForObject. Most likely from a SRWLock, CRITICAL_SECTION or WaitOnAdress.)";
    case ContextSwitchData::Win32_WrDeferredPreempt: return "(Thread should be preempting another, but can not due to the other being running uninterruptable code.)";
    case ContextSwitchData::Win32_WrPhysicalFault: return "(A physical fault needs to be handled.)";
    case ContextSwitchData::Win32_WrIoRing: return "(Waiting for I/O Ring operations, likely due to a call to SubmitIORing.)";
    case ContextSwitchData::Win32_WrMdlCache: return "(Waiting for the Memory Descriptor List cache, related to Virtual<>Physical I/O buffers.";
    case ContextSwitchData::Win32_WrRcu: return "(Waiting for a Read-Copy-Update synchronization.)";
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
                    TextFocused( "Readied by CPU:", RealToString( ev.WakeupCpu() ) );
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
    size_t visibleThreads = 0;
    for( const auto& t : m_threadOrder ) if( WaitStackThread( t->id ) ) visibleThreads++;
    if( visibleThreads == m_threadOrder.size() )
    {
        ImGui::TextDisabled( "(%zu)", m_threadOrder.size() );
    }
    else
    {
        ImGui::TextDisabled( "(%zi/%zu)", visibleThreads, m_threadOrder.size() );
    }
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
        ImGui::PushFont( m_bigFont );
        ImGui::Dummy( ImVec2( 0, ( ImGui::GetContentRegionAvail().y - ImGui::GetTextLineHeight() * 2 ) * 0.5f ) );
        TextCentered( ICON_FA_KIWI_BIRD );
        TextCentered( "No wait stacks to display" );
        ImGui::PopFont();
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
