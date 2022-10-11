#include <assert.h>
#include <stdio.h>
#include <inttypes.h>

#include "TracyEventDebug.hpp"
#include "../public/common/TracyQueue.hpp"

namespace tracy
{

void EventDebug( const QueueItem& ev )
{
    static FILE* f = fopen( "eventdebug.txt", "wb" );
    switch( ev.hdr.type )
    {
    case QueueType::ZoneText:
        fprintf( f, "ev %i (ZoneText)\n", ev.hdr.idx );
        break;
    case QueueType::ZoneName:
        fprintf( f, "ev %i (ZoneName)\n", ev.hdr.idx );
        break;
    case QueueType::Message:
        fprintf( f, "ev %i (Message)\n", ev.hdr.idx );
        break;
    case QueueType::MessageColor:
        fprintf( f, "ev %i (MessageColor)\n", ev.hdr.idx );
        break;
    case QueueType::MessageCallstack:
        fprintf( f, "ev %i (MessageCallstack)\n", ev.hdr.idx );
        break;
    case QueueType::MessageColorCallstack:
        fprintf( f, "ev %i (MessageColorCallstack)\n", ev.hdr.idx );
        break;
    case QueueType::MessageAppInfo:
        fprintf( f, "ev %i (MessageAppInfo)\n", ev.hdr.idx );
        break;
    case QueueType::ZoneBeginAllocSrcLoc:
        fprintf( f, "ev %i (ZoneBeginAllocSrcLoc)\n", ev.hdr.idx );
        break;
    case QueueType::ZoneBeginAllocSrcLocCallstack:
        fprintf( f, "ev %i (ZoneBeginAllocSrcLocCallstack)\n", ev.hdr.idx );
        break;
    case QueueType::CallstackSerial:
        fprintf( f, "ev %i (CallstackSerial)\n", ev.hdr.idx );
        break;
    case QueueType::Callstack:
        fprintf( f, "ev %i (Callstack)\n", ev.hdr.idx );
        break;
    case QueueType::CallstackAlloc:
        fprintf( f, "ev %i (CallstackAlloc)\n", ev.hdr.idx );
        break;
    case QueueType::CallstackSample:
        fprintf( f, "ev %i (CallstackSample)\n", ev.hdr.idx );
        break;
    case QueueType::CallstackSampleContextSwitch:
        fprintf( f, "ev %i (CallstackSampleContextSwitch)\n", ev.hdr.idx );
        break;
    case QueueType::FrameImage:
        fprintf( f, "ev %i (FrameImage)\n", ev.hdr.idx );
        break;
    case QueueType::ZoneBegin:
        fprintf( f, "ev %i (ZoneBegin)\n", ev.hdr.idx );
        fprintf( f, "\ttime = %" PRIi64 "\n", ev.zoneBeginLean.time );
        break;
    case QueueType::ZoneBeginCallstack:
        fprintf( f, "ev %i (ZoneBeginCallstack)\n", ev.hdr.idx );
        break;
    case QueueType::ZoneEnd:
        fprintf( f, "ev %i (ZoneEnd)\n", ev.hdr.idx );
        fprintf( f, "\ttime = %" PRIi64 "\n", ev.zoneEnd.time );
        break;
    case QueueType::LockWait:
        fprintf( f, "ev %i (LockWait)\n", ev.hdr.idx );
        break;
    case QueueType::LockObtain:
        fprintf( f, "ev %i (LockObtain)\n", ev.hdr.idx );
        break;
    case QueueType::LockRelease:
        fprintf( f, "ev %i (LockRelease)\n", ev.hdr.idx );
        break;
    case QueueType::LockSharedWait:
        fprintf( f, "ev %i (LockSharedWait)\n", ev.hdr.idx );
        break;
    case QueueType::LockSharedObtain:
        fprintf( f, "ev %i (LockSharedObtain)\n", ev.hdr.idx );
        break;
    case QueueType::LockSharedRelease:
        fprintf( f, "ev %i (LockSharedRelease)\n", ev.hdr.idx );
        break;
    case QueueType::LockName:
        fprintf( f, "ev %i (LockName)\n", ev.hdr.idx );
        break;
    case QueueType::MemAlloc:
        fprintf( f, "ev %i (MemAlloc)\n", ev.hdr.idx );
        break;
    case QueueType::MemAllocNamed:
        fprintf( f, "ev %i (MemAllocNamed)\n", ev.hdr.idx );
        break;
    case QueueType::MemFree:
        fprintf( f, "ev %i (MemFree)\n", ev.hdr.idx );
        break;
    case QueueType::MemFreeNamed:
        fprintf( f, "ev %i (MemFreeNamed)\n", ev.hdr.idx );
        break;
    case QueueType::MemAllocCallstack:
        fprintf( f, "ev %i (MemAllocCallstack)\n", ev.hdr.idx );
        break;
    case QueueType::MemAllocCallstackNamed:
        fprintf( f, "ev %i (MemAllocCallstackNamed)\n", ev.hdr.idx );
        break;
    case QueueType::MemFreeCallstack:
        fprintf( f, "ev %i (MemFreeCallstack)\n", ev.hdr.idx );
        break;
    case QueueType::MemFreeCallstackNamed:
        fprintf( f, "ev %i (MemFreeCallstackNamed)\n", ev.hdr.idx );
        break;
    case QueueType::GpuZoneBegin:
        fprintf( f, "ev %i (GpuZoneBegin)\n", ev.hdr.idx );
        break;
    case QueueType::GpuZoneBeginCallstack:
        fprintf( f, "ev %i (GpuZoneBeginCallstack)\n", ev.hdr.idx );
        break;
    case QueueType::GpuZoneBeginAllocSrcLoc:
        fprintf( f, "ev %i (GpuZoneBeginAllocSrcLoc)\n", ev.hdr.idx );
        break;
    case QueueType::GpuZoneBeginAllocSrcLocCallstack:
        fprintf( f, "ev %i (GpuZoneBeginAllocSrcLocCallstack)\n", ev.hdr.idx );
        break;
    case QueueType::GpuZoneEnd:
        fprintf( f, "ev %i (GpuZoneEnd)\n", ev.hdr.idx );
        break;
    case QueueType::GpuZoneBeginSerial:
        fprintf( f, "ev %i (GpuZoneBeginSerial)\n", ev.hdr.idx );
        break;
    case QueueType::GpuZoneBeginCallstackSerial:
        fprintf( f, "ev %i (GpuZoneBeginCallstackSerial)\n", ev.hdr.idx );
        break;
    case QueueType::GpuZoneBeginAllocSrcLocSerial:
        fprintf( f, "ev %i (GpuZoneBeginAllocSrcLocSerial)\n", ev.hdr.idx );
        break;
    case QueueType::GpuZoneBeginAllocSrcLocCallstackSerial:
        fprintf( f, "ev %i (GpuZoneBeginAllocSrcLocCallstackSerial)\n", ev.hdr.idx );
        break;
    case QueueType::GpuZoneEndSerial:
        fprintf( f, "ev %i (GpuZoneEndSerial)\n", ev.hdr.idx );
        break;
    case QueueType::PlotDataInt:
        fprintf( f, "ev %i (PlotDataInt)\n", ev.hdr.idx );
        break;
    case QueueType::PlotDataFloat:
        fprintf( f, "ev %i (PlotDataFloat)\n", ev.hdr.idx );
        break;
    case QueueType::PlotDataDouble:
        fprintf( f, "ev %i (PlotDataDouble)\n", ev.hdr.idx );
        break;
    case QueueType::ContextSwitch:
        fprintf( f, "ev %i (ContextSwitch)\n", ev.hdr.idx );
        break;
    case QueueType::ThreadWakeup:
        fprintf( f, "ev %i (ThreadWakeup)\n", ev.hdr.idx );
        break;
    case QueueType::GpuTime:
        fprintf( f, "ev %i (GpuTime)\n", ev.hdr.idx );
        break;
    case QueueType::GpuContextName:
        fprintf( f, "ev %i (GpuContextName)\n", ev.hdr.idx );
        break;
    case QueueType::CallstackFrameSize:
        fprintf( f, "ev %i (CallstackFrameSize)\n", ev.hdr.idx );
        break;
    case QueueType::SymbolInformation:
        fprintf( f, "ev %i (SymbolInformation)\n", ev.hdr.idx );
        break;
    case QueueType::FiberEnter:
        fprintf( f, "ev %i (FiberEnter)\n", ev.hdr.idx );
        fprintf( f, "\ttime   = %" PRIi64 "\n", ev.fiberEnter.time );
        fprintf( f, "\tfiber  = %" PRIu64 "\n", ev.fiberEnter.fiber );
        fprintf( f, "\tthread = %" PRIu32 "\n", ev.fiberEnter.thread );
        break;
    case QueueType::FiberLeave:
        fprintf( f, "ev %i (FiberLeave)\n", ev.hdr.idx );
        fprintf( f, "\ttime   = %" PRIi64 "\n", ev.fiberLeave.time );
        fprintf( f, "\tthread = %" PRIu32 "\n", ev.fiberLeave.thread );
        break;
    case QueueType::Terminate:
        fprintf( f, "ev %i (Terminate)\n", ev.hdr.idx );
        break;
    case QueueType::KeepAlive:
        fprintf( f, "ev %i (KeepAlive)\n", ev.hdr.idx );
        break;
    case QueueType::ThreadContext:
        fprintf( f, "ev %i (ThreadContext)\n", ev.hdr.idx );
        fprintf( f, "\tthread = %" PRIu32 "\n", ev.threadCtx.thread );
        break;
    case QueueType::GpuCalibration:
        fprintf( f, "ev %i (GpuCalibration)\n", ev.hdr.idx );
        break;
    case QueueType::Crash:
        fprintf( f, "ev %i (Crash)\n", ev.hdr.idx );
        break;
    case QueueType::CrashReport:
        fprintf( f, "ev %i (CrashReport)\n", ev.hdr.idx );
        break;
    case QueueType::ZoneValidation:
        fprintf( f, "ev %i (ZoneValidation)\n", ev.hdr.idx );
        fprintf( f, "\tid = %" PRIu32 "\n", ev.zoneValidation.id );
        break;
    case QueueType::ZoneColor:
        fprintf( f, "ev %i (ZoneColor)\n", ev.hdr.idx );
        break;
    case QueueType::ZoneValue:
        fprintf( f, "ev %i (ZoneValue)\n", ev.hdr.idx );
        break;
    case QueueType::FrameMarkMsg:
        fprintf( f, "ev %i (FrameMarkMsg)\n", ev.hdr.idx );
        break;
    case QueueType::FrameMarkMsgStart:
        fprintf( f, "ev %i (FrameMarkMsgStart)\n", ev.hdr.idx );
        break;
    case QueueType::FrameMarkMsgEnd:
        fprintf( f, "ev %i (FrameMarkMsgEnd)\n", ev.hdr.idx );
        break;
    case QueueType::SourceLocation:
        fprintf( f, "ev %i (SourceLocation)\n", ev.hdr.idx );
        break;
    case QueueType::LockAnnounce:
        fprintf( f, "ev %i (LockAnnounce)\n", ev.hdr.idx );
        break;
    case QueueType::LockTerminate:
        fprintf( f, "ev %i (LockTerminate)\n", ev.hdr.idx );
        break;
    case QueueType::LockMark:
        fprintf( f, "ev %i (LockMark)\n", ev.hdr.idx );
        break;
    case QueueType::MessageLiteral:
        fprintf( f, "ev %i (MessageLiteral)\n", ev.hdr.idx );
        break;
    case QueueType::MessageLiteralColor:
        fprintf( f, "ev %i (MessageLiteralColor)\n", ev.hdr.idx );
        break;
    case QueueType::MessageLiteralCallstack:
        fprintf( f, "ev %i (MessageLiteralCallstack)\n", ev.hdr.idx );
        break;
    case QueueType::MessageLiteralColorCallstack:
        fprintf( f, "ev %i (MessageLiteralColorCallstack)\n", ev.hdr.idx );
        break;
    case QueueType::GpuNewContext:
        fprintf( f, "ev %i (GpuNewContext)\n", ev.hdr.idx );
        break;
    case QueueType::CallstackFrame:
        fprintf( f, "ev %i (CallstackFrame)\n", ev.hdr.idx );
        break;
    case QueueType::SysTimeReport:
        fprintf( f, "ev %i (SysTimeReport)\n", ev.hdr.idx );
        fprintf( f, "\ttime    = %" PRIi64 "\n", ev.sysTime.time );
        fprintf( f, "\tsysTime = %f\n", ev.sysTime.sysTime );
        break;
    case QueueType::TidToPid:
        fprintf( f, "ev %i (TidToPid)\n", ev.hdr.idx );
        break;
    case QueueType::HwSampleCpuCycle:
        fprintf( f, "ev %i (HwSampleCpuCycle)\n", ev.hdr.idx );
        break;
    case QueueType::HwSampleInstructionRetired:
        fprintf( f, "ev %i (HwSampleInstructionRetired)\n", ev.hdr.idx );
        break;
    case QueueType::HwSampleCacheReference:
        fprintf( f, "ev %i (HwSampleCacheReference)\n", ev.hdr.idx );
        break;
    case QueueType::HwSampleCacheMiss:
        fprintf( f, "ev %i (HwSampleCacheMiss)\n", ev.hdr.idx );
        break;
    case QueueType::HwSampleBranchRetired:
        fprintf( f, "ev %i (HwSampleBranchRetired)\n", ev.hdr.idx );
        break;
    case QueueType::HwSampleBranchMiss:
        fprintf( f, "ev %i (HwSampleBranchMiss)\n", ev.hdr.idx );
        break;
    case QueueType::PlotConfig:
        fprintf( f, "ev %i (PlotConfig)\n", ev.hdr.idx );
        break;
    case QueueType::ParamSetup:
        fprintf( f, "ev %i (ParamSetup)\n", ev.hdr.idx );
        break;
    case QueueType::AckServerQueryNoop:
        fprintf( f, "ev %i (AckServerQueryNoop)\n", ev.hdr.idx );
        break;
    case QueueType::AckSourceCodeNotAvailable:
        fprintf( f, "ev %i (AckSourceCodeNotAvailable)\n", ev.hdr.idx );
        break;
    case QueueType::AckSymbolCodeNotAvailable:
        fprintf( f, "ev %i (AckSymbolCodeNotAvailable)\n", ev.hdr.idx );
        break;
    case QueueType::CpuTopology:
        fprintf( f, "ev %i (CpuTopology)\n", ev.hdr.idx );
        fprintf( f, "\tpackage = %" PRIu32 "\n", ev.cpuTopology.package );
        fprintf( f, "\tcore    = %" PRIu32 "\n", ev.cpuTopology.core );
        fprintf( f, "\tthread  = %" PRIu32 "\n", ev.cpuTopology.thread );
        break;
    case QueueType::SingleStringData:
        fprintf( f, "ev %i (SingleStringData)\n", ev.hdr.idx );
        break;
    case QueueType::SecondStringData:
        fprintf( f, "ev %i (SecondStringData)\n", ev.hdr.idx );
        break;
    case QueueType::MemNamePayload:
        fprintf( f, "ev %i (MemNamePayload)\n", ev.hdr.idx );
        break;
    case QueueType::StringData:
        fprintf( f, "ev %i (StringData)\n", ev.hdr.idx );
        break;
    case QueueType::ThreadName:
        fprintf( f, "ev %i (ThreadName)\n", ev.hdr.idx );
        break;
    case QueueType::PlotName:
        fprintf( f, "ev %i (PlotName)\n", ev.hdr.idx );
        break;
    case QueueType::SourceLocationPayload:
        fprintf( f, "ev %i (SourceLocationPayload)\n", ev.hdr.idx );
        break;
    case QueueType::CallstackPayload:
        fprintf( f, "ev %i (CallstackPayload)\n", ev.hdr.idx );
        break;
    case QueueType::CallstackAllocPayload:
        fprintf( f, "ev %i (CallstackAllocPayload)\n", ev.hdr.idx );
        break;
    case QueueType::FrameName:
        fprintf( f, "ev %i (FrameName)\n", ev.hdr.idx );
        break;
    case QueueType::FrameImageData:
        fprintf( f, "ev %i (FrameImageData)\n", ev.hdr.idx );
        break;
    case QueueType::ExternalName:
        fprintf( f, "ev %i (ExternalName)\n", ev.hdr.idx );
        break;
    case QueueType::ExternalThreadName:
        fprintf( f, "ev %i (ExternalThreadName)\n", ev.hdr.idx );
        break;
    case QueueType::SymbolCode:
        fprintf( f, "ev %i (SymbolCode)\n", ev.hdr.idx );
        break;
    case QueueType::SourceCode:
        fprintf( f, "ev %i (SourceCode)\n", ev.hdr.idx );
        break;
    case QueueType::FiberName:
        fprintf( f, "ev %i (FiberName)\n", ev.hdr.idx );
        break;
    default:
        assert( false );
        break;
    }
    fflush( f );
}

}
