#ifndef __TRACYVIEW_HPP__
#define __TRACYVIEW_HPP__

#include <array>
#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "imgui.h"

#include "TracyBadVersion.hpp"
#include "TracyBuzzAnim.hpp"
#include "TracyDecayValue.hpp"
#include "TracyFileWrite.hpp"
#include "TracyShortPtr.hpp"
#include "TracySourceContents.hpp"
#include "TracyTimelineController.hpp"
#include "TracyUserData.hpp"
#include "TracyUtility.hpp"
#include "TracyVector.hpp"
#include "TracyViewData.hpp"
#include "TracyWorker.hpp"
#include "tracy_robin_hood.h"

namespace tracy
{

constexpr const char* GpuContextNames[] = {
    "Invalid",
    "OpenGL",
    "Vulkan",
    "OpenCL",
    "Direct3D 12",
    "Direct3D 11"
};

struct MemoryPage;
class FileRead;
class SourceView;

class View
{
    struct Animation
    {
        bool active = false;
        int64_t start0, start1;
        int64_t end0, end1;
        double progress;
    };

    struct Region
    {
        bool active = false;
        int64_t start;
        int64_t end;
    };

    struct ZoneTimeData
    {
        int64_t time;
        uint64_t count;
    };

    enum class AccumulationMode
    {
        SelfOnly,
        AllChildren,
        NonReentrantChildren
    };

    struct StatisticsCache
    {
        RangeSlim range;
        AccumulationMode accumulationMode;
        size_t sourceCount;
        size_t count;
        int64_t total;
    };

public:
    struct PlotView
    {
        double min;
        double max;
    };

    using SetTitleCallback = void(*)( const char* );
    using SetScaleCallback = void(*)( float, ImFont*&, ImFont*&, ImFont*& );
    using AttentionCallback = void(*)();

    View( void(*cbMainThread)(std::function<void()>, bool), const char* addr, uint16_t port, ImFont* fixedWidth, ImFont* smallFont, ImFont* bigFont, SetTitleCallback stcb, SetScaleCallback sscb, AttentionCallback acb );
    View( void(*cbMainThread)(std::function<void()>, bool), FileRead& f, ImFont* fixedWidth, ImFont* smallFont, ImFont* bigFont, SetTitleCallback stcb, SetScaleCallback sscb, AttentionCallback acb );
    ~View();

    bool Draw();
    bool WasActive() const;

    void NotifyRootWindowSize( float w, float h ) { m_rootWidth = w; m_rootHeight = h; }
    void ViewSource( const char* fileName, int line );
    void ViewSymbol( const char* fileName, int line, uint64_t baseAddr, uint64_t symAddr );
    bool ViewDispatch( const char* fileName, int line, uint64_t symAddr );

    bool ReconnectRequested() const { return m_reconnectRequested; }
    std::string GetAddress() const { return m_worker.GetAddr(); }
    uint16_t GetPort() const { return m_worker.GetPort(); }

    const char* SourceSubstitution( const char* srcFile ) const;

    void ShowSampleParents( uint64_t symAddr, bool withInlines ) { m_sampleParents.symAddr = symAddr; m_sampleParents.sel = 0; m_sampleParents.withInlines = withInlines; }

    ViewData& GetViewData() { return m_vd; }
    const ViewData& GetViewData() const { return m_vd; }

    ShortenName GetShortenName() const { return m_shortenName; }
    int GetNextGpuIdx() { return m_gpuIdx++; }

    void HighlightThread( uint64_t thread );
    void ZoomToRange( int64_t start, int64_t end, bool pause = true );
    bool DrawPlot( PlotData& plot, double pxns, int& offset, const ImVec2& wpos, bool hover, float yMin, float yMax );
    bool DrawThread( const ThreadData& thread, double pxns, int& offset, const ImVec2& wpos, bool hover, float yMin, float yMax, bool ghostMode );
    void DrawThreadMessages( const ThreadData& thread, double pxns, int offset, const ImVec2& wpos, bool hover );
    void DrawThreadOverlays( const ThreadData& thread, const ImVec2& ul, const ImVec2& dr );
    bool DrawGpu( const GpuCtxData& gpu, double pxns, int& offset, const ImVec2& wpos, bool hover, float yMin, float yMax );
    bool DrawCpuData( double pxns, int& offset, const ImVec2& wpos, bool hover, float yMin, float yMax );

    bool m_showRanges = false;
    Range m_statRange;
    Range m_waitStackRange;

private:
    enum class ShortcutAction : uint8_t
    {
        None,
        OpenFind
    };

    enum { InvalidId = 0xFFFFFFFF };

    struct MemPathData
    {
        uint32_t cnt;
        uint64_t mem;
    };

    enum class ViewMode
    {
        Paused,
        LastFrames,
        LastRange
    };

    enum class MemRange
    {
        Full,
        Active,
        Inactive
    };

    struct KeyboardNavigation
    {
        enum Direction
        {
            // Pan left / right
            Left,
            Right,
            // Zoom in / out
            In,
            Out
        };

        constexpr static auto DirectionToKeyMap = std::array<ImGuiKey, 4> { ImGuiKey_A, ImGuiKey_D, ImGuiKey_W, ImGuiKey_S };
        constexpr static auto StartRangeMod = std::array<int, 4> { -1, 1, 1, -1 };
        constexpr static auto EndRangeMod = std::array<int, 4> { -1, 1, -1, 1 };

        std::array<float, 4> m_scrollInertia;
    };

    struct ZoneColorData
    {
        uint32_t color;
        uint32_t accentColor;
        float thickness;
        bool highlight;
    };

    struct SymList
    {
        uint64_t symAddr;
        uint32_t incl, excl;
        uint32_t count;
    };

    void InitMemory();
    void InitTextEditor( ImFont* font );

    bool DrawImpl();
    void DrawNotificationArea();
    bool DrawConnection();
    void DrawFrames();
    void DrawTimelineFramesHeader();
    void DrawTimelineFrames( const FrameData& frames );
    void DrawTimeline();
    void DrawContextSwitches( const ContextSwitch* ctx, const Vector<SampleData>& sampleData, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int offset, int endOffset, bool isFiber );
    void DrawSamples( const Vector<SampleData>& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int offset );
#ifndef TRACY_NO_STATISTICS
    int DispatchGhostLevel( const Vector<GhostZone>& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int offset, int depth, float yMin, float yMax, uint64_t tid );
    int DrawGhostLevel( const Vector<GhostZone>& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int offset, int depth, float yMin, float yMax, uint64_t tid );
    int SkipGhostLevel( const Vector<GhostZone>& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int offset, int depth, float yMin, float yMax, uint64_t tid );
#endif
    int DispatchZoneLevel( const Vector<short_ptr<ZoneEvent>>& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int offset, int depth, float yMin, float yMax, uint64_t tid );
    template<typename Adapter, typename V>
    int DrawZoneLevel( const V& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int offset, int depth, float yMin, float yMax, uint64_t tid );
    template<typename Adapter, typename V>
    int SkipZoneLevel( const V& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int offset, int depth, float yMin, float yMax, uint64_t tid );
    int DispatchGpuZoneLevel( const Vector<short_ptr<GpuEvent>>& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int offset, int depth, uint64_t thread, float yMin, float yMax, int64_t begin, int drift );
    template<typename Adapter, typename V>
    int DrawGpuZoneLevel( const V& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int offset, int depth, uint64_t thread, float yMin, float yMax, int64_t begin, int drift );
    template<typename Adapter, typename V>
    int SkipGpuZoneLevel( const V& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int offset, int depth, uint64_t thread, float yMin, float yMax, int64_t begin, int drift );
    void DrawLockHeader( uint32_t id, const LockMap& lockmap, const SourceLocation& srcloc, bool hover, ImDrawList* draw, const ImVec2& wpos, float w, float ty, float offset, uint8_t tid );
    int DrawLocks( uint64_t tid, bool hover, double pxns, const ImVec2& wpos, int offset, LockHighlight& highlight, float yMin, float yMax );
    void DrawPlotPoint( const ImVec2& wpos, float x, float y, int offset, uint32_t color, bool hover, bool hasPrev, const PlotItem* item, double prev, bool merged, PlotType type, PlotValueFormatting format, float PlotHeight, uint64_t name );
    void DrawPlotPoint( const ImVec2& wpos, float x, float y, int offset, uint32_t color, bool hover, bool hasPrev, double val, double prev, bool merged, PlotValueFormatting format, float PlotHeight );
    void DrawOptions();
    void DrawMessages();
    void DrawMessageLine( const MessageData& msg, bool hasCallstack, int& idx );
    void DrawFindZone();
    void AccumulationModeComboBox();
    void DrawStatistics();
    void DrawSamplesStatistics(Vector<SymList>& data, int64_t timeRange, AccumulationMode accumulationMode);
    void DrawMemory();
    void DrawAllocList();
    void DrawCompare();
    void DrawCallstackWindow();
    void DrawCallstackTable( uint32_t callstack, bool globalEntriesButton );
    void DrawMemoryAllocWindow();
    void DrawInfo();
    void DrawTextEditor();
    void DrawLockInfoWindow();
    void DrawPlayback();
    void DrawCpuDataWindow();
    void DrawSelectedAnnotation();
    void DrawAnnotationList();
    void DrawSampleParents();
    void DrawRanges();
    void DrawRangeEntry( Range& range, const char* label, uint32_t color, const char* popupLabel, int id );
    void DrawSourceTooltip( const char* filename, uint32_t line, int before = 3, int after = 3, bool separateTooltip = true );
    void DrawWaitStacks();

    void ListMemData( std::vector<const MemEvent*>& vec, std::function<void(const MemEvent*)> DrawAddress, const char* id = nullptr, int64_t startTime = -1, uint64_t pool = 0 );

    unordered_flat_map<uint32_t, MemPathData> GetCallstackPaths( const MemData& mem, MemRange memRange ) const;
    unordered_flat_map<uint64_t, MemCallstackFrameTree> GetCallstackFrameTreeBottomUp( const MemData& mem ) const;
    unordered_flat_map<uint64_t, MemCallstackFrameTree> GetCallstackFrameTreeTopDown( const MemData& mem ) const;
    void DrawFrameTreeLevel( const unordered_flat_map<uint64_t, MemCallstackFrameTree>& tree, int& idx );
    void DrawZoneList( int id, const Vector<short_ptr<ZoneEvent>>& zones );

    unordered_flat_map<uint64_t, CallstackFrameTree> GetCallstackFrameTreeBottomUp( const unordered_flat_map<uint32_t, uint64_t>& stacks, bool group ) const;
    unordered_flat_map<uint64_t, CallstackFrameTree> GetCallstackFrameTreeTopDown( const unordered_flat_map<uint32_t, uint64_t>& stacks, bool group ) const;
    void DrawFrameTreeLevel( const unordered_flat_map<uint64_t, CallstackFrameTree>& tree, int& idx );

    unordered_flat_map<uint64_t, CallstackFrameTree> GetParentsCallstackFrameTreeBottomUp( const unordered_flat_map<uint32_t, uint32_t>& stacks, bool group ) const;
    unordered_flat_map<uint64_t, CallstackFrameTree> GetParentsCallstackFrameTreeTopDown( const unordered_flat_map<uint32_t, uint32_t>& stacks, bool group ) const;
    void DrawParentsFrameTreeLevel( const unordered_flat_map<uint64_t, CallstackFrameTree>& tree, int& idx );

    void DrawInfoWindow();
    void DrawZoneInfoWindow();
    void DrawGpuInfoWindow();

    template<typename Adapter, typename V>
    void DrawZoneInfoChildren( const V& children, int64_t ztime );
    template<typename Adapter, typename V>
    void DrawGpuInfoChildren( const V& children, int64_t ztime );

    void HandleRange( Range& range, int64_t timespan, const ImVec2& wpos, float w );
    void HandleTimelineMouse( int64_t timespan, const ImVec2& wpos, float w, double& pxns );
    void HandleTimelineKeyboard( int64_t timespan, const ImVec2& wpos, float w );

    void AddAnnotation( int64_t start, int64_t end );

    uint32_t GetThreadColor( uint64_t thread, int depth );
    uint32_t GetSrcLocColor( const SourceLocation& srcloc, int depth );
    uint32_t GetRawSrcLocColor( const SourceLocation& srcloc, int depth );
    uint32_t GetZoneColor( const ZoneEvent& ev, uint64_t thread, int depth );
    uint32_t GetZoneColor( const GpuEvent& ev );
    ZoneColorData GetZoneColorData( const ZoneEvent& ev, uint64_t thread, int depth );
    ZoneColorData GetZoneColorData( const GpuEvent& ev );

    void ZoomToZone( const ZoneEvent& ev );
    void ZoomToZone( const GpuEvent& ev );
    void ZoomToPrevFrame();
    void ZoomToNextFrame();
    void CenterAtTime( int64_t t );

    void ShowZoneInfo( const ZoneEvent& ev );
    void ShowZoneInfo( const GpuEvent& ev, uint64_t thread );

    void ZoneTooltip( const ZoneEvent& ev );
    void ZoneTooltip( const GpuEvent& ev );
    void CallstackTooltip( uint32_t idx );
    void CallstackTooltipContents( uint32_t idx );
    void CrashTooltip();

    const ZoneEvent* GetZoneParent( const ZoneEvent& zone ) const;
    const ZoneEvent* GetZoneParent( const ZoneEvent& zone, uint64_t tid ) const;
    const ZoneEvent* GetZoneChild( const ZoneEvent& zone, int64_t time ) const;
    bool IsZoneReentry( const ZoneEvent& zone ) const;
    bool IsZoneReentry( const ZoneEvent& zone, uint64_t tid ) const;
    const GpuEvent* GetZoneParent( const GpuEvent& zone ) const;
    const ThreadData* GetZoneThreadData( const ZoneEvent& zone ) const;
    uint64_t GetZoneThread( const ZoneEvent& zone ) const;
    uint64_t GetZoneThread( const GpuEvent& zone ) const;
    const GpuCtxData* GetZoneCtx( const GpuEvent& zone ) const;
    bool FindMatchingZone( int prev0, int prev1, int flags );
    const ZoneEvent* FindZoneAtTime( uint64_t thread, int64_t time ) const;
    uint64_t GetFrameNumber( const FrameData& fd, int i, uint64_t offset ) const;
    const char* GetFrameText( const FrameData& fd, int i, uint64_t ftime, uint64_t offset ) const;
    const char* GetFrameSetName( const FrameData& fd ) const;
    static const char* GetFrameSetName( const FrameData& fd, const Worker& worker );

#ifndef TRACY_NO_STATISTICS
    void FindZones();
    void FindZonesCompare();
#endif

    std::vector<MemoryPage> GetMemoryPages() const;

    void SmallCallstackButton( const char* name, uint32_t callstack, int& idx, bool tooltip = true );
    void DrawCallstackCalls( uint32_t callstack, uint16_t limit ) const;
    void SetViewToLastFrames();
    int64_t GetZoneChildTime( const ZoneEvent& zone );
    int64_t GetZoneChildTime( const GpuEvent& zone );
    int64_t GetZoneChildTimeFast( const ZoneEvent& zone );
    int64_t GetZoneChildTimeFastClamped( const ZoneEvent& zone, int64_t t0, int64_t t1 );
    int64_t GetZoneSelfTime( const ZoneEvent& zone );
    int64_t GetZoneSelfTime( const GpuEvent& zone );
    bool GetZoneRunningTime( const ContextSwitch* ctx, const ZoneEvent& ev, int64_t& time, uint64_t& cnt );
    const char* GetThreadContextData( uint64_t thread, bool& local, bool& untracked, const char*& program );

    tracy_force_inline void CalcZoneTimeData( unordered_flat_map<int16_t, ZoneTimeData>& data, int64_t& ztime, const ZoneEvent& zone );
    tracy_force_inline void CalcZoneTimeData( const ContextSwitch* ctx, unordered_flat_map<int16_t, ZoneTimeData>& data, int64_t& ztime, const ZoneEvent& zone );
    template<typename Adapter, typename V>
    void CalcZoneTimeDataImpl( const V& children, unordered_flat_map<int16_t, ZoneTimeData>& data, int64_t& ztime, const ZoneEvent& zone );
    template<typename Adapter, typename V>
    void CalcZoneTimeDataImpl( const V& children, const ContextSwitch* ctx, unordered_flat_map<int16_t, ZoneTimeData>& data, int64_t& ztime, const ZoneEvent& zone );

    void SetPlaybackFrame( uint32_t idx );
    bool Save( const char* fn, FileWrite::Compression comp, int zlevel, bool buildDict );

    void Attention( bool& alreadyDone );

    unordered_flat_map<uint64_t, bool> m_visibleMsgThread;
    unordered_flat_map<uint64_t, bool> m_waitStackThread;
    unordered_flat_map<const void*, int> m_gpuDrift;
    unordered_flat_map<const PlotData*, PlotView> m_plotView;
    Vector<const ThreadData*> m_threadOrder;
    Vector<float> m_threadDnd;

    tracy_force_inline bool& VisibleMsgThread( uint64_t thread )
    {
        auto it = m_visibleMsgThread.find( thread );
        if( it == m_visibleMsgThread.end() )
        {
            it = m_visibleMsgThread.emplace( thread, true ).first;
        }
        return it->second;
    }

    tracy_force_inline bool& WaitStackThread( uint64_t thread )
    {
        auto it = m_waitStackThread.find( thread );
        if( it == m_waitStackThread.end() )
        {
            it = m_waitStackThread.emplace( thread, true ).first;
        }
        return it->second;
    }

    tracy_force_inline int& GpuDrift( const void* ptr )
    {
        auto it = m_gpuDrift.find( ptr );
        if( it == m_gpuDrift.end() )
        {
            it = m_gpuDrift.emplace( ptr, 0 ).first;
        }
        return it->second;
    }

    static int64_t AdjustGpuTime( int64_t time, int64_t begin, int drift );

    static const char* DecodeContextSwitchState( uint8_t state );
    static const char* DecodeContextSwitchStateCode( uint8_t state );
    static const char* DecodeContextSwitchReason( uint8_t reason );
    static const char* DecodeContextSwitchReasonCode( uint8_t reason );

    tracy_force_inline bool& Vis( const void* ptr )
    {
        auto it = m_visMap.find( ptr );
        if( it == m_visMap.end() ) it = m_visMap.emplace( ptr, true ).first;
        return it->second;
    }

    Worker m_worker;
    std::string m_filename, m_filenameStaging;
    bool m_staticView;
    ViewMode m_viewMode;
    bool m_viewModeHeuristicTry = false;
    DecayValue<bool> m_forceConnectionPopup = false;
    uint64_t m_totalMemory;

    ViewData m_vd;
    TimelineController m_tc;
    KeyboardNavigation m_kbNavCtrl;

    const ZoneEvent* m_zoneInfoWindow = nullptr;
    const ZoneEvent* m_zoneHighlight;
    DecayValue<int16_t> m_zoneSrcLocHighlight = 0;
    LockHighlight m_lockHighlight { -1 };
    LockHighlight m_nextLockHighlight;
    DecayValue<const MessageData*> m_msgHighlight = nullptr;
    DecayValue<uint32_t> m_lockHoverHighlight = InvalidId;
    DecayValue<const MessageData*> m_msgToFocus = nullptr;
    const GpuEvent* m_gpuInfoWindow = nullptr;
    const GpuEvent* m_gpuHighlight;
    uint64_t m_gpuInfoWindowThread;
    uint32_t m_callstackInfoWindow = 0;
    int64_t m_memoryAllocInfoWindow = -1;
    uint64_t m_memoryAllocInfoPool = 0;
    int64_t m_memoryAllocHover = -1;
    uint64_t m_memoryAllocHoverPool = 0;
    int m_memoryAllocHoverWait = 0;
    const FrameData* m_frames;
    uint32_t m_lockInfoWindow = InvalidId;
    const ZoneEvent* m_zoneHover = nullptr;
    DecayValue<const ZoneEvent*> m_zoneHover2 = nullptr;
    int m_frameHover = -1;
    bool m_messagesScrollBottom;
    ImGuiTextFilter m_messageFilter;
    bool m_showMessageImages = false;
    int m_visibleMessages = 0;
    size_t m_prevMessages = 0;
    bool m_messagesShowCallstack = false;
    Vector<uint32_t> m_msgList;
    bool m_disconnectIssued = false;
    DecayValue<uint64_t> m_drawThreadMigrations = 0;
    DecayValue<uint64_t> m_drawThreadHighlight = 0;
    Annotation* m_selectedAnnotation = nullptr;
    bool m_reactToCrash = false;
    bool m_reactToLostConnection = false;

    ImGuiTextFilter m_statisticsFilter;
    ImGuiTextFilter m_statisticsImageFilter;

    Region m_highlight;
    Region m_highlightZoom;

    DecayValue<uint64_t> m_cpuDataThread = 0;
    uint64_t m_gpuThread = 0;
    int64_t m_gpuStart = 0;
    int64_t m_gpuEnd = 0;

    bool m_showOptions = false;
    bool m_showMessages = false;
    bool m_showStatistics = false;
    bool m_showInfo = false;
    bool m_showPlayback = false;
    bool m_showCpuDataWindow = false;
    bool m_showAnnotationList = false;
    bool m_showWaitStacks = false;

    AccumulationMode m_statAccumulationMode = AccumulationMode::SelfOnly;
    bool m_statSampleTime = true;
    int m_statMode = 0;
    int m_statSampleLocation = 2;
    bool m_statHideUnknown = true;
    bool m_showAllSymbols = false;
    int m_showCallstackFrameAddress = 0;
    bool m_showUnknownFrames = true;
    bool m_statSeparateInlines = false;
    bool m_statShowAddress = false;
    bool m_statShowKernel = true;
    bool m_groupChildrenLocations = false;
    bool m_allocTimeRelativeToZone = true;
    bool m_ctxSwitchTimeRelativeToZone = true;
    bool m_messageTimeRelativeToZone = true;
    bool m_messagesExcludeChildren = true;
    uint64_t m_zoneInfoMemPool = 0;
    int m_waitStack = 0;
    int m_waitStackMode = 0;
    bool m_groupWaitStackBottomUp = true;
    bool m_groupWaitStackTopDown = true;

    ShortcutAction m_shortcut = ShortcutAction::None;
    ShortenName m_shortenName = ShortenName::NoSpaceAndNormalize;
    Animation m_zoomAnim;
    BuzzAnim<int> m_callstackBuzzAnim;
    BuzzAnim<int> m_sampleParentBuzzAnim;
    BuzzAnim<int> m_callstackTreeBuzzAnim;
    BuzzAnim<const void*> m_zoneinfoBuzzAnim;
    BuzzAnim<int> m_findZoneBuzzAnim;
    BuzzAnim<int16_t> m_optionsLockBuzzAnim;
    BuzzAnim<uint32_t> m_lockInfoAnim;
    BuzzAnim<uint32_t> m_statBuzzAnim;

    Vector<const ZoneEvent*> m_zoneInfoStack;
    Vector<const GpuEvent*> m_gpuInfoStack;

    SourceContents m_srcHintCache;
    std::unique_ptr<SourceView> m_sourceView;
    const char* m_sourceViewFile;
    bool m_uarchSet = false;

    ImFont* m_smallFont;
    ImFont* m_bigFont;
    ImFont* m_fixedFont;

    float m_rootWidth, m_rootHeight;
    SetTitleCallback m_stcb;
    bool m_titleSet = false;
    SetScaleCallback m_sscb;
    AttentionCallback m_acb;

    float m_notificationTime = 0;
    std::string m_notificationText;

    bool m_groupCallstackTreeByNameBottomUp = true;
    bool m_groupCallstackTreeByNameTopDown = true;
    MemRange m_memRangeBottomUp = MemRange::Full;
    MemRange m_memRangeTopDown = MemRange::Full;

    enum class SaveThreadState
    {
        Inert,
        Saving,
        NeedsJoin
    };

    enum
    {
        FindMatchingZoneFlagDefault = 0,
        FindMatchingZoneFlagSourceFile = (1 << 0),
        FindMatchingZoneFlagLineNum = (1 << 1),
    };

    std::atomic<SaveThreadState> m_saveThreadState { SaveThreadState::Inert };
    std::thread m_saveThread;
    std::atomic<size_t> m_srcFileBytes { 0 };
    std::atomic<size_t> m_dstFileBytes { 0 };

    void* m_frameTexture = nullptr;
    const void* m_frameTexturePtr = nullptr;

    void* m_frameTextureConn = nullptr;
    const void* m_frameTextureConnPtr = nullptr;

    std::vector<std::unique_ptr<Annotation>> m_annotations;
    UserData m_userData;

    bool m_wasActive = false;
    bool m_reconnectRequested = false;
    bool m_firstFrame = true;
    std::chrono::time_point<std::chrono::high_resolution_clock> m_firstFrameTime;
    float m_yDelta;

    std::vector<SourceRegex> m_sourceSubstitutions;
    bool m_sourceRegexValid = true;

    RangeSlim m_setRangePopup;
    bool m_setRangePopupOpen = false;

    unordered_flat_map<int16_t, StatisticsCache> m_statCache;
    unordered_flat_map<int16_t, StatisticsCache> m_gpuStatCache;

    unordered_flat_map<const void*, bool> m_visMap;

    void(*m_cbMainThread)(std::function<void()>, bool);

    int m_gpuIdx = 0;

    struct FindZone {
        enum : uint64_t { Unselected = std::numeric_limits<uint64_t>::max() - 1 };
        enum class GroupBy : int { Thread, UserText, ZoneName, Callstack, Parent, NoGrouping };
        enum class SortBy : int { Order, Count, Time, Mtpc };

        struct Group
        {
            uint16_t id;
            Vector<short_ptr<ZoneEvent>> zones;
            Vector<uint16_t> zonesTids;
            int64_t time = 0;
        };

        bool show = false;
        bool ignoreCase = false;
        std::vector<int16_t> match;
        unordered_flat_map<uint64_t, Group> groups;
        size_t processed;
        uint16_t groupId;
        int selMatch = 0;
        uint64_t selGroup = Unselected;
        char pattern[1024] = {};
        bool logVal = false;
        bool logTime = true;
        bool cumulateTime = false;
        bool selfTime = false;
        bool runningTime = false;
        GroupBy groupBy = GroupBy::Thread;
        SortBy sortBy = SortBy::Count;
        Region highlight;
        int64_t hlOrig_t0, hlOrig_t1;
        int64_t numBins = -1;
        std::unique_ptr<int64_t[]> bins, binTime, selBin;
        Vector<int64_t> sorted, selSort;
        size_t sortedNum = 0, selSortNum, selSortActive;
        float average, selAverage;
        float median, selMedian;
        int64_t total, selTotal;
        int64_t selTime;
        bool drawAvgMed = true;
        bool drawSelAvgMed = true;
        bool scheduleResetMatch = false;
        int selCs = 0;
        int minBinVal = 1;
        int64_t tmin, tmax;
        bool showZoneInFrames = false;
        Range range;
        RangeSlim rangeSlim;

        struct
        {
            int numBins = -1;
            ptrdiff_t distBegin;
            ptrdiff_t distEnd;
        } binCache;

        struct {
            Vector<SymList> counts;
            bool scheduleUpdate = false;
            bool enabled = false;
        } samples;

        void Reset()
        {
            ResetMatch();
            match.clear();
            selMatch = 0;
            selGroup = Unselected;
            highlight.active = false;
            samples.counts.clear();
        }

        void ResetMatch()
        {
            ResetGroups();
            sorted.clear();
            sortedNum = 0;
            average = 0;
            median = 0;
            total = 0;
            tmin = std::numeric_limits<int64_t>::max();
            tmax = std::numeric_limits<int64_t>::min();
        }

        void ResetGroups()
        {
            ResetSelection();
            groups.clear();
            processed = 0;
            groupId = 0;
            selCs = 0;
            selGroup = Unselected;
        }

        void ResetSelection()
        {
            selSort.clear();
            selSortNum = 0;
            selSortActive = 0;
            selAverage = 0;
            selMedian = 0;
            selTotal = 0;
            selTime = 0;
            binCache.numBins = -1;
            samples.scheduleUpdate = true;
        }

        void ShowZone( int16_t srcloc, const char* name )
        {
            show = true;
            range.active = false;
            Reset();
            match.emplace_back( srcloc );
            strcpy( pattern, name );
        }

        void ShowZone( int16_t srcloc, const char* name, int64_t limitMin, int64_t limitMax )
        {
            assert( limitMin <= limitMax );
            show = true;
            range.active = true;
            range.min = limitMin;
            range.max = limitMax;
            Reset();
            match.emplace_back( srcloc );
            strcpy( pattern, name );
        }
    } m_findZone;

    tracy_force_inline uint64_t GetSelectionTarget( const Worker::ZoneThreadData& ev, FindZone::GroupBy groupBy ) const;

    struct CompVal
    {
        double v0;
        double v1;
    };

    struct {
        bool show = false;
        bool ignoreCase = false;
        bool link = true;
        std::unique_ptr<Worker> second;
        std::unique_ptr<UserData> userData;
        std::thread loadThread;
        BadVersionState badVer;
        char pattern[1024] = {};
        std::vector<int16_t> match[2];
        int selMatch[2] = { 0, 0 };
        bool logVal = false;
        bool logTime = true;
        bool cumulateTime = false;
        bool normalize = true;
        int64_t numBins = -1;
        std::unique_ptr<CompVal[]> bins, binTime;
        std::vector<int64_t> sorted[2];
        size_t sortedNum[2] = { 0, 0 };
        float average[2];
        float median[2];
        int64_t total[2];
        int minBinVal = 1;
        int compareMode = 0;
        bool diffDone = false;
        bool diffDirection;
        std::vector<const char*> thisUnique;
        std::vector<const char*> secondUnique;
        std::vector<std::pair<const char*, std::string>> diffs;

        void ResetSelection()
        {
            for( int i=0; i<2; i++ )
            {
                sorted[i].clear();
                sortedNum[i] = 0;
                average[i] = 0;
                median[i] = 0;
                total[i] = 0;
            }
        }

        void Reset()
        {
            ResetSelection();
            for( int i=0; i<2; i++ )
            {
                match[i].clear();
                selMatch[i] = 0;
            }
            diffDone = false;
            thisUnique.clear();
            secondUnique.clear();
            diffs.clear();
        }
    } m_compare;

    struct {
        bool show = false;
        char pattern[1024] = {};
        uint64_t ptrFind = 0;
        uint64_t pool = 0;
        bool showAllocList = false;
        std::vector<size_t> allocList;
        Range range;
    } m_memInfo;

    struct {
        std::vector<int64_t> data;
        const FrameData* frameSet = nullptr;
        size_t frameNum = 0;
        float average = 0;
        float median = 0;
        int64_t total = 0;
        bool logVal = false;
        bool logTime = true;
        int64_t numBins = -1;
        std::unique_ptr<int64_t[]> bins;
        bool drawAvgMed = true;
        bool limitToView = false;
        std::pair<int, int> limitRange = { -1, 0 };
        int minBinVal = 1;
    } m_frameSortData;

    struct {
        std::pair<const ZoneEvent*, int64_t> zoneSelfTime = { nullptr, 0 };
        std::pair<const ZoneEvent*, int64_t> zoneSelfTime2 = { nullptr, 0 };
        std::pair<const GpuEvent*, int64_t> gpuSelfTime = { nullptr, 0 };
        std::pair<const GpuEvent*, int64_t> gpuSelfTime2 = { nullptr, 0 };
    } m_cache;

    struct {
        void* texture = nullptr;
        float timeLeft = 0;
        float speed = 1;
        uint32_t frame = 0;
        uint32_t currFrame = -1;
        bool pause = true;
        bool sync = false;
        bool zoom = false;
    } m_playback;

    struct TimeDistribution {
        bool runningTime = false;
        bool exclusiveTime = true;
        unordered_flat_map<int16_t, ZoneTimeData> data;
        const ZoneEvent* dataValidFor = nullptr;
        float fztime;
    } m_timeDist;

    struct {
        uint64_t symAddr = 0;
        int sel;
        bool withInlines = false;
        int mode = 0;
        bool groupBottomUp = true;
        bool groupTopDown = true;
    } m_sampleParents;

    struct
    {
        bool enabled = false;
        bool monitor = false;
        int64_t time;
    } m_sendQueueWarning;

    std::vector<std::pair<int, int>> m_cpuUsageBuf;

    bool m_attnProtoMismatch = false;
    bool m_attnNotAvailable = false;
    bool m_attnDropped = false;
    bool m_attnFailure = false;
    bool m_attnWorking = false;
    bool m_attnDisconnected = false;
};

}

#endif
