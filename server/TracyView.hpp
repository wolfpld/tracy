#ifndef __TRACYVIEW_HPP__
#define __TRACYVIEW_HPP__

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "TracyBadVersion.hpp"
#include "TracyBuzzAnim.hpp"
#include "TracyDecayValue.hpp"
#include "TracyFileWrite.hpp"
#include "TracyImGui.hpp"
#include "TracyShortPtr.hpp"
#include "TracySourceContents.hpp"
#include "TracyTexture.hpp"
#include "TracyUserData.hpp"
#include "TracyVector.hpp"
#include "TracyViewData.hpp"
#include "TracyWorker.hpp"
#include "tracy_robin_hood.h"

struct ImVec2;
struct ImFont;

namespace tracy
{

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
    struct VisData
    {
        bool visible = true;
        bool showFull = true;
        bool ghost = false;
        int offset = 0;
        int height = 0;
    };

    struct PlotView
    {
        double min;
        double max;
    };

    using SetTitleCallback = void(*)( const char* );
    using GetWindowCallback = void*(*)();

    View( void(*cbMainThread)(std::function<void()>), ImFont* fixedWidth = nullptr, ImFont* smallFont = nullptr, ImFont* bigFont = nullptr, SetTitleCallback stcb = nullptr, GetWindowCallback gwcb = nullptr ) : View( cbMainThread, "127.0.0.1", 8086, fixedWidth, smallFont, bigFont, stcb, gwcb ) {}
    View( void(*cbMainThread)(std::function<void()>), const char* addr, uint16_t port, ImFont* fixedWidth = nullptr, ImFont* smallFont = nullptr, ImFont* bigFont = nullptr, SetTitleCallback stcb = nullptr, GetWindowCallback gwcb = nullptr );
    View( void(*cbMainThread)(std::function<void()>), FileRead& f, ImFont* fixedWidth = nullptr, ImFont* smallFont = nullptr, ImFont* bigFont = nullptr, SetTitleCallback stcb = nullptr, GetWindowCallback gwcb = nullptr );
    ~View();

    static bool Draw();

    void NotifyRootWindowSize( float w, float h ) { m_rootWidth = w; m_rootHeight = h; }
    void ViewSource( const char* fileName, int line );
    void ViewSymbol( const char* fileName, int line, uint64_t baseAddr, uint64_t symAddr );
    bool ViewDispatch( const char* fileName, int line, uint64_t symAddr );

    bool ReconnectRequested() const { return m_reconnectRequested; }
    std::string GetAddress() const { return m_worker.GetAddr(); }
    uint16_t GetPort() const { return m_worker.GetPort(); }

    const char* SourceSubstitution( const char* srcFile ) const;

    void ShowSampleParents( uint64_t symAddr ) { m_sampleParents.symAddr = symAddr; m_sampleParents.sel = 0; }
    const ViewData& GetViewData() const { return m_vd; }


    bool m_showRanges = false;
    Range m_statRange;

private:
    enum class Namespace : uint8_t
    {
        Full,
        Mid,
        Short
    };

    enum class ShortcutAction : uint8_t
    {
        None,
        OpenFind
    };

    enum { InvalidId = 0xFFFFFFFF };

    struct PathData
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

    struct ZoneColorData
    {
        uint32_t color;
        uint32_t accentColor;
        float thickness;
        bool highlight;
    };

    void InitMemory();
    void InitTextEditor( ImFont* font );

    const char* ShortenNamespace( const char* name ) const;

    void DrawHelpMarker( const char* desc ) const;

    bool DrawImpl();
    void DrawNotificationArea();
    bool DrawConnection();
    void DrawFrames();
    void DrawZoneFramesHeader();
    void DrawZoneFrames( const FrameData& frames );
    void DrawZones();
    void DrawContextSwitches( const ContextSwitch* ctx, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int offset, int endOffset );
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
    int DrawPlots( int offset, double pxns, const ImVec2& wpos, bool hover, float yMin, float yMax );
    void DrawPlotPoint( const ImVec2& wpos, float x, float y, int offset, uint32_t color, bool hover, bool hasPrev, const PlotItem* item, double prev, bool merged, PlotType type, PlotValueFormatting format, float PlotHeight, uint64_t name );
    void DrawPlotPoint( const ImVec2& wpos, float x, float y, int offset, uint32_t color, bool hover, bool hasPrev, double val, double prev, bool merged, PlotValueFormatting format, float PlotHeight );
    int DrawCpuData( int offset, double pxns, const ImVec2& wpos, bool hover, float yMin, float yMax );
    void DrawOptions();
    void DrawMessages();
    void DrawMessageLine( const MessageData& msg, bool hasCallstack, int& idx );
    void DrawFindZone();
    void AccumulationModeComboBox();
    void DrawStatistics();
    void DrawMemory();
    void DrawAllocList();
    void DrawCompare();
    void DrawCallstackWindow();
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

    void ListMemData( std::vector<const MemEvent*>& vec, std::function<void(const MemEvent*)> DrawAddress, const char* id = nullptr, int64_t startTime = -1, uint64_t pool = 0 );

    unordered_flat_map<uint32_t, PathData> GetCallstackPaths( const MemData& mem, bool onlyActive ) const;
    unordered_flat_map<uint64_t, CallstackFrameTree> GetCallstackFrameTreeBottomUp( const MemData& mem ) const;
    unordered_flat_map<uint64_t, CallstackFrameTree> GetCallstackFrameTreeTopDown( const MemData& mem ) const;
    void DrawFrameTreeLevel( const unordered_flat_map<uint64_t, CallstackFrameTree>& tree, int& idx );
    void DrawZoneList( int id, const Vector<short_ptr<ZoneEvent>>& zones );

    void DrawInfoWindow();
    void DrawZoneInfoWindow();
    void DrawGpuInfoWindow();

    template<typename Adapter, typename V>
    void DrawZoneInfoChildren( const V& children, int64_t ztime );
    template<typename Adapter, typename V>
    void DrawGpuInfoChildren( const V& children, int64_t ztime );

    void HandleRange( Range& range, int64_t timespan, const ImVec2& wpos, float w );
    void HandleZoneViewMouse( int64_t timespan, const ImVec2& wpos, float w, double& pxns );

    uint32_t GetThreadColor( uint64_t thread, int depth );
    uint32_t GetSrcLocColor( const SourceLocation& srcloc, int depth );
    uint32_t GetRawSrcLocColor( const SourceLocation& srcloc, int depth );
    uint32_t GetZoneColor( const ZoneEvent& ev, uint64_t thread, int depth );
    uint32_t GetZoneColor( const GpuEvent& ev );
    ZoneColorData GetZoneColorData( const ZoneEvent& ev, uint64_t thread, int depth );
    ZoneColorData GetZoneColorData( const GpuEvent& ev );

    void ZoomToZone( const ZoneEvent& ev );
    void ZoomToZone( const GpuEvent& ev );
    void ZoomToRange( int64_t start, int64_t end, bool pause = true );
    void ZoomToPrevFrame();
    void ZoomToNextFrame();
    void CenterAtTime( int64_t t );

    void ShowZoneInfo( const ZoneEvent& ev );
    void ShowZoneInfo( const GpuEvent& ev, uint64_t thread );

    void ZoneTooltip( const ZoneEvent& ev );
    void ZoneTooltip( const GpuEvent& ev );
    void CallstackTooltip( uint32_t idx );
    void CrashTooltip();

    const ZoneEvent* GetZoneParent( const ZoneEvent& zone ) const;
    const ZoneEvent* GetZoneParent( const ZoneEvent& zone, uint64_t tid ) const;
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

#ifndef TRACY_NO_STATISTICS
    void FindZones();
    void FindZonesCompare();
#endif

    std::vector<MemoryPage> GetMemoryPages() const;
    const char* GetPlotName( const PlotData* plot ) const;

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

    unordered_flat_map<const void*, VisData> m_visData;
    unordered_flat_map<uint64_t, bool> m_visibleMsgThread;
    unordered_flat_map<const void*, int> m_gpuDrift;
    unordered_flat_map<const PlotData*, PlotView> m_plotView;
    Vector<const ThreadData*> m_threadOrder;
    Vector<float> m_threadDnd;

    tracy_force_inline VisData& Vis( const void* ptr )
    {
        auto it = m_visData.find( ptr );
        if( it == m_visData.end() )
        {
            it = m_visData.emplace( ptr, VisData {} ).first;
        }
        return it->second;
    }

    tracy_force_inline bool& VisibleMsgThread( uint64_t thread )
    {
        auto it = m_visibleMsgThread.find( thread );
        if( it == m_visibleMsgThread.end() )
        {
            it = m_visibleMsgThread.emplace( thread, true ).first;
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

    void AdjustThreadHeight( View::VisData& vis, int oldOffset, int& offset );

    Worker m_worker;
    std::string m_filename, m_filenameStaging;
    bool m_staticView;
    ViewMode m_viewMode;
    bool m_viewModeHeuristicTry = false;
    DecayValue<bool> m_forceConnectionPopup = false;
    uint64_t m_totalMemory;

    ViewData m_vd;

    const ZoneEvent* m_zoneInfoWindow = nullptr;
    const ZoneEvent* m_zoneHighlight;
    DecayValue<int16_t> m_zoneSrcLocHighlight = 0;
    LockHighlight m_lockHighlight { -1 };
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
    uint64_t m_zoneInfoMemPool = 0;

    ShortcutAction m_shortcut = ShortcutAction::None;
    Namespace m_namespace = Namespace::Short;
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
    GetWindowCallback m_gwcb;

    float m_notificationTime = 0;
    std::string m_notificationText;

    bool m_groupCallstackTreeByNameBottomUp = true;
    bool m_groupCallstackTreeByNameTopDown = true;
    bool m_activeOnlyBottomUp = false;
    bool m_activeOnlyTopDown = false;

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

    bool m_reconnectRequested = false;
    bool m_firstFrame = true;
    std::chrono::time_point<std::chrono::high_resolution_clock> m_firstFrameTime;
    float m_yDelta;

    std::vector<SourceRegex> m_sourceSubstitutions;
    bool m_sourceRegexValid = true;

    RangeSlim m_setRangePopup;
    bool m_setRangePopupOpen = false;

    unordered_flat_map<int16_t, StatisticsCache> m_statCache;

    void(*m_cbMainThread)(std::function<void()>);

    struct FindZone {
        enum : uint64_t { Unselected = std::numeric_limits<uint64_t>::max() - 1 };
        enum class GroupBy : int { Thread, UserText, ZoneName, Callstack, Parent, NoGrouping };
        enum class SortBy : int { Order, Count, Time, Mtpc };

        struct Group
        {
            uint16_t id;
            Vector<short_ptr<ZoneEvent>> zones;
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

        void Reset()
        {
            ResetMatch();
            match.clear();
            selMatch = 0;
            selGroup = Unselected;
            highlight.active = false;
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
        }
    } m_compare;

    struct {
        bool show = false;
        char pattern[1024] = {};
        uint64_t ptrFind = 0;
        uint64_t pool = 0;
        bool restrictTime = false;
        bool showAllocList = false;
        std::vector<size_t> allocList;
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
    } m_sampleParents;

    std::vector<std::pair<int, int>> m_cpuUsageBuf;
};

}

#endif
