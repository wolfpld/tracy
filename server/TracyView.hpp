#ifndef __TRACYVIEW_HPP__
#define __TRACYVIEW_HPP__

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "TracyBuzzAnim.hpp"
#include "TracyDecayValue.hpp"
#include "TracyVector.hpp"
#include "TracyWorker.hpp"
#include "tracy_flat_hash_map.hpp"

struct ImVec2;
struct ImFont;

namespace tracy
{

struct QueueItem;
class FileRead;
class TextEditor;

class View
{
    struct Animation
    {
        bool active = false;
        int64_t start0, start1;
        int64_t end0, end1;
        double progress;
        double lenMod;
    };

    struct Region
    {
        bool active = false;
        int64_t start;
        int64_t end;
    };

public:
    using SetTitleCallback = void(*)( const char* );

    View( ImFont* fixedWidth = nullptr, SetTitleCallback stcb = nullptr ) : View( "127.0.0.1", fixedWidth, stcb ) {}
    View( const char* addr, ImFont* fixedWidth = nullptr, SetTitleCallback stcb = nullptr );
    View( FileRead& f, ImFont* fixedWidth = nullptr, SetTitleCallback stcb = nullptr );
    ~View();

    static bool Draw();

    void NotifyRootWindowSize( float w, float h ) { m_rootWidth = w; m_rootHeight = h; }
    void SetTextEditorFile( const char* fileName, int line );

private:
    enum class Namespace : uint8_t
    {
        Full,
        Mid,
        Short
    };

    void InitTextEditor();

    const char* ShortenNamespace( const char* name ) const;

    void DrawHelpMarker( const char* desc ) const;

    void DrawTextContrast( ImDrawList* draw, const ImVec2& pos, uint32_t color, const char* text );

    bool DrawImpl();
    void DrawConnection();
    void DrawFrames();
    bool DrawZoneFramesHeader();
    bool DrawZoneFrames( const FrameData& frames );
    void DrawZones();
    int DispatchZoneLevel( const Vector<ZoneEvent*>& vec, bool hover, double pxns, const ImVec2& wpos, int offset, int depth, float yMin, float yMax );
    int DrawZoneLevel( const Vector<ZoneEvent*>& vec, bool hover, double pxns, const ImVec2& wpos, int offset, int depth, float yMin, float yMax );
    int SkipZoneLevel( const Vector<ZoneEvent*>& vec, bool hover, double pxns, const ImVec2& wpos, int offset, int depth, float yMin, float yMax );
    int DispatchGpuZoneLevel( const Vector<GpuEvent*>& vec, bool hover, double pxns, const ImVec2& wpos, int offset, int depth, uint64_t thread, float yMin, float yMax, int64_t begin, int drift );
    int DrawGpuZoneLevel( const Vector<GpuEvent*>& vec, bool hover, double pxns, const ImVec2& wpos, int offset, int depth, uint64_t thread, float yMin, float yMax, int64_t begin, int drift );
    int SkipGpuZoneLevel( const Vector<GpuEvent*>& vec, bool hover, double pxns, const ImVec2& wpos, int offset, int depth, uint64_t thread, float yMin, float yMax, int64_t begin, int drift );
    int DrawLocks( uint64_t tid, bool hover, double pxns, const ImVec2& wpos, int offset, LockHighlight& highlight, float yMin, float yMax );
    int DrawPlots( int offset, double pxns, const ImVec2& wpos, bool hover, float yMin, float yMax );
    void DrawPlotPoint( const ImVec2& wpos, float x, float y, int offset, uint32_t color, bool hover, bool hasPrev, const PlotItem* item, double prev, bool merged, PlotType type, float PlotHeight );
    void DrawPlotPoint( const ImVec2& wpos, float x, float y, int offset, uint32_t color, bool hover, bool hasPrev, double val, double prev, bool merged, float PlotHeight );
    void DrawOptions();
    void DrawMessages();
    void DrawFindZone();
    void DrawStatistics();
    void DrawMemory();
    void DrawCompare();
    void DrawCallstackWindow();
    void DrawMemoryAllocWindow();
    void DrawInfo();
    void DrawTextEditor();

    template<class T>
    void ListMemData( T ptr, T end, std::function<void(T&)> DrawAddress, const char* id = nullptr );

    std::vector<CallstackFrameTree> GetCallstackFrameTree( const MemData& mem ) const;
    void DrawFrameTreeLevel( std::vector<CallstackFrameTree>& tree, int& idx );

    void DrawInfoWindow();
    void DrawZoneInfoWindow();
    void DrawGpuInfoWindow();

    void HandleZoneViewMouse( int64_t timespan, const ImVec2& wpos, float w, double& pxns );

    uint32_t GetZoneColor( const ZoneEvent& ev );
    uint32_t GetZoneColor( const GpuEvent& ev );
    uint32_t GetZoneHighlight( const ZoneEvent& ev, bool migration );
    uint32_t GetZoneHighlight( const GpuEvent& ev );
    float GetZoneThickness( const ZoneEvent& ev );
    float GetZoneThickness( const GpuEvent& ev );

    void ZoomToZone( const ZoneEvent& ev );
    void ZoomToZone( const GpuEvent& ev );
    void ZoomToRange( int64_t start, int64_t end );
    void ZoomToPrevFrame();
    void ZoomToNextFrame();
    void CenterAtTime( int64_t t );

    void ShowZoneInfo( const ZoneEvent& ev );
    void ShowZoneInfo( const GpuEvent& ev, uint64_t thread );

    void ZoneTooltip( const ZoneEvent& ev );
    void ZoneTooltip( const GpuEvent& ev );
    void CallstackTooltip( uint32_t idx );

    const ZoneEvent* GetZoneParent( const ZoneEvent& zone ) const;
    const GpuEvent* GetZoneParent( const GpuEvent& zone ) const;
    uint64_t GetZoneThread( const ZoneEvent& zone ) const;
    uint64_t GetZoneThread( const GpuEvent& zone ) const;
    const GpuCtxData* GetZoneCtx( const GpuEvent& zone ) const;
    const ZoneEvent* FindZoneAtTime( uint64_t thread, int64_t time ) const;
    const char* GetFrameText( const FrameData& fd, int i, uint64_t ftime, uint64_t offset ) const;

#ifndef TRACY_NO_STATISTICS
    void FindZones();
    void FindZonesCompare();
#endif

    std::pair<int8_t*, size_t> GetMemoryPages() const;
    const char* GetPlotName( const PlotData* plot ) const;

    void SmallCallstackButton( const char* name, uint32_t callstack, int& idx );

    flat_hash_map<const void*, bool, nohash<const void*>> m_visible;
    flat_hash_map<uint64_t, bool, nohash<uint64_t>> m_visibleMsgThread;
    flat_hash_map<const void*, bool, nohash<const void*>> m_showFull;
    flat_hash_map<const void*, int, nohash<const void*>> m_gpuDrift;

    tracy_force_inline bool& Visible( const void* ptr )
    {
        auto it = m_visible.find( ptr );
        if( it == m_visible.end() )
        {
            it = m_visible.emplace( ptr, true ).first;
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

    tracy_force_inline bool& ShowFull( const void* ptr )
    {
        auto it = m_showFull.find( ptr );
        if( it == m_showFull.end() )
        {
            it = m_showFull.emplace( ptr, true ).first;
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

    Worker m_worker;
    bool m_staticView;

    int m_frameScale;
    bool m_pause;
    int m_frameStart;

    int64_t m_zvStart;
    int64_t m_zvEnd;
    int64_t m_lastTime;

    int8_t m_lastCpu;

    int m_zvHeight;
    int m_zvScroll;

    const ZoneEvent* m_zoneInfoWindow;
    const ZoneEvent* m_zoneHighlight;
    DecayValue<uint64_t> m_zoneSrcLocHighlight;
    LockHighlight m_lockHighlight;
    DecayValue<const MessageData*> m_msgHighlight;
    const MessageData* m_msgToFocus;
    const GpuEvent* m_gpuInfoWindow;
    const GpuEvent* m_gpuHighlight;
    uint64_t m_gpuInfoWindowThread;
    uint32_t m_callstackInfoWindow;
    int64_t m_memoryAllocInfoWindow;
    int64_t m_memoryAllocHover;
    int m_memoryAllocHoverWait;
    const FrameData* m_frames;

    Region m_highlight;
    Region m_highlightZoom;

    uint64_t m_gpuThread;
    int64_t m_gpuStart;
    int64_t m_gpuEnd;

    bool m_showOptions;
    bool m_showMessages;
    bool m_showStatistics;
    bool m_showInfo;
    bool m_drawGpuZones;
    bool m_drawZones;
    bool m_drawLocks;
    bool m_drawPlots;
    bool m_onlyContendedLocks;

    int m_statSort;
    bool m_statSelf;
    bool m_showCallstackFrameAddress;

    Namespace m_namespace;
    Animation m_zoomAnim;
    BuzzAnim<int> m_callstackBuzzAnim;
    BuzzAnim<int> m_callstackTreeBuzzAnim;
    BuzzAnim<const void*> m_zoneinfoBuzzAnim;
    BuzzAnim<int> m_findZoneBuzzAnim;

    Vector<const ZoneEvent*> m_zoneInfoStack;
    Vector<const GpuEvent*> m_gpuInfoStack;

    std::unique_ptr<TextEditor> m_textEditor;
    const char* m_textEditorFile;
    ImFont* m_textEditorFont;

    float m_rootWidth, m_rootHeight;
    SetTitleCallback m_stcb;
    bool m_titleSet;

    struct FindZone {
        enum : uint64_t { Unselected = std::numeric_limits<uint64_t>::max() - 1 };
        enum class GroupBy : int { Thread, UserText, Callstack };
        enum class SortBy : int { Order, Count, Time };

        struct Group
        {
            Vector<ZoneEvent*> zones;
            int64_t time = 0;
        };

        bool show = false;
        std::vector<int32_t> match;
        std::map<uint64_t, Group> groups;
        size_t processed;
        int selMatch = 0;
        uint64_t selGroup = Unselected;
        char pattern[1024] = {};
        bool logVal = false;
        bool logTime = true;
        bool cumulateTime = false;
        GroupBy groupBy = GroupBy::Thread;
        SortBy sortBy = SortBy::Order;
        Region highlight;
        int64_t numBins = -1;
        std::unique_ptr<int64_t[]> bins, binTime, selBin;

        void Reset()
        {
            ResetGroups();
            match.clear();
            selMatch = 0;
            selGroup = Unselected;
            highlight.active = false;
        }

        void ResetGroups()
        {
            groups.clear();
            processed = 0;
        }

        void ShowZone( int32_t srcloc, const char* name )
        {
            show = true;
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
        std::unique_ptr<Worker> second;
        std::thread loadThread;
        int badVer = 0;
        char pattern[1024] = {};
        std::vector<int32_t> match[2];
        int selMatch[2] = { 0, 0 };
        bool logVal = false;
        bool logTime = true;
        bool cumulateTime = false;
        bool normalize = false;
        int64_t numBins = -1;
        std::unique_ptr<CompVal[]> bins, binTime;

        void Reset()
        {
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
        bool restrictTime = false;
    } m_memInfo;
};

}

#endif
