#ifndef __TRACYVIEW_HPP__
#define __TRACYVIEW_HPP__

#include <atomic>
#include <map>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "TracyVector.hpp"
#include "TracyWorker.hpp"
#include "tracy_benaphore.h"
#include "tracy_flat_hash_map.hpp"

struct ImVec2;

namespace tracy
{

struct QueueItem;
class FileRead;

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
    View() : View( "127.0.0.1" ) {}
    View( const char* addr );
    View( FileRead& f );
    ~View();

    static void Draw();

private:
    enum class Namespace : uint8_t
    {
        Full,
        Mid,
        Short
    };

    const char* ShortenNamespace( const char* name ) const;

    void DrawHelpMarker( const char* desc ) const;

    void DrawTextContrast( ImDrawList* draw, const ImVec2& pos, uint32_t color, const char* text );

    void DrawImpl();
    void DrawConnection();
    void DrawFrames();
    bool DrawZoneFrames();
    void DrawZones();
    int DrawZoneLevel( const Vector<ZoneEvent*>& vec, bool hover, double pxns, const ImVec2& wpos, int offset, int depth );
    int DrawGpuZoneLevel( const Vector<GpuEvent*>& vec, bool hover, double pxns, const ImVec2& wpos, int offset, int depth, uint64_t thread );
    int DrawLocks( uint64_t tid, bool hover, double pxns, const ImVec2& wpos, int offset, LockHighlight& highlight );
    int DrawPlots( int offset, double pxns, const ImVec2& wpos, bool hover );
    void DrawPlotPoint( const ImVec2& wpos, float x, float y, int offset, uint32_t color, bool hover, bool hasPrev, double val, double prev, bool merged );
    void DrawOptions();
    void DrawMessages();
    void DrawFindZone();

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

    void ZoneTooltip( const ZoneEvent& ev );
    void ZoneTooltip( const GpuEvent& ev );
    const ZoneEvent* GetZoneParent( const ZoneEvent& zone ) const;
    const GpuEvent* GetZoneParent( const GpuEvent& zone ) const;
    uint64_t GetZoneThread( const ZoneEvent& zone ) const;

#ifndef TRACY_NO_STATISTICS
    void FindZones();
#endif

    template <typename T>
    bool& Visible( const T* ptr )
    {
        static std::map <const T*, bool> visible;
        if( visible.find( ptr ) == visible.end() )
        {
            visible[ptr] = true;
        }

        return visible[ptr];
    }

    template <typename T>
    bool& ShowFull( const T* ptr )
    {
        static std::map <const T*, bool> showFull;
        if( showFull.find( ptr ) == showFull.end() )
        {
            showFull[ptr] = true;
        }

        return showFull[ptr];
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
    LockHighlight m_lockHighlight;
    const MessageData* m_msgHighlight;
    const GpuEvent* m_gpuInfoWindow;
    const GpuEvent* m_gpuHighlight;
    uint64_t m_gpuInfoWindowThread;

    Region m_highlight;

    uint64_t m_gpuThread;
    int64_t m_gpuStart;
    int64_t m_gpuEnd;

    bool m_showOptions;
    bool m_showMessages;
    bool m_drawGpuZones;
    bool m_drawZones;
    bool m_drawLocks;
    bool m_drawPlots;
    bool m_onlyContendedLocks;

    Namespace m_namespace;
    Animation m_zoomAnim;

    struct {
        bool show;
        std::vector<uint32_t> counts;
        std::vector<int32_t> match;
        int selMatch = 0;
        char pattern[1024] = { "" };
        bool logVal = false;
        bool logTime = false;
        bool cumulateTime = false;
        Region highlight;

        void Reset()
        {
            match.clear();
            counts.clear();
            selMatch = 0;
            highlight.active = false;
        }
    } m_findZone;
};

}

#endif
