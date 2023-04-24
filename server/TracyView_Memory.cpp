#include <inttypes.h>

#include "TracyImGui.hpp"
#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracyView.hpp"

namespace tracy
{

enum { ChunkBits = 10 };
enum { PageBits = 10 };
enum { PageSize = 1 << PageBits };
enum { PageChunkBits = ChunkBits + PageBits };
enum { PageChunkSize = 1 << PageChunkBits };

uint32_t MemDecayColor[256] = {
    0x0, 0xFF077F07, 0xFF078007, 0xFF078207, 0xFF078307, 0xFF078507, 0xFF078707, 0xFF078807,
    0xFF078A07, 0xFF078B07, 0xFF078D07, 0xFF078F07, 0xFF079007, 0xFF089208, 0xFF089308, 0xFF089508,
    0xFF089708, 0xFF089808, 0xFF089A08, 0xFF089B08, 0xFF089D08, 0xFF089F08, 0xFF08A008, 0xFF08A208,
    0xFF09A309, 0xFF09A509, 0xFF09A709, 0xFF09A809, 0xFF09AA09, 0xFF09AB09, 0xFF09AD09, 0xFF09AF09,
    0xFF09B009, 0xFF09B209, 0xFF09B309, 0xFF09B509, 0xFF0AB70A, 0xFF0AB80A, 0xFF0ABA0A, 0xFF0ABB0A,
    0xFF0ABD0A, 0xFF0ABF0A, 0xFF0AC00A, 0xFF0AC20A, 0xFF0AC30A, 0xFF0AC50A, 0xFF0AC70A, 0xFF0BC80B,
    0xFF0BCA0B, 0xFF0BCB0B, 0xFF0BCD0B, 0xFF0BCF0B, 0xFF0BD00B, 0xFF0BD20B, 0xFF0BD30B, 0xFF0BD50B,
    0xFF0BD70B, 0xFF0BD80B, 0xFF0BDA0B, 0xFF0CDB0C, 0xFF0CDD0C, 0xFF0CDF0C, 0xFF0CE00C, 0xFF0CE20C,
    0xFF0CE30C, 0xFF0CE50C, 0xFF0CE70C, 0xFF0CE80C, 0xFF0CEA0C, 0xFF0CEB0C, 0xFF0DED0D, 0xFF0DEF0D,
    0xFF0DF00D, 0xFF0DF20D, 0xFF0DF30D, 0xFF0DF50D, 0xFF0DF70D, 0xFF0DF80D, 0xFF0DFA0D, 0xFF0DFB0D,
    0xFF0DFD0D, 0xFF0EFF0E, 0xFF0EFF0E, 0xFF0EFF0E, 0xFF0EFF0E, 0xFF0EFF0E, 0xFF0EFF0E, 0xFF0EFF0E,
    0xFF0EFF0E, 0xFF0EFF0E, 0xFF0EFF0E, 0xFF0EFF0E, 0xFF0EFF0E, 0xFF0FFF0F, 0xFF0FFF0F, 0xFF0FFF0F,
    0xFF0FFF0F, 0xFF0FFF0F, 0xFF0FFF0F, 0xFF0FFF0F, 0xFF0FFF0F, 0xFF0FFF0F, 0xFF0FFF0F, 0xFF0FFF0F,
    0xFF10FF10, 0xFF10FF10, 0xFF10FF10, 0xFF10FF10, 0xFF10FF10, 0xFF10FF10, 0xFF10FF10, 0xFF10FF10,
    0xFF10FF10, 0xFF10FF10, 0xFF10FF10, 0xFF10FF10, 0xFF11FF11, 0xFF11FF11, 0xFF11FF11, 0xFF11FF11,
    0xFF11FF11, 0xFF11FF11, 0xFF11FF11, 0xFF11FF11, 0xFF11FF11, 0xFF11FF11, 0xFF11FF11, 0xFF12FF12,
    0x0, 0xFF1212FF, 0xFF1111FF, 0xFF1111FF, 0xFF1111FF, 0xFF1111FF, 0xFF1111FF, 0xFF1111FF,
    0xFF1111FF, 0xFF1111FF, 0xFF1111FF, 0xFF1111FF, 0xFF1111FF, 0xFF1010FF, 0xFF1010FF, 0xFF1010FF,
    0xFF1010FF, 0xFF1010FF, 0xFF1010FF, 0xFF1010FF, 0xFF1010FF, 0xFF1010FF, 0xFF1010FF, 0xFF1010FF,
    0xFF1010FF, 0xFF0F0FFF, 0xFF0F0FFF, 0xFF0F0FFF, 0xFF0F0FFF, 0xFF0F0FFF, 0xFF0F0FFF, 0xFF0F0FFF,
    0xFF0F0FFF, 0xFF0F0FFF, 0xFF0F0FFF, 0xFF0F0FFF, 0xFF0E0EFF, 0xFF0E0EFF, 0xFF0E0EFF, 0xFF0E0EFF,
    0xFF0E0EFF, 0xFF0E0EFF, 0xFF0E0EFF, 0xFF0E0EFF, 0xFF0E0EFF, 0xFF0E0EFF, 0xFF0E0EFF, 0xFF0E0EFF,
    0xFF0D0DFD, 0xFF0D0DFB, 0xFF0D0DFA, 0xFF0D0DF8, 0xFF0D0DF7, 0xFF0D0DF5, 0xFF0D0DF3, 0xFF0D0DF2,
    0xFF0D0DF0, 0xFF0D0DEF, 0xFF0D0DED, 0xFF0C0CEB, 0xFF0C0CEA, 0xFF0C0CE8, 0xFF0C0CE7, 0xFF0C0CE5,
    0xFF0C0CE3, 0xFF0C0CE2, 0xFF0C0CE0, 0xFF0C0CDF, 0xFF0C0CDD, 0xFF0C0CDB, 0xFF0B0BDA, 0xFF0B0BD8,
    0xFF0B0BD7, 0xFF0B0BD5, 0xFF0B0BD3, 0xFF0B0BD2, 0xFF0B0BD0, 0xFF0B0BCF, 0xFF0B0BCD, 0xFF0B0BCB,
    0xFF0B0BCA, 0xFF0B0BC8, 0xFF0A0AC7, 0xFF0A0AC5, 0xFF0A0AC3, 0xFF0A0AC2, 0xFF0A0AC0, 0xFF0A0ABF,
    0xFF0A0ABD, 0xFF0A0ABB, 0xFF0A0ABA, 0xFF0A0AB8, 0xFF0A0AB7, 0xFF0909B5, 0xFF0909B3, 0xFF0909B2,
    0xFF0909B0, 0xFF0909AF, 0xFF0909AD, 0xFF0909AB, 0xFF0909AA, 0xFF0909A8, 0xFF0909A7, 0xFF0909A5,
    0xFF0909A3, 0xFF0808A2, 0xFF0808A0, 0xFF08089F, 0xFF08089D, 0xFF08089B, 0xFF08089A, 0xFF080898,
    0xFF080897, 0xFF080895, 0xFF080893, 0xFF080892, 0xFF070790, 0xFF07078F, 0xFF07078D, 0xFF07078B,
    0xFF07078A, 0xFF070788, 0xFF070787, 0xFF070785, 0xFF070783, 0xFF070782, 0xFF070780, 0xFF07077F,
};

struct MemoryPage
{
    uint64_t page;
    int8_t data[PageSize];
};

static tracy_force_inline MemoryPage& GetPage( unordered_flat_map<uint64_t, MemoryPage>& memmap, uint64_t page )
{
    auto it = memmap.find( page );
    if( it == memmap.end() )
    {
        it = memmap.emplace( page, MemoryPage { page, {} } ).first;
    }
    return it->second;
}

static tracy_force_inline void FillPages( unordered_flat_map<uint64_t, MemoryPage>& memmap, uint64_t c0, uint64_t c1, int8_t val )
{
    auto p0 = c0 >> PageBits;
    const auto p1 = c1 >> PageBits;

    if( p0 == p1 )
    {
        const auto a0 = c0 & ( PageSize - 1 );
        const auto a1 = c1 & ( PageSize - 1 );

        auto& page = GetPage( memmap, p0 );
        if( a0 == a1 )
        {
            page.data[a0] = val;
        }
        else
        {
            memset( page.data + a0, val, a1 - a0 + 1 );
        }
    }
    else
    {
        {
            const auto a0 = c0 & ( PageSize - 1 );
            auto& page = GetPage( memmap, p0 );
            memset( page.data + a0, val, PageSize - a0 );
        }
        while( ++p0 < p1 )
        {
            auto& page = GetPage( memmap, p0 );
            memset( page.data, val, PageSize );
        }
        {
            const auto a1 = c1 & ( PageSize - 1 );
            auto& page = GetPage( memmap, p1 );
            memset( page.data, val, a1 + 1 );
        }
    }
}

std::vector<MemoryPage> View::GetMemoryPages() const
{
    std::vector<MemoryPage> ret;

    static unordered_flat_map<uint64_t, MemoryPage> memmap;

    const auto& mem = m_worker.GetMemoryNamed( m_memInfo.pool );
    const auto memlow = mem.low;

    if( m_memInfo.range.active )
    {
        auto it = std::lower_bound( mem.data.begin(), mem.data.end(), m_memInfo.range.min, []( const auto& lhs, const auto& rhs ) { return lhs.TimeAlloc() < rhs; } );
        if( it != mem.data.end() )
        {
            auto end = std::lower_bound( mem.data.begin(), mem.data.end(), m_memInfo.range.max, []( const auto& lhs, const auto& rhs ) { return lhs.TimeAlloc() < rhs; } );
            while( it != end )
            {
                auto& alloc = *it++;

                const auto a0 = alloc.Ptr() - memlow;
                const auto a1 = a0 + alloc.Size();
                int8_t val = alloc.TimeFree() < 0 ?
                    int8_t( std::max( int64_t( 1 ), 127 - ( ( m_memInfo.range.max - alloc.TimeAlloc() ) >> 24 ) ) ) :
                    ( alloc.TimeFree() > m_memInfo.range.max ?
                        int8_t( std::max( int64_t( 1 ), 127 - ( ( m_memInfo.range.max - alloc.TimeAlloc() ) >> 24 ) ) ) :
                        int8_t( -std::max( int64_t( 1 ), 127 - ( ( m_memInfo.range.max - alloc.TimeFree() ) >> 24 ) ) ) );

                const auto c0 = a0 >> ChunkBits;
                const auto c1 = a1 >> ChunkBits;

                FillPages( memmap, c0, c1, val );
            }
        }
    }
    else
    {
        const auto lastTime = m_worker.GetLastTime();
        for( auto& alloc : mem.data )
        {
            const auto a0 = alloc.Ptr() - memlow;
            const auto a1 = a0 + alloc.Size();
            const int8_t val = alloc.TimeFree() < 0 ?
                int8_t( std::max( int64_t( 1 ), 127 - ( ( lastTime - std::min( lastTime, alloc.TimeAlloc() ) ) >> 24 ) ) ) :
                int8_t( -std::max( int64_t( 1 ), 127 - ( ( lastTime - std::min( lastTime, alloc.TimeFree() ) ) >> 24 ) ) );

            const auto c0 = a0 >> ChunkBits;
            const auto c1 = a1 >> ChunkBits;

            FillPages( memmap, c0, c1, val );
        }
    }

    std::vector<unordered_flat_map<uint64_t, MemoryPage>::const_iterator> itmap;
    itmap.reserve( memmap.size() );
    ret.reserve( memmap.size() );
    for( auto it = memmap.begin(); it != memmap.end(); ++it ) itmap.emplace_back( it );
    pdqsort_branchless( itmap.begin(), itmap.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.page < rhs->second.page; } );
    for( auto& v : itmap ) ret.emplace_back( v->second );

    memmap.clear();
    return ret;
}

void View::DrawMemory()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 1100 * scale, 500 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Memory", &m_memInfo.show, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }

    auto& memNameMap = m_worker.GetMemNameMap();
    if( memNameMap.size() > 1 )
    {
        TextDisabledUnformatted( ICON_FA_BOX_ARCHIVE " Memory pool:" );
        ImGui::SameLine();
        if( ImGui::BeginCombo( "##memoryPool", m_memInfo.pool == 0 ? "Default allocator" : m_worker.GetString( m_memInfo.pool ) ) )
        {
            for( auto& v : memNameMap )
            {
                if( ImGui::Selectable( v.first == 0 ? "Default allocator" : m_worker.GetString( v.first ) ) )
                {
                    m_memInfo.pool = v.first;
                    m_memInfo.showAllocList = false;
                }
            }
            ImGui::EndCombo();
        }
        ImGui::Separator();
    }

    auto& mem = m_worker.GetMemoryNamed( m_memInfo.pool );
    if( mem.data.empty() )
    {
        ImGui::TextWrapped( "No memory data collected." );
        ImGui::End();
        return;
    }

    TextDisabledUnformatted( "Total allocations:" );
    ImGui::SameLine();
    ImGui::Text( "%-15s", RealToString( mem.data.size() ) );
    ImGui::SameLine();
    TextDisabledUnformatted( "Active allocations:" );
    ImGui::SameLine();
    ImGui::Text( "%-15s", RealToString( mem.active.size() ) );
    ImGui::SameLine();
    TextDisabledUnformatted( "Memory usage:" );
    ImGui::SameLine();
    ImGui::Text( "%-15s", MemSizeToString( mem.usage ) );
    ImGui::SameLine();
    TextFocused( "Memory span:", MemSizeToString( mem.high - mem.low ) );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    DrawHelpMarker(
        "Click on address to display memory allocation info window. Middle click to zoom to allocation range.\n"
        "Active allocations are displayed using green color.\n"
        "A single thread is displayed if alloc and free was performed on the same thread. Otherwise two threads are displayed in order: alloc, free.\n"
        "If alloc and free is performed in the same zone, the free zone is displayed in yellow color." );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    ImGui::SeparatorEx( ImGuiSeparatorFlags_Vertical );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 2, 2 ) );
    if( ImGui::Checkbox( "Limit range", &m_memInfo.range.active ) )
    {
        if( m_memInfo.range.active && m_memInfo.range.min == 0 && m_memInfo.range.max == 0 )
        {
            m_memInfo.range.min = m_vd.zvStart;
            m_memInfo.range.max = m_vd.zvEnd;
        }
    }
    if( m_memInfo.range.active )
    {
        ImGui::SameLine();
        TextColoredUnformatted( 0xFF00FFFF, ICON_FA_TRIANGLE_EXCLAMATION );
        ImGui::SameLine();
        ToggleButton( ICON_FA_RULER " Limits", m_showRanges );
    }
    ImGui::PopStyleVar();

    ImGui::Separator();
    ImGui::BeginChild( "##memory" );
    if( ImGui::TreeNode( ICON_FA_AT " Allocations" ) )
    {
        bool findClicked =  ImGui::InputTextWithHint( "###address", "Enter memory address to search for", m_memInfo.pattern, 1024, ImGuiInputTextFlags_EnterReturnsTrue );
        ImGui::SameLine();
        findClicked |= ImGui::Button( ICON_FA_MAGNIFYING_GLASS " Find" );
        if( findClicked )
        {
            m_memInfo.ptrFind = strtoull( m_memInfo.pattern, nullptr, 0 );
        }
        ImGui::SameLine();
        if( ImGui::Button( ICON_FA_DELETE_LEFT " Clear" ) )
        {
            m_memInfo.ptrFind = 0;
            m_memInfo.pattern[0] = '\0';
        }

        if( m_memInfo.ptrFind != 0 )
        {
            std::vector<const MemEvent*> match;
            match.reserve( mem.active.size() );     // heuristic
            if( m_memInfo.range.active )
            {
                auto it = std::lower_bound( mem.data.begin(), mem.data.end(), m_memInfo.range.min, [] ( const auto& lhs, const auto& rhs ) { return lhs.TimeAlloc() < rhs; } );
                if( it != mem.data.end() )
                {
                    auto end = std::lower_bound( it, mem.data.end(), m_memInfo.range.max, [] ( const auto& lhs, const auto& rhs ) { return lhs.TimeAlloc() < rhs; } );
                    while( it != end )
                    {
                        if( it->Ptr() <= m_memInfo.ptrFind && it->Ptr() + it->Size() > m_memInfo.ptrFind )
                        {
                            match.emplace_back( it );
                        }
                        ++it;
                    }
                }
            }
            else
            {
                for( auto& v : mem.data )
                {
                    if( v.Ptr() <= m_memInfo.ptrFind && v.Ptr() + v.Size() > m_memInfo.ptrFind )
                    {
                        match.emplace_back( &v );
                    }
                }
            }

            if( match.empty() )
            {
                ImGui::TextUnformatted( "Found no allocations at given address" );
            }
            else
            {
                ListMemData( match, [this]( auto v ) {
                    if( v->Ptr() == m_memInfo.ptrFind )
                    {
                        ImGui::Text( "0x%" PRIx64, m_memInfo.ptrFind );
                    }
                    else
                    {
                        ImGui::Text( "0x%" PRIx64 "+%" PRIu64, v->Ptr(), m_memInfo.ptrFind - v->Ptr() );
                    }
                    }, -1, m_memInfo.pool );
            }
        }
        ImGui::TreePop();
    }

    ImGui::Separator();
    if( ImGui::TreeNode( ICON_FA_HEART_PULSE " Active allocations" ) )
    {
        uint64_t total = 0;
        std::vector<const MemEvent*> items;
        items.reserve( mem.active.size() );
        if( m_memInfo.range.active )
        {
            auto it = std::lower_bound( mem.data.begin(), mem.data.end(), m_memInfo.range.min, [] ( const auto& lhs, const auto& rhs ) { return lhs.TimeAlloc() < rhs; } );
            if( it != mem.data.end() )
            {
                auto end = std::lower_bound( it, mem.data.end(), m_memInfo.range.max, [] ( const auto& lhs, const auto& rhs ) { return lhs.TimeAlloc() < rhs; } );
                while( it != end )
                {
                    const auto tf = it->TimeFree();
                    if( tf < 0 || tf >= m_memInfo.range.max )
                    {
                        items.emplace_back( it );
                        total += it->Size();
                    }
                    ++it;
                }
            }
        }
        else
        {
            auto ptr = mem.data.data();
            for( auto& v : mem.active ) items.emplace_back( ptr + v.second );
            pdqsort_branchless( items.begin(), items.end(), []( const auto& lhs, const auto& rhs ) { return lhs->TimeAlloc() < rhs->TimeAlloc(); } );
            total = mem.usage;
        }

        ImGui::SameLine();
        ImGui::TextDisabled( "(%s)", RealToString( items.size() ) );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextFocused( "Memory usage:", MemSizeToString( total ) );

        if( !items.empty() )
        {
            ListMemData( items, []( auto v ) {
                ImGui::Text( "0x%" PRIx64, v->Ptr() );
                }, -1, m_memInfo.pool );
        }
        else
        {
            TextDisabledUnformatted( "No active allocations" );
        }
        ImGui::TreePop();
    }

    ImGui::Separator();
    if( ImGui::TreeNode( ICON_FA_MAP " Memory map" ) )
    {
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextFocused( "Single pixel:", MemSizeToString( 1 << ChunkBits ) );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextFocused( "Single line:", MemSizeToString( PageChunkSize ) );

        auto pages = GetMemoryPages();
        const size_t lines = pages.size();

        ImGui::BeginChild( "##memMap", ImVec2( PageSize + 2, lines + 2 ), false );
        auto draw = ImGui::GetWindowDrawList();
        const auto wpos = ImGui::GetCursorScreenPos() + ImVec2( 1, 1 );
        const auto dpos = wpos + ImVec2( 0.5f, 0.5f );
        draw->AddRect( wpos - ImVec2( 1, 1 ), wpos + ImVec2( PageSize + 1, lines + 1 ), 0xFF666666 );
        draw->AddRectFilled( wpos, wpos + ImVec2( PageSize, lines ), 0xFF444444 );

        size_t line = 0;
        for( auto& page : pages )
        {
            size_t idx = 0;
            while( idx < PageSize )
            {
                if( page.data[idx] == 0 )
                {
                    do
                    {
                        idx++;
                    }
                    while( idx < PageSize && page.data[idx] == 0 );
                }
                else
                {
                    auto val = page.data[idx];
                    const auto i0 = idx;
                    do
                    {
                        idx++;
                    }
                    while( idx < PageSize && page.data[idx] == val );
                    DrawLine( draw, dpos + ImVec2( i0, line ), dpos + ImVec2( idx, line ), MemDecayColor[(uint8_t)val] );
                }
            }
            line++;
        }

        ImGui::EndChild();
        ImGui::TreePop();
    }

    ImGui::PushID( m_memInfo.pool );
    ImGui::Separator();
    if( ImGui::TreeNode( ICON_FA_TREE " Bottom-up call stack tree" ) )
    {
        ImGui::SameLine();
        DrawHelpMarker( "Press ctrl key to display allocation info tooltip. Right click on function name to display allocations list." );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        SmallCheckbox( "Group by function name", &m_groupCallstackTreeByNameBottomUp );
        ImGui::SameLine();
        DrawHelpMarker( "If enabled, only one source location will be displayed (which may be incorrect)." );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        bool activeOnlyBottomUp = m_memRangeBottomUp == MemRange::Active;
        if( SmallCheckbox( "Only active allocations", &activeOnlyBottomUp ) )
            m_memRangeBottomUp = activeOnlyBottomUp ? MemRange::Active : MemRange::Full;
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        bool inactiveOnlyBottomUp = m_memRangeBottomUp == MemRange::Inactive;
        if( SmallCheckbox( "Only inactive allocations", &inactiveOnlyBottomUp ) )
            m_memRangeBottomUp = inactiveOnlyBottomUp ? MemRange::Inactive : MemRange::Full;

        auto tree = GetCallstackFrameTreeBottomUp( mem );
        if( !tree.empty() )
        {
            int idx = 0;
            DrawFrameTreeLevel( tree, idx );
        }
        else
        {
            TextDisabledUnformatted( "No call stack data collected" );
        }

        ImGui::TreePop();
    }

    ImGui::Separator();
    if( ImGui::TreeNode( ICON_FA_TREE " Top-down call stack tree" ) )
    {
        ImGui::SameLine();
        DrawHelpMarker( "Press ctrl key to display allocation info tooltip. Right click on function name to display allocations list." );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        SmallCheckbox( "Group by function name", &m_groupCallstackTreeByNameTopDown );
        ImGui::SameLine();
        DrawHelpMarker( "If enabled, only one source location will be displayed (which may be incorrect)." );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        bool activeOnlyTopDown = m_memRangeTopDown == MemRange::Active;
        if( SmallCheckbox( "Only active allocations", &activeOnlyTopDown ) )
            m_memRangeTopDown = activeOnlyTopDown ? MemRange::Active : MemRange::Full;
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        bool inactiveOnlyTopDown = m_memRangeTopDown == MemRange::Inactive;
        if( SmallCheckbox( "Only inactive allocations", &inactiveOnlyTopDown ) )
            m_memRangeTopDown = inactiveOnlyTopDown ? MemRange::Inactive : MemRange::Full;

        auto tree = GetCallstackFrameTreeTopDown( mem );
        if( !tree.empty() )
        {
            int idx = 0;
            DrawFrameTreeLevel( tree, idx );
        }
        else
        {
            TextDisabledUnformatted( "No call stack data collected" );
        }

        ImGui::TreePop();
    }
    ImGui::PopID();

    ImGui::EndChild();
    ImGui::End();
}

void View::DrawMemoryAllocWindow()
{
    bool show = true;
    ImGui::Begin( "Memory allocation", &show, ImGuiWindowFlags_AlwaysAutoResize );
    if( !ImGui::GetCurrentWindowRead()->SkipItems )
    {
        const auto& mem = m_worker.GetMemoryNamed( m_memoryAllocInfoPool );
        const auto& ev = mem.data[m_memoryAllocInfoWindow];
        const auto tidAlloc = m_worker.DecompressThread( ev.ThreadAlloc() );
        const auto tidFree = m_worker.DecompressThread( ev.ThreadFree() );
        int idx = 0;

        if( ImGui::Button( ICON_FA_MICROSCOPE " Zoom to allocation" ) )
        {
            ZoomToRange( ev.TimeAlloc(), ev.TimeFree() >= 0 ? ev.TimeFree() : m_worker.GetLastTime() );
        }

        if( m_worker.GetMemNameMap().size() > 1 )
        {
            TextFocused( ICON_FA_BOX_ARCHIVE " Pool:", m_memoryAllocInfoPool == 0 ? "Default allocator" : m_worker.GetString( m_memoryAllocInfoPool ) );
        }
        char buf[64];
        sprintf( buf, "0x%" PRIx64, ev.Ptr() );
        TextFocused( "Address:", buf );
        TextFocused( "Size:", MemSizeToString( ev.Size() ) );
        if( ev.Size() >= 10000ll )
        {
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s bytes)", RealToString( ev.Size() ) );
        }
        ImGui::Separator();
        TextFocused( "Appeared at", TimeToStringExact( ev.TimeAlloc() ) );
        if( ImGui::IsItemClicked() ) CenterAtTime( ev.TimeAlloc() );
        ImGui::SameLine(); ImGui::Spacing(); ImGui::SameLine();
        SmallColorBox( GetThreadColor( tidAlloc, 0 ) );
        ImGui::SameLine();
        TextFocused( "Thread:", m_worker.GetThreadName( tidAlloc ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s)", RealToString( tidAlloc ) );
        if( m_worker.IsThreadFiber( tidAlloc ) )
        {
            ImGui::SameLine();
            TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
        }
        if( ev.CsAlloc() != 0 )
        {
            const auto cs = ev.CsAlloc();
            SmallCallstackButton( ICON_FA_ALIGN_JUSTIFY, cs, idx );
            ImGui::SameLine();
            DrawCallstackCalls( cs, 4 );
        }
        if( ev.TimeFree() < 0 )
        {
            TextDisabledUnformatted( "Allocation still active" );
        }
        else
        {
            TextFocused( "Freed at", TimeToStringExact( ev.TimeFree() ) );
            if( ImGui::IsItemClicked() ) CenterAtTime( ev.TimeFree() );
            ImGui::SameLine(); ImGui::Spacing(); ImGui::SameLine();
            SmallColorBox( GetThreadColor( tidFree, 0 ) );
            ImGui::SameLine();
            TextFocused( "Thread:", m_worker.GetThreadName( tidFree ) );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s)", RealToString( tidFree ) );
            if( m_worker.IsThreadFiber( tidFree ) )
            {
                ImGui::SameLine();
                TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
            }
            if( ev.csFree.Val() != 0 )
            {
                const auto cs = ev.csFree.Val();
                SmallCallstackButton( ICON_FA_ALIGN_JUSTIFY, cs, idx );
                ImGui::SameLine();
                DrawCallstackCalls( cs, 4 );
            }
            TextFocused( "Duration:", TimeToString( ev.TimeFree() - ev.TimeAlloc() ) );
        }

        bool sep = false;
        auto zoneAlloc = FindZoneAtTime( tidAlloc, ev.TimeAlloc() );
        if( zoneAlloc )
        {
            ImGui::Separator();
            sep = true;
            const auto& srcloc = m_worker.GetSourceLocation( zoneAlloc->SrcLoc() );
            const auto txt = srcloc.name.active ? m_worker.GetString( srcloc.name ) : m_worker.GetString( srcloc.function );
            ImGui::PushID( idx++ );
            TextFocused( "Zone alloc:", txt );
            auto hover = ImGui::IsItemHovered();
            ImGui::PopID();
            if( ImGui::IsItemClicked() )
            {
                ShowZoneInfo( *zoneAlloc );
            }
            if( hover )
            {
                m_zoneHighlight = zoneAlloc;
                if( IsMouseClicked( 2 ) )
                {
                    ZoomToZone( *zoneAlloc );
                }
                ZoneTooltip( *zoneAlloc );
            }
        }

        if( ev.TimeFree() >= 0 )
        {
            auto zoneFree = FindZoneAtTime( tidFree, ev.TimeFree() );
            if( zoneFree )
            {
                if( !sep ) ImGui::Separator();
                const auto& srcloc = m_worker.GetSourceLocation( zoneFree->SrcLoc() );
                const auto txt = srcloc.name.active ? m_worker.GetString( srcloc.name ) : m_worker.GetString( srcloc.function );
                TextFocused( "Zone free:", txt );
                auto hover = ImGui::IsItemHovered();
                if( ImGui::IsItemClicked() )
                {
                    ShowZoneInfo( *zoneFree );
                }
                if( hover )
                {
                    m_zoneHighlight = zoneFree;
                    if( IsMouseClicked( 2 ) )
                    {
                        ZoomToZone( *zoneFree );
                    }
                    ZoneTooltip( *zoneFree );
                }
                if( zoneAlloc == zoneFree )
                {
                    ImGui::SameLine();
                    TextDisabledUnformatted( "(same zone)" );
                }
            }
        }
    }
    ImGui::End();
    if( !show ) m_memoryAllocInfoWindow = -1;
}

void View::ListMemData( std::vector<const MemEvent*>& vec, const std::function<void(const MemEvent*)>& DrawAddress, int64_t startTime, uint64_t pool )
{
    if( startTime == -1 ) startTime = 0;
    if( ImGui::BeginTable( "##mem", 8, ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable | ImGuiTableFlags_Sortable | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY, ImVec2( 0, ImGui::GetTextLineHeightWithSpacing() * std::min<int64_t>( 1+vec.size(), 15 ) ) ) )
    {
        ImGui::TableSetupScrollFreeze( 0, 1 );
        ImGui::TableSetupColumn( "Address", ImGuiTableColumnFlags_NoHide );
        ImGui::TableSetupColumn( "Size", ImGuiTableColumnFlags_PreferSortDescending );
        ImGui::TableSetupColumn( "Appeared at", ImGuiTableColumnFlags_DefaultSort );
        ImGui::TableSetupColumn( "Duration", ImGuiTableColumnFlags_PreferSortDescending );
        ImGui::TableSetupColumn( "Thread", ImGuiTableColumnFlags_NoSort );
        ImGui::TableSetupColumn( "Zone alloc", ImGuiTableColumnFlags_NoSort );
        ImGui::TableSetupColumn( "Zone free", ImGuiTableColumnFlags_NoSort );
        ImGui::TableSetupColumn( "Call stack", ImGuiTableColumnFlags_NoSort );
        ImGui::TableHeadersRow();

        const auto& mem = m_worker.GetMemoryNamed( pool );
        const auto& sortspec = *ImGui::TableGetSortSpecs()->Specs;
        switch( sortspec.ColumnIndex )
        {
        case 0:
            if( sortspec.SortDirection == ImGuiSortDirection_Ascending )
            {
                pdqsort_branchless( vec.begin(), vec.end(), []( const auto& l, const auto& r ) { return l->Ptr() < r->Ptr(); } );
            }
            else
            {
                pdqsort_branchless( vec.begin(), vec.end(), []( const auto& l, const auto& r ) { return l->Ptr() > r->Ptr(); } );
            }
            break;
        case 1:
            if( sortspec.SortDirection == ImGuiSortDirection_Ascending )
            {
                pdqsort_branchless( vec.begin(), vec.end(), []( const auto& l, const auto& r ) { return l->Size() < r->Size(); } );
            }
            else
            {
                pdqsort_branchless( vec.begin(), vec.end(), []( const auto& l, const auto& r ) { return l->Size() > r->Size(); } );
            }
            break;
        case 2:
            if( sortspec.SortDirection == ImGuiSortDirection_Descending )
            {
                std::reverse( vec.begin(), vec.end() );
            }
            break;
        case 3:
            if( sortspec.SortDirection == ImGuiSortDirection_Ascending )
            {
                pdqsort_branchless( vec.begin(), vec.end(), []( const auto& l, const auto& r ) { return ( l->TimeFree() - l->TimeAlloc() ) < ( r->TimeFree() - r->TimeAlloc() ); } );
            }
            else
            {
                pdqsort_branchless( vec.begin(), vec.end(), []( const auto& l, const auto& r ) { return ( l->TimeFree() - l->TimeAlloc() ) > ( r->TimeFree() - r->TimeAlloc() ); } );
            }
            break;
        default:
            assert( false );
            break;
        }

        int idx = 0;
        ImGuiListClipper clipper;
        clipper.Begin( vec.end() - vec.begin() );
        while( clipper.Step() )
        {
            for( auto i=clipper.DisplayStart; i<clipper.DisplayEnd; i++ )
            {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();

                auto v = vec[i];
                const auto arrIdx = std::distance( mem.data.begin(), v );

                ImGui::PushFont( m_fixedFont );
                if( m_memoryAllocInfoPool == pool && m_memoryAllocInfoWindow == arrIdx )
                {
                    ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 1.f, 0.f, 0.f, 1.f ) );
                    DrawAddress( v );
                    ImGui::PopStyleColor();
                }
                else
                {
                    DrawAddress( v );
                    if( ImGui::IsItemClicked() )
                    {
                        m_memoryAllocInfoWindow = arrIdx;
                        m_memoryAllocInfoPool = pool;
                    }
                }
                ImGui::PopFont();
                if( ImGui::IsItemClicked( 2 ) )
                {
                    ZoomToRange( v->TimeAlloc(), v->TimeFree() >= 0 ? v->TimeFree() : m_worker.GetLastTime() );
                }
                if( ImGui::IsItemHovered() )
                {
                    m_memoryAllocHover = arrIdx;
                    m_memoryAllocHoverWait = 2;
                    m_memoryAllocHoverPool = pool;
                }
                ImGui::TableNextColumn();
                ImGui::TextUnformatted( MemSizeToString( v->Size() ) );
                ImGui::TableNextColumn();
                ImGui::PushID( idx++ );
                if( ImGui::Selectable( TimeToStringExact( v->TimeAlloc() - startTime ) ) )
                {
                    CenterAtTime( v->TimeAlloc() );
                }
                ImGui::PopID();
                ImGui::TableNextColumn();
                if( v->TimeFree() < 0 )
                {
                    TextColoredUnformatted( ImVec4( 0.6f, 1.f, 0.6f, 1.f ), TimeToString( m_worker.GetLastTime() - v->TimeAlloc() ) );
                    ImGui::TableNextColumn();
                    const auto tid = m_worker.DecompressThread( v->ThreadAlloc() );
                    SmallColorBox( GetThreadColor( tid, 0 ) );
                    ImGui::SameLine();
                    ImGui::TextUnformatted( m_worker.GetThreadName( tid ) );
                }
                else
                {
                    ImGui::PushID( idx++ );
                    if( ImGui::Selectable( TimeToString( v->TimeFree() - v->TimeAlloc() ) ) )
                    {
                        CenterAtTime( v->TimeFree() );
                    }
                    ImGui::PopID();
                    ImGui::TableNextColumn();
                    if( v->ThreadAlloc() == v->ThreadFree() )
                    {
                        const auto tid = m_worker.DecompressThread( v->ThreadAlloc() );
                        SmallColorBox( GetThreadColor( tid, 0 ) );
                        ImGui::SameLine();
                        ImGui::TextUnformatted( m_worker.GetThreadName( tid ) );
                    }
                    else
                    {
                        const auto tidAlloc = m_worker.DecompressThread( v->ThreadAlloc() );
                        const auto tidFree = m_worker.DecompressThread( v->ThreadFree() );
                        SmallColorBox( GetThreadColor( tidAlloc, 0 ) );
                        ImGui::SameLine();
                        ImGui::TextUnformatted( m_worker.GetThreadName( tidAlloc ) );
                        ImGui::SameLine();
                        ImGui::TextUnformatted( "/" );
                        ImGui::SameLine();
                        SmallColorBox( GetThreadColor( tidFree, 0 ) );
                        ImGui::SameLine();
                        ImGui::TextUnformatted( m_worker.GetThreadName( tidFree ) );
                    }
                }
                ImGui::TableNextColumn();
                auto zone = FindZoneAtTime( m_worker.DecompressThread( v->ThreadAlloc() ), v->TimeAlloc() );
                if( !zone )
                {
                    ImGui::TextUnformatted( "-" );
                }
                else
                {
                    const auto& srcloc = m_worker.GetSourceLocation( zone->SrcLoc() );
                    const auto txt = srcloc.name.active ? m_worker.GetString( srcloc.name ) : m_worker.GetString( srcloc.function );
                    ImGui::PushID( idx++ );
                    auto sel = ImGui::Selectable( txt, m_zoneInfoWindow == zone );
                    auto hover = ImGui::IsItemHovered();
                    ImGui::PopID();
                    if( sel )
                    {
                        ShowZoneInfo( *zone );
                    }
                    if( hover )
                    {
                        m_zoneHighlight = zone;
                        if( IsMouseClicked( 2 ) )
                        {
                            ZoomToZone( *zone );
                        }
                        ZoneTooltip( *zone );
                    }
                }
                ImGui::TableNextColumn();
                if( v->TimeFree() < 0 )
                {
                    TextColoredUnformatted( ImVec4( 0.6f, 1.f, 0.6f, 1.f ), "active" );
                }
                else
                {
                    auto zoneFree = FindZoneAtTime( m_worker.DecompressThread( v->ThreadFree() ), v->TimeFree() );
                    if( !zoneFree )
                    {
                        ImGui::TextUnformatted( "-" );
                    }
                    else
                    {
                        const auto& srcloc = m_worker.GetSourceLocation( zoneFree->SrcLoc() );
                        const auto txt = srcloc.name.active ? m_worker.GetString( srcloc.name ) : m_worker.GetString( srcloc.function );
                        ImGui::PushID( idx++ );
                        bool sel;
                        if( zoneFree == zone )
                        {
                            ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 1.f, 1.f, 0.6f, 1.f ) );
                            sel = ImGui::Selectable( txt, m_zoneInfoWindow == zoneFree );
                            ImGui::PopStyleColor( 1 );
                        }
                        else
                        {
                            sel = ImGui::Selectable( txt, m_zoneInfoWindow == zoneFree );
                        }
                        auto hover = ImGui::IsItemHovered();
                        ImGui::PopID();
                        if( sel )
                        {
                            ShowZoneInfo( *zoneFree );
                        }
                        if( hover )
                        {
                            m_zoneHighlight = zoneFree;
                            if( IsMouseClicked( 2 ) )
                            {
                                ZoomToZone( *zoneFree );
                            }
                            ZoneTooltip( *zoneFree );
                        }
                    }
                }
                ImGui::TableNextColumn();
                if( v->CsAlloc() == 0 )
                {
                    TextDisabledUnformatted( "[alloc]" );
                }
                else
                {
                    SmallCallstackButton( "alloc", v->CsAlloc(), idx );
                }
                ImGui::SameLine();
                ImGui::Spacing();
                ImGui::SameLine();
                if( v->csFree.Val() == 0 )
                {
                    TextDisabledUnformatted( "[free]" );
                }
                else
                {
                    SmallCallstackButton( "free", v->csFree.Val(), idx );
                }
            }
        }
        ImGui::EndTable();
    }
}

void View::DrawAllocList()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 1100 * scale, 500 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Allocations list", &m_memInfo.showAllocList );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }

    std::vector<const MemEvent*> data;
    auto basePtr = m_worker.GetMemoryNamed( m_memInfo.pool ).data.data();
    data.reserve( m_memInfo.allocList.size() );
    for( auto& idx : m_memInfo.allocList )
    {
        data.emplace_back( basePtr + idx );
    }

    TextFocused( "Number of allocations:", RealToString( m_memInfo.allocList.size() ) );
    ListMemData( data, []( auto v ) {
        ImGui::Text( "0x%" PRIx64, v->Ptr() );
        }, -1, m_memInfo.pool );
    ImGui::End();
}

}
