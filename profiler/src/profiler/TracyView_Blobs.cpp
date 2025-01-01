#include "TracyImGui.hpp"
#include "TracyPrint.hpp"
#include "TracyTexture.hpp"
#include "TracyView.hpp"

#include <cinttypes>
#include "imgui_memory_editor.h"

namespace tracy
{

void View::DrawBlobs()
{
    const auto& blobs = m_worker.GetBlobs();

    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 1200 * scale, 600 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Blobs", &m_showBlobs );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }

    if( blobs.empty() )
    {
        const auto ty = ImGui::GetTextLineHeight();
        ImGui::PushFont( m_bigFont );
        ImGui::Dummy( ImVec2( 0, ( ImGui::GetContentRegionAvail().y - ImGui::GetTextLineHeight() * 2 ) * 0.5f ) );
        TextCentered( ICON_FA_FISH_FINS );
        TextCentered( "No blobs were collected" );
        ImGui::PopFont();
        ImGui::End();
        return;
    }

    ImGui::BeginChild( "Blobs View", ImVec2( 600 * scale, 0 ), ImGuiChildFlags_Borders );
    bool filterChanged = m_blobFilter.Draw( ICON_FA_FILTER " Filter blobs", 200 );
    ImGui::SameLine();
    if( ImGui::Button( ICON_FA_DELETE_LEFT " Clear" ) )
    {
        m_blobFilter.Clear();
        filterChanged = true;
    }
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    TextFocused( "Total blob count:", RealToString( blobs.size() ) );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    TextFocused( "Visible blobs:", RealToString( m_visibleBlobs ) );

    bool threadsChanged = false;
    auto expand = ImGui::TreeNode( ICON_FA_SHUFFLE " Visible threads:" );
    ImGui::SameLine();
    size_t visibleThreads = 0;
    size_t tsz = 0;
    for( const auto& t : m_threadOrder )
    {
        if( t->blobs.empty() ) continue;
        if( VisibleBlobThread( t->id ) ) visibleThreads++;
        tsz++;
    }
    if( visibleThreads == tsz )
    {
        ImGui::TextDisabled( "(%zu)", tsz );
    }
    else
    {
        ImGui::TextDisabled( "(%zu/%zu)", visibleThreads, tsz );
    }
    if( expand )
    {
        auto& crash = m_worker.GetCrashEvent();

        ImGui::SameLine();
        if( ImGui::SmallButton( "Select all" ) )
        {
            for( const auto& t : m_threadOrder )
            {
                VisibleBlobThread( t->id ) = true;
            }
            threadsChanged = true;
        }
        ImGui::SameLine();
        if( ImGui::SmallButton( "Unselect all" ) )
        {
            for( const auto& t : m_threadOrder )
            {
                VisibleBlobThread( t->id ) = false;
            }
            threadsChanged = true;
        }

        int idx = 0;
        for( const auto& t : m_threadOrder )
        {
            if( t->blobs.empty() ) continue;
            ImGui::PushID( idx++ );
            const auto threadColor = GetThreadColor( t->id, 0 );
            SmallColorBox( threadColor );
            ImGui::SameLine();
            if( SmallCheckbox( m_worker.GetThreadName( t->id ), &VisibleBlobThread( t->id ) ) )
            {
                threadsChanged = true;
            }
            ImGui::PopID();
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s)", RealToString( t->blobs.size() ) );
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

    const bool blobsChanged = blobs.size() != m_prevBlobs;
    if( filterChanged || threadsChanged )
    {
        bool showCallstack = false;
        m_blobList.reserve( blobs.size() );
        m_blobList.clear();
        if( m_blobFilter.IsActive() )
        {
            for( size_t i=0; i<blobs.size(); i++ )
            {
                const auto& v = blobs[i];
                const auto tid = m_worker.DecompressThread( v->thread );
                if( VisibleBlobThread( tid ) )
                {
                    const auto text = m_worker.GetString( blobs[i]->ref );
                    if( m_blobFilter.PassFilter( text ) )
                    {
                        if( !showCallstack && blobs[i]->callstack.Val() != 0 ) showCallstack = true;
                        m_blobList.push_back_no_space_check( uint32_t( i ) );
                    }
                }
            }
        }
        else
        {
            for( size_t i=0; i<blobs.size(); i++ )
            {
                const auto& v = blobs[i];
                const auto tid = m_worker.DecompressThread( v->thread );
                if( VisibleBlobThread( tid ) )
                {
                    if( !showCallstack && blobs[i]->callstack.Val() != 0 ) showCallstack = true;
                    m_blobList.push_back_no_space_check( uint32_t( i ) );
                }
            }
        }
        m_blobsShowCallstack = showCallstack;
        m_visibleBlobs = m_blobList.size();
        if( blobsChanged ) m_prevBlobs = blobs.size();
    }
    else if( blobsChanged )
    {
        assert( m_prevBlobs < blobs.size() );
        bool showCallstack = m_blobsShowCallstack;
        m_blobList.reserve( blobs.size() );
        if( m_blobFilter.IsActive() )
        {
            for( size_t i=m_prevBlobs; i<blobs.size(); i++ )
            {
                const auto& v = blobs[i];
                const auto tid = m_worker.DecompressThread( v->thread );
                if( VisibleBlobThread( tid ) )
                {
                    const auto text = m_worker.GetString( blobs[i]->ref );
                    if( m_blobFilter.PassFilter( text ) )
                    {
                        if( !showCallstack && blobs[i]->callstack.Val() != 0 ) showCallstack = true;
                        m_blobList.push_back_no_space_check( uint32_t( i ) );
                    }
                }
            }
        }
        else
        {
            for( size_t i=m_prevBlobs; i<blobs.size(); i++ )
            {
                const auto& v = blobs[i];
                const auto tid = m_worker.DecompressThread( v->thread );
                if( VisibleBlobThread( tid ) )
                {
                    if( !showCallstack && blobs[i]->callstack.Val() != 0 ) showCallstack = true;
                    m_blobList.push_back_no_space_check( uint32_t( i ) );
                }
            }
        }
        m_blobsShowCallstack = showCallstack;
        m_visibleBlobs = m_blobList.size();
        m_prevBlobs = blobs.size();
    }

    bool hasCallstack = m_blobsShowCallstack;
    ImGui::Separator();
    ImGui::BeginChild( "##blobs" );
    const int colNum = hasCallstack ? 4 : 3;
    if( ImGui::BeginTable( "##blobs", colNum, ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Hideable ) )
    {
        ImGui::TableSetupScrollFreeze( 0, 1 );
        ImGui::TableSetupColumn( "Time", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
        ImGui::TableSetupColumn( "Thread" );
        ImGui::TableSetupColumn( "Encoding" );
        if( hasCallstack ) ImGui::TableSetupColumn( "Call stack" );
        ImGui::TableHeadersRow();

        int idx = 0;
        if( m_blobToFocus )
        {
            {
            }
        }
        else
        {
            ImGuiListClipper clipper;
            clipper.Begin( m_blobList.size() );
            while( clipper.Step() )
            {
                for( auto i=clipper.DisplayStart; i<clipper.DisplayEnd; i++ )
                {
                    DrawBlobLine( *blobs[m_blobList[i]], hasCallstack, idx );
                }
            }
        }

        if( m_worker.IsConnected() && ImGui::GetScrollY() >= ImGui::GetScrollMaxY() )
        {
            ImGui::SetScrollHereY( 1.f );
        }
        ImGui::EndTable();

    }
    ImGui::EndChild();
    ImGui::EndChild();

    if( m_blobSelected )
    {
        ImGui::SameLine();
        ImGui::BeginChild("##blob hexdump", ImVec2( 600 * scale, 0 ), ImGuiChildFlags_Borders, ImGuiWindowFlags_NoScrollbar);
        ImGui::TextDisabled( "Blob at %s", TimeToStringExact( m_blobSelected->time ) );
        size_t sz;
        const auto data = m_worker.GetData( m_blobSelected->ref, &sz );
        static MemoryEditor mem_edit;
        mem_edit.DrawContents((void*)data, sz, 0);
        ImGui::EndChild();
    }

    ImGui::End();
}

void View::DrawBlobLine( const BlobData& blob, bool hasCallstack, int& idx )
{
    ImGui::TableNextRow();
    ImGui::TableNextColumn();
    const auto tid = m_worker.DecompressThread( blob.thread );
    ImGui::PushID( &blob );
    if( ImGui::Selectable( TimeToStringExact( blob.time ), m_blobHighlight == &blob, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap ) )
    {
        CenterAtTime( blob.time );
        m_blobSelected = &blob;
    }
    if( m_blobToFocus == &blob )
    {
        ImGui::SetScrollHereY();
        m_blobToFocus.Decay( nullptr );
        m_blobsScrollBottom = false;
    }
    ImGui::PopID();
    ImGui::TableNextColumn();
    SmallColorBox( GetThreadColor( tid, 0 ) );
    ImGui::SameLine();
    if( m_worker.IsThreadFiber( tid ) )
    {
        TextColoredUnformatted( 0xFF88FF88, m_worker.GetThreadName( tid ) );
    }
    else
    {
        ImGui::TextUnformatted( m_worker.GetThreadName( tid ) );
    }
    ImGui::SameLine();
    ImGui::TextDisabled( "(%s)", RealToString( tid ) );

    ImGui::TableNextColumn();
    ImGui::TextDisabled( "%" PRIu64, blob.encoding);

    if( hasCallstack )
    {
        ImGui::TableNextColumn();
        const auto cs = blob.callstack.Val();
        if( cs != 0 )
        {
            SmallCallstackButton( ICON_FA_ALIGN_JUSTIFY, cs, idx );
            ImGui::SameLine();
            DrawCallstackCalls( cs, 6 );
        }
    }
}

}
