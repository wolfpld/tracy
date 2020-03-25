#include <inttypes.h>
#include <stdio.h>

#include "../imgui/imgui.h"
#include "TracyImGui.hpp"
#include "TracyPrint.hpp"
#include "TracySourceView.hpp"
#include "TracyWorker.hpp"

namespace tracy
{

SourceView::SourceView( ImFont* font )
    : m_font( font )
    , m_file( nullptr )
    , m_symAddr( 0 )
    , m_data( nullptr )
    , m_dataSize( 0 )
    , m_targetLine( 0 )
    , m_selectedLine( 0 )
{
}

SourceView::~SourceView()
{
    delete[] m_data;
}

void SourceView::Open( const char* fileName, int line, uint64_t symAddr )
{
    m_targetLine = line;
    m_selectedLine = line;
    m_symAddr = symAddr;

    if( m_file != fileName )
    {
        m_file = fileName;
        FILE* f = fopen( fileName, "rb" );
        fseek( f, 0, SEEK_END );
        const auto sz = ftell( f );
        fseek( f, 0, SEEK_SET );
        if( sz > m_dataSize )
        {
            delete[] m_data;
            m_data = new char[sz+1];
            m_dataSize = sz;
        }
        fread( m_data, 1, sz, f );
        m_data[sz] = '\0';
        fclose( f );

        m_lines.clear();
        auto txt = m_data;
        for(;;)
        {
            auto end = txt;
            while( *end != '\n' && *end != '\r' && end - m_data < sz ) end++;
            m_lines.emplace_back( Line { txt, end } );
            if( *end == '\n' )
            {
                end++;
                if( *end == '\r' ) end++;
            }
            else if( *end == '\r' )
            {
                end++;
                if( *end == '\n' ) end++;
            }
            if( *end == '\0' ) break;
            txt = end;
        }
    }
}

void SourceView::Render( const Worker& worker )
{
    uint32_t iptotal = 0;
    unordered_flat_map<uint32_t, uint32_t> ipcount;
    auto ipmap = m_symAddr != 0 ? worker.GetSymbolInstructionPointers( m_symAddr ) : nullptr;
    if( ipmap )
    {
        for( auto& ip : *ipmap )
        {
            auto frame = worker.GetCallstackFrame( ip.first );
            if( frame )
            {
                auto ffn = worker.GetString( frame->data[0].file );
                if( strcmp( ffn, m_file ) == 0 )
                {
                    const auto line = frame->data[0].line;
                    auto it = ipcount.find( line );
                    if( it == ipcount.end() )
                    {
                        ipcount.emplace( line, ip.second );
                    }
                    else
                    {
                        it->second += ip.second;
                    }
                    iptotal += ip.second;
                }
            }
        }
        auto sym = worker.GetSymbolData( m_symAddr );
        if( sym )
        {
            TextFocused( "Showing profiling data for:", worker.GetString( sym->name ) );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%" PRIu32 " samples)", iptotal );
        }
    }

    ImGui::BeginChild( "##sourceView", ImVec2( 0, 0 ), true );
    if( m_font ) ImGui::PushFont( m_font );
    const auto nw = ImGui::CalcTextSize( "123,345" ).x;
    if( m_targetLine != 0 )
    {
        int lineNum = 1;
        for( auto& line : m_lines )
        {
            if( m_targetLine == lineNum )
            {
                m_targetLine = 0;
                ImGui::SetScrollHereY();
            }
            RenderLine( line, lineNum++, 0, iptotal );
        }
    }
    else
    {
        ImGuiListClipper clipper( m_lines.size() );
        while( clipper.Step() )
        {
            if( iptotal == 0 )
            {
                for( auto i=clipper.DisplayStart; i<clipper.DisplayEnd; i++ )
                {
                    RenderLine( m_lines[i], i+1, 0, 0 );
                }
            }
            else
            {
                for( auto i=clipper.DisplayStart; i<clipper.DisplayEnd; i++ )
                {
                    auto it = ipcount.find( i+1 );
                    const auto ipcnt = it == ipcount.end() ? 0 : it->second;
                    RenderLine( m_lines[i], i+1, ipcnt, iptotal );
                }
            }
        }
    }
    if( m_font ) ImGui::PopFont();
    ImGui::EndChild();
}

void SourceView::RenderLine( const Line& line, int lineNum, uint32_t ipcnt, uint32_t iptotal )
{
    const auto ty = ImGui::GetFontSize();
    auto draw = ImGui::GetWindowDrawList();
    const auto w = ImGui::GetWindowWidth();
    const auto wpos = ImGui::GetCursorScreenPos();
    if( lineNum == m_selectedLine )
    {
        draw->AddRectFilled( wpos, wpos + ImVec2( w, ty+1 ), 0xFF333322 );
    }

    if( iptotal != 0 )
    {
        if( ipcnt == 0 )
        {
            ImGui::TextUnformatted( "       " );
        }
        else
        {
            char tmp[16];
            auto end = PrintFloat( tmp, tmp+16, 100.f * ipcnt / iptotal, 2 );
            memcpy( end, "%", 2 );
            end++;
            const auto sz = end - tmp;
            char buf[16];
            memset( buf, ' ', 7-sz );
            memcpy( buf + 7 - sz, tmp, sz+1 );
            ImGui::TextUnformatted( buf );
        }
        ImGui::SameLine( 0, ty );
    }

    const auto lineString = RealToString( lineNum );
    const auto linesz = strlen( lineString );
    char buf[16];
    memset( buf, ' ', 7 - linesz );
    memcpy( buf + 7 - linesz, lineString, linesz+1 );
    TextDisabledUnformatted( buf );
    ImGui::SameLine( 0, ty );
    ImGui::TextUnformatted( line.begin, line.end );

    draw->AddLine( wpos + ImVec2( 0, ty+2 ), wpos + ImVec2( w, ty+2 ), 0x08FFFFFF );
}

}
