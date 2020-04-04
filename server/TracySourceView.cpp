#include <inttypes.h>
#include <stdio.h>

#include <capstone/capstone.h>

#include "../imgui/imgui.h"
#include "TracyColor.hpp"
#include "TracyFilesystem.hpp"
#include "TracyImGui.hpp"
#include "TracyPrint.hpp"
#include "TracySort.hpp"
#include "TracySourceView.hpp"
#include "TracyWorker.hpp"

#include "IconsFontAwesome5.h"

namespace tracy
{

enum { JumpSeparation = 6 };
enum { JumpArrow = 9 };

SourceView::SourceView( ImFont* font )
    : m_font( font )
    , m_file( nullptr )
    , m_fileStringIdx( 0 )
    , m_symAddr( 0 )
    , m_currentAddr( 0 )
    , m_targetAddr( 0 )
    , m_data( nullptr )
    , m_dataSize( 0 )
    , m_targetLine( 0 )
    , m_selectedLine( 0 )
    , m_showAsm( false )
    , m_codeLen( 0 )
    , m_highlightAddr( 0 )
    , m_asmRelative( false )
    , m_asmShowSourceLocation( true )
    , m_showJumps( true )
{
}

SourceView::~SourceView()
{
    delete[] m_data;
}

void SourceView::Open( const char* fileName, int line, uint64_t baseAddr, uint64_t symAddr, const Worker& worker )
{
    m_targetLine = line;
    m_selectedLine = line;
    m_targetAddr = symAddr;
    m_baseAddr = baseAddr;
    m_symAddr = symAddr;
    m_currentAddr = symAddr;

    if( m_file != fileName )
    {
        m_file = fileName;
        m_fileStringIdx = worker.FindStringIdx( fileName );
        m_lines.clear();
        if( fileName )
        {
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

    if( m_lines.empty() ) m_showAsm = true;
    if( !Disassemble( baseAddr, worker ) ) m_showAsm = false;
    assert( m_showAsm || !m_lines.empty() );
}

bool SourceView::Disassemble( uint64_t symAddr, const Worker& worker )
{
    m_asm.clear();
    m_jumpTable.clear();
    m_jumpOut.clear();
    m_maxJumpLevel = 0;
    if( symAddr == 0 ) return false;
    const auto arch = worker.GetCpuArch();
    if( arch == CpuArchUnknown ) return false;
    uint32_t len;
    auto code = worker.GetSymbolCode( symAddr, len );
    if( !code ) return false;
    csh handle;
    cs_err rval = CS_ERR_ARCH;
    switch( arch )
    {
    case CpuArchX86:
        rval = cs_open( CS_ARCH_X86, CS_MODE_32, &handle );
        break;
    case CpuArchX64:
        rval = cs_open( CS_ARCH_X86, CS_MODE_64, &handle );
        break;
    case CpuArchArm32:
        rval = cs_open( CS_ARCH_ARM, CS_MODE_ARM, &handle );
        break;
    case CpuArchArm64:
        rval = cs_open( CS_ARCH_ARM64, CS_MODE_ARM, &handle );
        break;
    default:
        assert( false );
        break;
    }
    if( rval != CS_ERR_OK ) return false;
    cs_option( handle, CS_OPT_DETAIL, CS_OPT_ON );
    cs_insn* insn;
    size_t cnt = cs_disasm( handle, (const uint8_t*)code, len, symAddr, 0, &insn );
    if( cnt > 0 )
    {
        m_asm.reserve( cnt );
        for( size_t i=0; i<cnt; i++ )
        {
            const auto& op = insn[i];
            const auto& detail = *op.detail;
            bool hasJump = false;
            for( auto j=0; j<detail.groups_count; j++ )
            {
                if( detail.groups[j] == CS_GRP_JUMP || detail.groups[j] == CS_GRP_CALL )
                {
                    hasJump = true;
                    break;
                }
            }
            uint64_t jumpAddr = 0;
            if( hasJump )
            {
                switch( arch )
                {
                case CpuArchX86:
                case CpuArchX64:
                    if( detail.x86.op_count == 1 && detail.x86.operands[0].type == X86_OP_IMM )
                    {
                        jumpAddr = (uint64_t)detail.x86.operands[0].imm;
                    }
                    break;
                case CpuArchArm32:
                    if( detail.arm.op_count == 1 && detail.arm.operands[0].type == ARM_OP_IMM )
                    {
                        jumpAddr = (uint64_t)detail.arm.operands[0].imm;
                    }
                    break;
                case CpuArchArm64:
                    if( detail.arm64.op_count == 1 && detail.arm64.operands[0].type == ARM64_OP_IMM )
                    {
                        jumpAddr = (uint64_t)detail.arm64.operands[0].imm;
                    }
                    break;
                default:
                    assert( false );
                    break;
                }
                if( jumpAddr >= symAddr && jumpAddr < symAddr + len )
                {
                    const auto min = std::min( jumpAddr, op.address );
                    const auto max = std::max( jumpAddr, op.address );
                    auto it = m_jumpTable.find( jumpAddr );
                    if( it == m_jumpTable.end() )
                    {
                        m_jumpTable.emplace( jumpAddr, JumpData { min, max, 0, { op.address } } );
                    }
                    else
                    {
                        if( it->second.min > min ) it->second.min = min;
                        else if( it->second.max < max ) it->second.max = max;
                        it->second.source.emplace_back( op.address );
                    }
                }
                else
                {
                    m_jumpOut.emplace( op.address );
                }
            }
            m_asm.emplace_back( AsmLine { op.address, jumpAddr, op.mnemonic, op.op_str } );
        }
        cs_free( insn, cnt );
        if( !m_jumpTable.empty() )
        {
            struct JumpRange
            {
                uint64_t target;
                uint64_t len;
            };
            std::vector<JumpRange> jumpRange;
            jumpRange.reserve( m_jumpTable.size() );
            for( auto& v : m_jumpTable )
            {
                pdqsort_branchless( v.second.source.begin(), v.second.source.end() );
                jumpRange.emplace_back( JumpRange { v.first, v.second.max - v.second.min } );
            }
            pdqsort_branchless( jumpRange.begin(), jumpRange.end(), []( const auto& l, const auto& r ) { return l.len < r.len; } );
            std::vector<std::vector<std::pair<uint64_t, uint64_t>>> levelRanges;
            for( auto& v : jumpRange )
            {
                auto it = m_jumpTable.find( v.target );
                assert( it != m_jumpTable.end() );
                int level = 0;
                for(;;)
                {
                    assert( levelRanges.size() >= level );
                    if( levelRanges.size() == level )
                    {
                        it->second.level = level;
                        levelRanges.push_back( { { it->second.min, it->second.max } } );
                        break;
                    }
                    else
                    {
                        bool validFit = true;
                        auto& lr = levelRanges[level];
                        for( auto& range : lr )
                        {
                            assert( !( it->second.min >= range.first && it->second.max <= range.second ) );
                            if( it->second.min <= range.second && it->second.max >= range.first )
                            {
                                validFit = false;
                                break;
                            }
                        }
                        if( validFit )
                        {
                            it->second.level = level;
                            lr.emplace_back( it->second.min, it->second.max );
                            break;
                        }
                        level++;
                    }
                }
                if( level > m_maxJumpLevel ) m_maxJumpLevel = level;
            }
        }
    }
    cs_close( &handle );
    m_codeLen = len;
    return true;
}

void SourceView::Render( const Worker& worker )
{
    m_highlightAddr.Decay( 0 );

    if( m_file ) TextFocused( "File:", m_file );

    if( !m_asm.empty() && !m_lines.empty() )
    {
        if( SmallCheckbox( ICON_FA_MICROCHIP " Show assembly", &m_showAsm ) )
        {
            if( m_showAsm )
            {
                m_targetAddr = m_symAddr;
            }
            else
            {
                m_targetLine = m_selectedLine;
            }
        }
    }
    if( !m_asm.empty() )
    {
        if( !m_lines.empty() )
        {
            ImGui::SameLine();
            ImGui::Spacing();
            ImGui::SameLine();
        }
        TextFocused( "Code size:", MemSizeToString( m_codeLen ) );
    }

    uint32_t iptotal = 0;
    unordered_flat_map<uint64_t, uint32_t> ipcount;
    auto ipmap = m_symAddr != 0 ? worker.GetSymbolInstructionPointers( m_symAddr ) : nullptr;
    if( ipmap )
    {
        if( m_showAsm )
        {
            for( auto& ip : *ipmap )
            {
                auto addr = worker.GetCanonicalPointer( ip.first );
                assert( ipcount.find( addr ) == ipcount.end() );
                ipcount.emplace( addr, ip.second );
                iptotal += ip.second;
            }
        }
        else
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
        }

        if( iptotal > 0 )
        {
            ImGui::SameLine();
            ImGui::Spacing();
            ImGui::SameLine();
            TextFocused( "Samples:", RealToString( iptotal ) );
        }
    }

    auto sym = worker.GetSymbolData( m_symAddr );
    if( sym )
    {
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextFocused( "Symbol:", worker.GetString( sym->name ) );
        if( sym->isInline )
        {
            auto parent = worker.GetSymbolData( m_baseAddr );
            if( parent )
            {
                ImGui::SameLine();
                ImGui::TextDisabled( "(%s)", worker.GetString( parent->name ) );
            }
        }
    }

    if( !m_showAsm )
    {
        TextColoredUnformatted( ImVec4( 1.f, 1.f, 0.2f, 1.f ), ICON_FA_EXCLAMATION_TRIANGLE );
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 1.f, 0.3f, 0.3f, 1.f ), "The source file contents might not reflect the actual profiled code!" );
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 1.f, 1.f, 0.2f, 1.f ), ICON_FA_EXCLAMATION_TRIANGLE );
    }
    else
    {
        SmallCheckbox( ICON_FA_SEARCH_LOCATION " Relative locations", &m_asmRelative );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        SmallCheckbox( ICON_FA_FILE_IMPORT " Show source locations", &m_asmShowSourceLocation );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        SmallCheckbox( ICON_FA_SHARE " Draw jumps", &m_showJumps );
    }

    uint64_t jumpOut = 0;
    ImGui::BeginChild( "##sourceView", ImVec2( 0, 0 ), true );
    if( m_font ) ImGui::PushFont( m_font );
    if( m_showAsm )
    {
        if( m_targetAddr != 0 )
        {
            for( auto& line : m_asm )
            {
                if( m_targetAddr == line.addr )
                {
                    m_targetAddr = 0;
                    ImGui::SetScrollHereY();
                }
                RenderAsmLine( line, 0, iptotal, worker, jumpOut );
            }
        }
        else
        {
            const auto th = ImGui::GetTextLineHeightWithSpacing();
            ImGuiListClipper clipper( (int)m_asm.size(), th );
            while( clipper.Step() )
            {
                assert( clipper.StepNo == 3 );
                const auto wpos = ImGui::GetCursorScreenPos();
                static std::vector<uint64_t> insList;
                insList.clear();
                if( iptotal == 0 )
                {
                    for( auto i=clipper.DisplayStart; i<clipper.DisplayEnd; i++ )
                    {
                        RenderAsmLine( m_asm[i], 0, 0, worker, jumpOut );
                        insList.emplace_back( m_asm[i].addr );
                    }
                }
                else
                {
                    for( auto i=clipper.DisplayStart; i<clipper.DisplayEnd; i++ )
                    {
                        auto& line = m_asm[i];
                        auto it = ipcount.find( line.addr );
                        const auto ipcnt = it == ipcount.end() ? 0 : it->second;
                        RenderAsmLine( line, ipcnt, iptotal, worker, jumpOut );
                        insList.emplace_back( line.addr );
                    }
                }
                if( m_showJumps && !m_jumpTable.empty() )
                {
                    auto draw = ImGui::GetWindowDrawList();
                    const auto ts = ImGui::CalcTextSize( " " );
                    const auto th2 = floor( ts.y / 2 );
                    const auto th4 = floor( ts.y / 4 );
                    const auto xoff = ( iptotal == 0 ? 0 : ( 7 * ts.x + ts.y ) ) + 19 * ts.x + ( m_asmShowSourceLocation ? 36 * ts.x : 0 );
                    const auto minAddr = m_asm[clipper.DisplayStart].addr;
                    const auto maxAddr = m_asm[clipper.DisplayEnd-1].addr;
                    const auto mjl = m_maxJumpLevel;

                    int i = -1;
                    for( auto& v : m_jumpTable )
                    {
                        i++;
                        if( v.second.min > maxAddr || v.second.max < minAddr ) continue;
                        const auto col = GetHsvColor( i, 0 );
                        if( v.first >= minAddr && v.first <= maxAddr )
                        {
                            auto iit = std::lower_bound( insList.begin(), insList.end(), v.first );
                            assert( iit != insList.end() );
                            const auto y = ( iit - insList.begin() ) * th;
                            draw->AddLine( wpos + ImVec2( xoff + JumpSeparation * ( mjl - v.second.level ), y + th2 ), wpos + ImVec2( xoff + JumpSeparation * mjl + JumpArrow + 1, y + th2 ), col );
                            draw->AddLine( wpos + ImVec2( xoff + JumpSeparation * mjl + JumpArrow, y + th2 ), wpos + ImVec2( xoff + JumpSeparation * mjl + JumpArrow - th4, y + th2 - th4 ), col );
                            draw->AddLine( wpos + ImVec2( xoff + JumpSeparation * mjl + JumpArrow, y + th2 ), wpos + ImVec2( xoff + JumpSeparation * mjl + JumpArrow - th4, y + th2 + th4 ), col );
                        }
                        for( auto& s : v.second.source )
                        {
                            if( s >= minAddr && s <= maxAddr )
                            {
                                auto iit = std::lower_bound( insList.begin(), insList.end(), s );
                                assert( iit != insList.end() );
                                const auto y = ( iit - insList.begin() ) * th;
                                draw->AddLine( wpos + ImVec2( xoff + JumpSeparation * ( mjl - v.second.level ), y + th2 ), wpos + ImVec2( xoff + JumpSeparation * mjl + JumpArrow, y + th2 ), col );
                            }
                        }
                        auto it0 = std::lower_bound( insList.begin(), insList.end(), v.second.min );
                        auto it1 = std::lower_bound( insList.begin(), insList.end(), v.second.max );
                        const auto y0 = ( it0 == insList.end() || *it0 != v.second.min ) ? -th : ( it0 - insList.begin() ) * th;
                        const auto y1 = it1 == insList.end() ? ( insList.size() + 1 ) * th  : ( it1 - insList.begin() ) * th;
                        draw->AddLine( wpos + ImVec2( xoff + JumpSeparation * ( mjl - v.second.level ), y0 + th2 ), wpos + ImVec2( xoff + JumpSeparation * ( mjl - v.second.level ), y1 + th2 ), col );
                    }
                }
            }
        }
    }
    else
    {
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
                RenderLine( line, lineNum++, 0, iptotal, worker );
            }
        }
        else
        {
            ImGuiListClipper clipper( (int)m_lines.size() );
            while( clipper.Step() )
            {
                if( iptotal == 0 )
                {
                    for( auto i=clipper.DisplayStart; i<clipper.DisplayEnd; i++ )
                    {
                        RenderLine( m_lines[i], i+1, 0, 0, worker );
                    }
                }
                else
                {
                    for( auto i=clipper.DisplayStart; i<clipper.DisplayEnd; i++ )
                    {
                        auto it = ipcount.find( i+1 );
                        const auto ipcnt = it == ipcount.end() ? 0 : it->second;
                        RenderLine( m_lines[i], i+1, ipcnt, iptotal, worker );
                    }
                }
            }
        }
    }
    if( m_font ) ImGui::PopFont();
    ImGui::EndChild();

    if( jumpOut != 0 )
    {
        auto sym = worker.GetSymbolData( jumpOut );
        if( sym )
        {
            auto line = sym->line;
            auto file = line == 0 ? nullptr : worker.GetString( sym->file );
            if( file && !SourceFileValid( file, worker.GetCaptureTime() ) )
            {
                file = nullptr;
                line = 0;
            }
            if( line > 0 || sym->size.Val() > 0 )
            {
                Open( file, line, jumpOut, jumpOut, worker );
            }
        }
    }
}

static void PrintPercentage( float val )
{
    const auto ty = ImGui::GetFontSize();
    auto draw = ImGui::GetWindowDrawList();
    const auto wpos = ImGui::GetCursorScreenPos();
    const auto stw = ImGui::CalcTextSize( " " ).x;
    const auto htw = stw / 2;
    const auto tw = stw * 8;

    char tmp[16];
    auto end = PrintFloat( tmp, tmp+16, val, 2 );
    memcpy( end, "%", 2 );
    end++;
    const auto sz = end - tmp;
    char buf[16];
    memset( buf, ' ', 7-sz );
    memcpy( buf + 7 - sz, tmp, sz+1 );

    draw->AddRectFilled( wpos, wpos + ImVec2( val * tw / 100, ty+1 ), 0xFF444444 );
    DrawTextContrast( draw, wpos + ImVec2( htw, 0 ), 0xFFFFFFFF, buf );

    ImGui::ItemSize( ImVec2( stw * 7, ty ), 0 );
}

void SourceView::RenderLine( const Line& line, int lineNum, uint32_t ipcnt, uint32_t iptotal, const Worker& worker )
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
            const auto ts = ImGui::CalcTextSize( " " );
            ImGui::ItemSize( ImVec2( 7 * ts.x, ts.y ) );
        }
        else
        {
            PrintPercentage( 100.f * ipcnt / iptotal );
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

    const auto stw = ImGui::CalcTextSize( " " ).x;
    uint32_t match = 0;
    auto addresses = worker.GetAddressesForLocation( m_fileStringIdx, lineNum );
    if( addresses )
    {
        for( auto& addr : *addresses )
        {
            match += ( addr >= m_symAddr && addr < m_symAddr + m_codeLen );
        }
    }
    if( match > 0 )
    {
        const auto asmString = RealToString( match );
        sprintf( buf, "@%s", asmString );
        const auto asmsz = strlen( buf );
        TextDisabledUnformatted( buf );
        if( ImGui::IsItemClicked() )
        {
            m_showAsm = true;
            m_currentAddr = (*addresses)[0];
            m_targetAddr = (*addresses)[0];
        }
        ImGui::SameLine( 0, 0 );
        ImGui::ItemSize( ImVec2( stw * ( 8 - asmsz ), ty ), 0 );
    }
    else
    {
        ImGui::ItemSize( ImVec2( stw * 8, ty ), 0 );
    }

    ImGui::SameLine( 0, ty );
    ImGui::TextUnformatted( line.begin, line.end );

    draw->AddLine( wpos + ImVec2( 0, ty+2 ), wpos + ImVec2( w, ty+2 ), 0x08FFFFFF );
}

void SourceView::RenderAsmLine( const AsmLine& line, uint32_t ipcnt, uint32_t iptotal, const Worker& worker, uint64_t& jumpOut )
{
    const auto ty = ImGui::GetFontSize();
    auto draw = ImGui::GetWindowDrawList();
    const auto w = ImGui::GetWindowWidth();
    const auto wpos = ImGui::GetCursorScreenPos();
    if( line.addr == m_currentAddr )
    {
        draw->AddRectFilled( wpos, wpos + ImVec2( w, ty+1 ), 0xFF333322 );
    }
    if( line.addr == m_highlightAddr )
    {
        draw->AddRectFilled( wpos, wpos + ImVec2( w, ty+1 ), 0xFF222233 );
    }

    if( iptotal != 0 )
    {
        if( ipcnt == 0 )
        {
            const auto ts = ImGui::CalcTextSize( " " );
            ImGui::ItemSize( ImVec2( 7 * ts.x, ts.y ) );
        }
        else
        {
            PrintPercentage( 100.f * ipcnt / iptotal );
        }
        ImGui::SameLine( 0, ty );
    }

    char buf[256];
    if( m_asmRelative )
    {
        sprintf( buf, "+%" PRIu64, line.addr - m_baseAddr );
    }
    else
    {
        sprintf( buf, "%" PRIx64, line.addr );
    }
    const auto asz = strlen( buf );
    memset( buf+asz, ' ', 16-asz );
    buf[16] = '\0';
    TextDisabledUnformatted( buf );

    if( m_asmShowSourceLocation )
    {
        const auto stw = ImGui::CalcTextSize( " " ).x;
        ImGui::SameLine();
        uint32_t srcline;
        const auto srcidx = worker.GetLocationForAddress( line.addr, srcline );
        if( srcline != 0 )
        {
            const auto fileName = worker.GetString( srcidx );
            const auto fileColor = GetHsvColor( srcidx.Idx(), 0 );
            SmallColorBox( fileColor );
            ImGui::SameLine();
            const auto lineString = RealToString( srcline );
            const auto linesz = strlen( lineString );
            char buf[32];
            const auto fnsz = strlen( fileName );
            if( fnsz < 32 - 8 )
            {
                sprintf( buf, "%s:%i", fileName, srcline );
            }
            else
            {
                sprintf( buf, "...%s:%i", fileName+fnsz-(32-3-1-8), srcline );
            }
            const auto bufsz = strlen( buf );
            TextDisabledUnformatted( buf );
            if( ImGui::IsItemHovered() )
            {
                if( m_font ) ImGui::PopFont();
                ImGui::BeginTooltip();
                ImGui::Text( "%s:%i", fileName, srcline );
                ImGui::EndTooltip();
                if( m_font ) ImGui::PushFont( m_font );
                if( !m_lines.empty() && m_file == fileName && ImGui::IsItemClicked() )
                {
                    m_currentAddr = line.addr;
                    m_targetLine = srcline;
                    m_selectedLine = srcline;
                    m_showAsm = false;
                }
            }
            ImGui::SameLine( 0, 0 );
            ImGui::ItemSize( ImVec2( stw * ( 32 - bufsz ), ty ), 0 );
        }
        else
        {
            SmallColorBox( 0 );
            ImGui::SameLine( 0, 0 );
            ImGui::ItemSize( ImVec2( stw * 32, ty ), 0 );
        }
    }
    if( m_showJumps )
    {
        ImGui::SameLine( 0, 2*ty + JumpArrow + m_maxJumpLevel * JumpSeparation );
    }
    else
    {
        ImGui::SameLine( 0, ty );
    }

    const auto msz = line.mnemonic.size();
    memcpy( buf, line.mnemonic.c_str(), msz );
    memset( buf+msz, ' ', 16-msz );
    memcpy( buf+16, line.operands.c_str(), line.operands.size() + 1 );
    ImGui::TextUnformatted( buf );

    if( line.jumpAddr != 0 )
    {
        uint32_t offset = 0;
        const auto base = worker.GetSymbolForAddress( line.jumpAddr, offset );
        auto sym = base == 0 ? worker.GetSymbolData( line.jumpAddr ) : worker.GetSymbolData( base );
        if( sym )
        {
            ImGui::SameLine();
            ImGui::Spacing();
            ImGui::SameLine();
            if( base == m_baseAddr )
            {
                ImGui::TextDisabled( "-> [%s+%" PRIu32"]", worker.GetString( sym->name ), offset );
                if( ImGui::IsItemHovered() )
                {
                    m_highlightAddr = line.jumpAddr;
                    if( ImGui::IsItemClicked() )
                    {
                        m_targetAddr = line.jumpAddr;
                        m_currentAddr = line.jumpAddr;
                    }
                }
            }
            else
            {
                ImGui::TextDisabled( "[%s+%" PRIu32"]", worker.GetString( sym->name ), offset );
                if( ImGui::IsItemClicked() ) jumpOut = line.jumpAddr;
            }
        }
    }

    draw->AddLine( wpos + ImVec2( 0, ty+2 ), wpos + ImVec2( w, ty+2 ), 0x08FFFFFF );
}


}
