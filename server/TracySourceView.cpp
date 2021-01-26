#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>

#include <capstone.h>

#include "../imgui/imgui.h"
#include "TracyCharUtil.hpp"
#include "TracyColor.hpp"
#include "TracyFilesystem.hpp"
#include "TracyImGui.hpp"
#include "TracyMicroArchitecture.hpp"
#include "TracyPrint.hpp"
#include "TracySort.hpp"
#include "TracySourceView.hpp"
#include "TracyView.hpp"
#include "TracyWorker.hpp"

#include "IconsFontAwesome5.h"

#ifndef TRACY_NO_FILESELECTOR
#  include "../nfd/nfd.h"
#endif

namespace tracy
{

struct MicroArchUx
{
    const char* uArch;
    const char* cpuName;
    const char* moniker;
};

static constexpr MicroArchUx s_uArchUx[] = {
    { "Conroe", "Core 2 Duo E6750", "CON" },
    { "Wolfdale", "Core 2 Duo E8400", "WOL" },
    { "Nehalem", "Core i5-750", "NHM" },
    { "Westmere", "Core i5-650", "WSM" },
    { "Sandy Bridge", "Core i7-2600", "SNB" },
    { "Ivy Bridge", "Core i5-3470", "IVB" },
    { "Haswell", "Xeon E3-1225 v3", "HSW" },
    { "Broadwell", "Core i5-5200U", "BDW" },
    { "Skylake", "Core i7-6500U", "SKL" },
    { "Skylake-X", "Core i9-7900X", "SKX" },
    { "Kaby Lake", "Core i7-7700", "KBL" },
    { "Coffee Lake", "Core i7-8700K", "CFL" },
    { "Cannon Lake", "Core i3-8121U", "CNL" },
    { "Ice Lake", "Core i5-1035G1", "ICL" },
    { "Cascade Lake", "Core i9-10980XE", "CLX" },
    { "AMD Zen+", "Ryzen 5 2600", "ZEN+" },
    { "AMD Zen 2", "Ryzen 7 3700X", "ZEN2" },
    { "AMD Zen 3", "Ryzen 9 5950X", "ZEN3" },
};

static constexpr const char* s_regNameX86[] = {
    "invalid", "rflags",
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7",
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9",
    "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15", "xmm16", "xmm17", "xmm18", "xmm19",
    "xmm20", "xmm21", "xmm22", "xmm23", "xmm24", "xmm25", "xmm26", "xmm27", "xmm28", "xmm29",
    "xmm30", "xmm31", "k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7"
};
static_assert( sizeof( s_regNameX86 ) / sizeof( *s_regNameX86 ) == (size_t)SourceView::RegsX86::NUMBER_OF_ENTRIES, "Invalid x86 register name table" );

static SourceView::RegsX86 s_regMapX86[X86_REG_ENDING];


enum { JumpSeparation = 6 };
enum { JumpArrowBase = 9 };

SourceView::SourceView( ImFont* font, GetWindowCallback gwcb )
    : m_font( font )
    , m_file( nullptr )
    , m_fileStringIdx( 0 )
    , m_symAddr( 0 )
    , m_targetAddr( 0 )
    , m_data( nullptr )
    , m_dataBuf( nullptr )
    , m_dataSize( 0 )
    , m_targetLine( 0 )
    , m_selectedLine( 0 )
    , m_asmSelected( -1 )
    , m_hoveredLine( 0 )
    , m_hoveredSource( 0 )
    , m_codeLen( 0 )
    , m_highlightAddr( 0 )
    , m_asmCountBase( -1 )
    , m_asmRelative( false )
    , m_asmBytes( false )
    , m_asmShowSourceLocation( true )
    , m_calcInlineStats( true )
    , m_atnt( false )
    , m_showJumps( true )
    , m_cpuArch( CpuArchUnknown )
    , m_showLatency( false )
    , m_gwcb( gwcb )
{
    m_microArchOpMap.reserve( OpsNum );
    for( int i=0; i<OpsNum; i++ )
    {
        m_microArchOpMap.emplace( OpsList[i], i );
    }

    memset( s_regMapX86, 0, sizeof( s_regMapX86 ) );

    s_regMapX86[X86_REG_EFLAGS] = RegsX86::flags;
    s_regMapX86[X86_REG_AH] = RegsX86::rax;
    s_regMapX86[X86_REG_AL] = RegsX86::rax;
    s_regMapX86[X86_REG_AX] = RegsX86::rax;
    s_regMapX86[X86_REG_EAX] = RegsX86::rax;
    s_regMapX86[X86_REG_RAX] = RegsX86::rax;
    s_regMapX86[X86_REG_BH] = RegsX86::rbx;
    s_regMapX86[X86_REG_BL] = RegsX86::rbx;
    s_regMapX86[X86_REG_BX] = RegsX86::rbx;
    s_regMapX86[X86_REG_EBX] = RegsX86::rbx;
    s_regMapX86[X86_REG_RBX] = RegsX86::rbx;
    s_regMapX86[X86_REG_CH] = RegsX86::rcx;
    s_regMapX86[X86_REG_CL] = RegsX86::rcx;
    s_regMapX86[X86_REG_CX] = RegsX86::rcx;
    s_regMapX86[X86_REG_ECX] = RegsX86::rcx;
    s_regMapX86[X86_REG_RCX] = RegsX86::rcx;
    s_regMapX86[X86_REG_DH] = RegsX86::rdx;
    s_regMapX86[X86_REG_DL] = RegsX86::rdx;
    s_regMapX86[X86_REG_DX] = RegsX86::rdx;
    s_regMapX86[X86_REG_EDX] = RegsX86::rdx;
    s_regMapX86[X86_REG_RDX] = RegsX86::rdx;
    s_regMapX86[X86_REG_SIL] = RegsX86::rsi;
    s_regMapX86[X86_REG_SI] = RegsX86::rsi;
    s_regMapX86[X86_REG_ESI] = RegsX86::rsi;
    s_regMapX86[X86_REG_RSI] = RegsX86::rsi;
    s_regMapX86[X86_REG_DIL] = RegsX86::rdi;
    s_regMapX86[X86_REG_DI] = RegsX86::rdi;
    s_regMapX86[X86_REG_EDI] = RegsX86::rdi;
    s_regMapX86[X86_REG_RDI] = RegsX86::rdi;
    s_regMapX86[X86_REG_BP] = RegsX86::rbp;
    s_regMapX86[X86_REG_BP] = RegsX86::rbp;
    s_regMapX86[X86_REG_EBP] = RegsX86::rbp;
    s_regMapX86[X86_REG_RBP] = RegsX86::rbp;
    s_regMapX86[X86_REG_SPL] = RegsX86::rsp;
    s_regMapX86[X86_REG_SP] = RegsX86::rsp;
    s_regMapX86[X86_REG_ESP] = RegsX86::rsp;
    s_regMapX86[X86_REG_RSP] = RegsX86::rsp;
    s_regMapX86[X86_REG_R8B] = RegsX86::r8;
    s_regMapX86[X86_REG_R8W] = RegsX86::r8;
    s_regMapX86[X86_REG_R8D] = RegsX86::r8;
    s_regMapX86[X86_REG_R8] = RegsX86::r8;
    s_regMapX86[X86_REG_R9B] = RegsX86::r9;
    s_regMapX86[X86_REG_R9W] = RegsX86::r9;
    s_regMapX86[X86_REG_R9D] = RegsX86::r9;
    s_regMapX86[X86_REG_R9] = RegsX86::r9;
    s_regMapX86[X86_REG_R10B] = RegsX86::r10;
    s_regMapX86[X86_REG_R10W] = RegsX86::r10;
    s_regMapX86[X86_REG_R10D] = RegsX86::r10;
    s_regMapX86[X86_REG_R10] = RegsX86::r10;
    s_regMapX86[X86_REG_R11B] = RegsX86::r11;
    s_regMapX86[X86_REG_R11W] = RegsX86::r11;
    s_regMapX86[X86_REG_R11D] = RegsX86::r11;
    s_regMapX86[X86_REG_R11] = RegsX86::r11;
    s_regMapX86[X86_REG_R12B] = RegsX86::r12;
    s_regMapX86[X86_REG_R12W] = RegsX86::r12;
    s_regMapX86[X86_REG_R12D] = RegsX86::r12;
    s_regMapX86[X86_REG_R12] = RegsX86::r12;
    s_regMapX86[X86_REG_R13B] = RegsX86::r13;
    s_regMapX86[X86_REG_R13W] = RegsX86::r13;
    s_regMapX86[X86_REG_R13D] = RegsX86::r13;
    s_regMapX86[X86_REG_R13] = RegsX86::r13;
    s_regMapX86[X86_REG_R14B] = RegsX86::r14;
    s_regMapX86[X86_REG_R14W] = RegsX86::r14;
    s_regMapX86[X86_REG_R14D] = RegsX86::r14;
    s_regMapX86[X86_REG_R14] = RegsX86::r14;
    s_regMapX86[X86_REG_R15B] = RegsX86::r15;
    s_regMapX86[X86_REG_R15W] = RegsX86::r15;
    s_regMapX86[X86_REG_R15D] = RegsX86::r15;
    s_regMapX86[X86_REG_R15] = RegsX86::r15;
    s_regMapX86[X86_REG_MM0] = RegsX86::mm0;
    s_regMapX86[X86_REG_MM1] = RegsX86::mm1;
    s_regMapX86[X86_REG_MM2] = RegsX86::mm2;
    s_regMapX86[X86_REG_MM3] = RegsX86::mm3;
    s_regMapX86[X86_REG_MM4] = RegsX86::mm4;
    s_regMapX86[X86_REG_MM5] = RegsX86::mm5;
    s_regMapX86[X86_REG_MM6] = RegsX86::mm6;
    s_regMapX86[X86_REG_MM7] = RegsX86::mm7;
    s_regMapX86[X86_REG_ST0] = RegsX86::mm0;
    s_regMapX86[X86_REG_ST1] = RegsX86::mm1;
    s_regMapX86[X86_REG_ST2] = RegsX86::mm2;
    s_regMapX86[X86_REG_ST3] = RegsX86::mm3;
    s_regMapX86[X86_REG_ST4] = RegsX86::mm4;
    s_regMapX86[X86_REG_ST5] = RegsX86::mm5;
    s_regMapX86[X86_REG_ST6] = RegsX86::mm6;
    s_regMapX86[X86_REG_ST7] = RegsX86::mm7;
    s_regMapX86[X86_REG_XMM0] = RegsX86::xmm0;
    s_regMapX86[X86_REG_YMM0] = RegsX86::xmm0;
    s_regMapX86[X86_REG_ZMM0] = RegsX86::xmm0;
    s_regMapX86[X86_REG_XMM1] = RegsX86::xmm1;
    s_regMapX86[X86_REG_YMM1] = RegsX86::xmm1;
    s_regMapX86[X86_REG_ZMM1] = RegsX86::xmm1;
    s_regMapX86[X86_REG_XMM2] = RegsX86::xmm2;
    s_regMapX86[X86_REG_YMM2] = RegsX86::xmm2;
    s_regMapX86[X86_REG_ZMM2] = RegsX86::xmm2;
    s_regMapX86[X86_REG_XMM3] = RegsX86::xmm3;
    s_regMapX86[X86_REG_YMM3] = RegsX86::xmm3;
    s_regMapX86[X86_REG_ZMM3] = RegsX86::xmm3;
    s_regMapX86[X86_REG_XMM4] = RegsX86::xmm4;
    s_regMapX86[X86_REG_YMM4] = RegsX86::xmm4;
    s_regMapX86[X86_REG_ZMM4] = RegsX86::xmm4;
    s_regMapX86[X86_REG_XMM5] = RegsX86::xmm5;
    s_regMapX86[X86_REG_YMM5] = RegsX86::xmm5;
    s_regMapX86[X86_REG_ZMM5] = RegsX86::xmm5;
    s_regMapX86[X86_REG_XMM6] = RegsX86::xmm6;
    s_regMapX86[X86_REG_YMM6] = RegsX86::xmm6;
    s_regMapX86[X86_REG_ZMM6] = RegsX86::xmm6;
    s_regMapX86[X86_REG_XMM7] = RegsX86::xmm7;
    s_regMapX86[X86_REG_YMM7] = RegsX86::xmm7;
    s_regMapX86[X86_REG_ZMM7] = RegsX86::xmm7;
    s_regMapX86[X86_REG_XMM8] = RegsX86::xmm8;
    s_regMapX86[X86_REG_YMM8] = RegsX86::xmm8;
    s_regMapX86[X86_REG_ZMM8] = RegsX86::xmm8;
    s_regMapX86[X86_REG_XMM9] = RegsX86::xmm9;
    s_regMapX86[X86_REG_YMM9] = RegsX86::xmm9;
    s_regMapX86[X86_REG_ZMM9] = RegsX86::xmm9;
    s_regMapX86[X86_REG_XMM10] = RegsX86::xmm10;
    s_regMapX86[X86_REG_YMM10] = RegsX86::xmm10;
    s_regMapX86[X86_REG_ZMM10] = RegsX86::xmm10;
    s_regMapX86[X86_REG_XMM11] = RegsX86::xmm11;
    s_regMapX86[X86_REG_YMM11] = RegsX86::xmm11;
    s_regMapX86[X86_REG_ZMM11] = RegsX86::xmm11;
    s_regMapX86[X86_REG_XMM12] = RegsX86::xmm12;
    s_regMapX86[X86_REG_YMM12] = RegsX86::xmm12;
    s_regMapX86[X86_REG_ZMM12] = RegsX86::xmm12;
    s_regMapX86[X86_REG_XMM13] = RegsX86::xmm13;
    s_regMapX86[X86_REG_YMM13] = RegsX86::xmm13;
    s_regMapX86[X86_REG_ZMM13] = RegsX86::xmm13;
    s_regMapX86[X86_REG_XMM14] = RegsX86::xmm14;
    s_regMapX86[X86_REG_YMM14] = RegsX86::xmm14;
    s_regMapX86[X86_REG_ZMM14] = RegsX86::xmm14;
    s_regMapX86[X86_REG_XMM15] = RegsX86::xmm15;
    s_regMapX86[X86_REG_YMM15] = RegsX86::xmm15;
    s_regMapX86[X86_REG_ZMM15] = RegsX86::xmm15;
    s_regMapX86[X86_REG_XMM16] = RegsX86::xmm16;
    s_regMapX86[X86_REG_YMM16] = RegsX86::xmm16;
    s_regMapX86[X86_REG_ZMM16] = RegsX86::xmm16;
    s_regMapX86[X86_REG_XMM17] = RegsX86::xmm17;
    s_regMapX86[X86_REG_YMM17] = RegsX86::xmm17;
    s_regMapX86[X86_REG_ZMM17] = RegsX86::xmm17;
    s_regMapX86[X86_REG_XMM18] = RegsX86::xmm18;
    s_regMapX86[X86_REG_YMM18] = RegsX86::xmm18;
    s_regMapX86[X86_REG_ZMM18] = RegsX86::xmm18;
    s_regMapX86[X86_REG_XMM19] = RegsX86::xmm19;
    s_regMapX86[X86_REG_YMM19] = RegsX86::xmm19;
    s_regMapX86[X86_REG_ZMM19] = RegsX86::xmm19;
    s_regMapX86[X86_REG_XMM20] = RegsX86::xmm20;
    s_regMapX86[X86_REG_YMM20] = RegsX86::xmm20;
    s_regMapX86[X86_REG_ZMM20] = RegsX86::xmm20;
    s_regMapX86[X86_REG_XMM21] = RegsX86::xmm21;
    s_regMapX86[X86_REG_YMM21] = RegsX86::xmm21;
    s_regMapX86[X86_REG_ZMM21] = RegsX86::xmm21;
    s_regMapX86[X86_REG_XMM22] = RegsX86::xmm22;
    s_regMapX86[X86_REG_YMM22] = RegsX86::xmm22;
    s_regMapX86[X86_REG_ZMM22] = RegsX86::xmm22;
    s_regMapX86[X86_REG_XMM23] = RegsX86::xmm23;
    s_regMapX86[X86_REG_YMM23] = RegsX86::xmm23;
    s_regMapX86[X86_REG_ZMM23] = RegsX86::xmm23;
    s_regMapX86[X86_REG_XMM24] = RegsX86::xmm24;
    s_regMapX86[X86_REG_YMM24] = RegsX86::xmm24;
    s_regMapX86[X86_REG_ZMM24] = RegsX86::xmm24;
    s_regMapX86[X86_REG_XMM25] = RegsX86::xmm25;
    s_regMapX86[X86_REG_YMM25] = RegsX86::xmm25;
    s_regMapX86[X86_REG_ZMM25] = RegsX86::xmm25;
    s_regMapX86[X86_REG_XMM26] = RegsX86::xmm26;
    s_regMapX86[X86_REG_YMM26] = RegsX86::xmm26;
    s_regMapX86[X86_REG_ZMM26] = RegsX86::xmm26;
    s_regMapX86[X86_REG_XMM27] = RegsX86::xmm27;
    s_regMapX86[X86_REG_YMM27] = RegsX86::xmm27;
    s_regMapX86[X86_REG_ZMM27] = RegsX86::xmm27;
    s_regMapX86[X86_REG_XMM28] = RegsX86::xmm28;
    s_regMapX86[X86_REG_YMM28] = RegsX86::xmm28;
    s_regMapX86[X86_REG_ZMM28] = RegsX86::xmm28;
    s_regMapX86[X86_REG_XMM29] = RegsX86::xmm29;
    s_regMapX86[X86_REG_YMM29] = RegsX86::xmm29;
    s_regMapX86[X86_REG_ZMM29] = RegsX86::xmm29;
    s_regMapX86[X86_REG_XMM30] = RegsX86::xmm30;
    s_regMapX86[X86_REG_YMM30] = RegsX86::xmm30;
    s_regMapX86[X86_REG_ZMM30] = RegsX86::xmm30;
    s_regMapX86[X86_REG_XMM31] = RegsX86::xmm31;
    s_regMapX86[X86_REG_YMM31] = RegsX86::xmm31;
    s_regMapX86[X86_REG_ZMM31] = RegsX86::xmm31;
    s_regMapX86[X86_REG_K0] = RegsX86::k0;
    s_regMapX86[X86_REG_K1] = RegsX86::k1;
    s_regMapX86[X86_REG_K2] = RegsX86::k2;
    s_regMapX86[X86_REG_K3] = RegsX86::k3;
    s_regMapX86[X86_REG_K4] = RegsX86::k4;
    s_regMapX86[X86_REG_K5] = RegsX86::k5;
    s_regMapX86[X86_REG_K6] = RegsX86::k6;
    s_regMapX86[X86_REG_K7] = RegsX86::k7;
}

SourceView::~SourceView()
{
    delete[] m_dataBuf;
}

static constexpr uint32_t PackCpuInfo( uint32_t cpuid )
{
    return ( cpuid & 0xFFF ) | ( ( cpuid & 0xFFF0000 ) >> 4 );
}

struct CpuIdMap
{
    uint32_t cpuInfo;
    const char* moniker;
};

//                   .------ extended family id
//                   |.----- extended model id
//                   || .--- family id
//                   || |.-- model
//                   || ||.- stepping
//                   || |||
static constexpr CpuIdMap s_cpuIdMap[] = {
    { PackCpuInfo( 0x810F81 ), "ZEN+" },
    { PackCpuInfo( 0x800F82 ), "ZEN+" },
    { PackCpuInfo( 0x870F10 ), "ZEN2" },
    { PackCpuInfo( 0x830F10 ), "ZEN2" },
    { PackCpuInfo( 0x860F01 ), "ZEN2" },
    { PackCpuInfo( 0x860F81 ), "ZEN2" },
    { PackCpuInfo( 0x890F00 ), "ZEN2" },
    { PackCpuInfo( 0xA20F10 ), "ZEN3" },
    { PackCpuInfo( 0x0706E5 ), "ICL" },
    { PackCpuInfo( 0x050656 ), "CLX" },
    { PackCpuInfo( 0x050657 ), "CLX" },
    { PackCpuInfo( 0x060663 ), "CNL" },
    { PackCpuInfo( 0x0906EA ), "CFL" },
    { PackCpuInfo( 0x0906EB ), "CFL" },
    { PackCpuInfo( 0x0906EC ), "CFL" },
    { PackCpuInfo( 0x0906ED ), "CFL" },
    { PackCpuInfo( 0x0806E9 ), "KBL" },
    { PackCpuInfo( 0x0806EA ), "KBL" },
    { PackCpuInfo( 0x0906E9 ), "KBL" },
    { PackCpuInfo( 0x050654 ), "SKX" },
    { PackCpuInfo( 0x0406E3 ), "SKL" },
    { PackCpuInfo( 0x0506E0 ), "SKL" },
    { PackCpuInfo( 0x0506E3 ), "SKL" },
    { PackCpuInfo( 0x0306D4 ), "BDW" },
    { PackCpuInfo( 0x040671 ), "BDW" },
    { PackCpuInfo( 0x0406F1 ), "BDW" },
    { PackCpuInfo( 0x0306C3 ), "HSW" },
    { PackCpuInfo( 0x0306F2 ), "HSW" },
    { PackCpuInfo( 0x040651 ), "HSW" },
    { PackCpuInfo( 0x0306A9 ), "IVB" },
    { PackCpuInfo( 0x0306E3 ), "IVB" },
    { PackCpuInfo( 0x0306E4 ), "IVB" },
    { PackCpuInfo( 0x0206A2 ), "SNB" },
    { PackCpuInfo( 0x0206A7 ), "SNB" },
    { PackCpuInfo( 0x0206D5 ), "SNB" },
    { PackCpuInfo( 0x0206D6 ), "SNB" },
    { PackCpuInfo( 0x0206D7 ), "SNB" },
    { PackCpuInfo( 0x0206F2 ), "WSM" },
    { PackCpuInfo( 0x0206C0 ), "WSM" },
    { PackCpuInfo( 0x0206C1 ), "WSM" },
    { PackCpuInfo( 0x0206C2 ), "WSM" },
    { PackCpuInfo( 0x020652 ), "WSM" },
    { PackCpuInfo( 0x020655 ), "WSM" },
    { PackCpuInfo( 0x0206E6 ), "NHM" },
    { PackCpuInfo( 0x0106A1 ), "NHM" },
    { PackCpuInfo( 0x0106A2 ), "NHM" },
    { PackCpuInfo( 0x0106A4 ), "NHM" },
    { PackCpuInfo( 0x0106A5 ), "NHM" },
    { PackCpuInfo( 0x0106E4 ), "NHM" },
    { PackCpuInfo( 0x0106E5 ), "NHM" },
    { PackCpuInfo( 0x010676 ), "WOL" },
    { PackCpuInfo( 0x01067A ), "WOL" },
    { PackCpuInfo( 0x0006F2 ), "CON" },
    { PackCpuInfo( 0x0006F4 ), "CON" },
    { PackCpuInfo( 0x0006F6 ), "CON" },
    { PackCpuInfo( 0x0006FB ), "CON" },
    { PackCpuInfo( 0x0006FD ), "CON" },
    { 0, 0 }
};

void SourceView::SetCpuId( uint32_t cpuId )
{
    auto ptr = s_cpuIdMap;
    while( ptr->cpuInfo )
    {
        if( cpuId == ptr->cpuInfo )
        {
            SelectMicroArchitecture( ptr->moniker );
            m_profileMicroArch = m_selMicroArch;
            return;
        }
        ptr++;
    }
    SelectMicroArchitecture( "ZEN2" );
    m_profileMicroArch = -1;
}

void SourceView::OpenSource( const char* fileName, int line, const View& view, const Worker& worker )
{
    m_targetLine = line;
    m_selectedLine = line;
    m_targetAddr = 0;
    m_baseAddr = 0;
    m_symAddr = 0;
    m_sourceFiles.clear();
    m_asm.clear();

    ParseSource( fileName, worker, view );
    assert( !m_lines.empty() );
}

void SourceView::OpenSymbol( const char* fileName, int line, uint64_t baseAddr, uint64_t symAddr, const Worker& worker, const View& view )
{
    m_targetLine = line;
    m_targetAddr = symAddr;
    m_baseAddr = baseAddr;
    m_symAddr = symAddr;
    m_sourceFiles.clear();
    m_selectedAddresses.clear();
    m_selectedAddresses.emplace( symAddr );

    ParseSource( fileName, worker, view );
    Disassemble( baseAddr, worker );
    SelectLine( line, &worker, true, symAddr );

    SelectViewMode();
}

void SourceView::SelectViewMode()
{
    if( !m_lines.empty() )
    {
        if( !m_asm.empty() )
        {
            m_displayMode = DisplayMixed;
        }
        else
        {
            m_displayMode = DisplaySource;
        }
    }
    else
    {
        assert( !m_asm.empty() );
        m_displayMode = DisplayAsm;
    }
}

void SourceView::ParseSource( const char* fileName, const Worker& worker, const View& view )
{
    if( m_file != fileName )
    {
        m_srcWidth = 0;
        m_file = fileName;
        m_fileStringIdx = worker.FindStringIdx( fileName );
        m_lines.clear();
        if( fileName )
        {
            uint32_t sz;
            const auto srcCache = worker.GetSourceFileFromCache( fileName );
            if( srcCache.data != nullptr )
            {
                m_data = srcCache.data;
                sz = srcCache.len;
            }
            else
            {
                FILE* f = fopen( view.SourceSubstitution( fileName ), "rb" );
                if( f )
                {
                    fseek( f, 0, SEEK_END );
                    sz = ftell( f );
                    fseek( f, 0, SEEK_SET );
                    if( sz > m_dataSize )
                    {
                        delete[] m_dataBuf;
                        m_dataBuf = new char[sz];
                        m_dataSize = sz;
                    }
                    fread( m_dataBuf, 1, sz, f );
                    m_data = m_dataBuf;
                    fclose( f );
                }
                else
                {
                    m_file = nullptr;
                }
            }

            if( m_file )
            {
                m_tokenizer.Reset();
                auto txt = m_data;
                for(;;)
                {
                    auto end = txt;
                    while( *end != '\n' && *end != '\r' && end - m_data < sz ) end++;
                    m_lines.emplace_back( Line { txt, end, Tokenize( txt, end ) } );
                    if( end - m_data == sz ) break;
                    if( *end == '\n' )
                    {
                        end++;
                        if( end - m_data < sz && *end == '\r' ) end++;
                    }
                    else if( *end == '\r' )
                    {
                        end++;
                        if( end - m_data < sz && *end == '\n' ) end++;
                    }
                    if( end - m_data == sz ) break;
                    txt = end;
                }
            }
        }
    }
}

static bool IsJumpConditionalX86( const char* op )
{
    static constexpr const char* branchX86[] = {
        "je", "jne", "jg", "jge", "ja", "jae", "jl", "jle", "jb", "jbe", "jo", "jno", "jz", "jnz", "js", "jns", "jcxz", "jecxz", "jrcxz", "loop", "loope",
        "loopne", "loopnz", "loopz", "jnle", "jnl", "jnge", "jng", "jnbe", "jnb", "jnae", "jna", "jc", "jnc", "jp", "jpe", "jnp", "jpo", nullptr
    };
    auto ptr = branchX86;
    while( *ptr ) if( strcmp( *ptr++, op ) == 0 ) return true;
    return false;
}

bool SourceView::Disassemble( uint64_t symAddr, const Worker& worker )
{
    m_asm.clear();
    m_locMap.clear();
    m_jumpTable.clear();
    m_jumpOut.clear();
    m_maxJumpLevel = 0;
    m_asmSelected = -1;
    m_asmCountBase = -1;
    m_asmWidth = 0;
    if( symAddr == 0 ) return false;
    m_cpuArch = worker.GetCpuArch();
    if( m_cpuArch == CpuArchUnknown ) return false;
    uint32_t len;
    auto code = worker.GetSymbolCode( symAddr, len );
    if( !code ) return false;
    m_disasmFail = -1;
    csh handle;
    cs_err rval = CS_ERR_ARCH;
    switch( m_cpuArch )
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
    cs_option( handle, CS_OPT_SYNTAX, m_atnt ? CS_OPT_SYNTAX_ATT : CS_OPT_SYNTAX_INTEL );
    cs_insn* insn;
    size_t cnt = cs_disasm( handle, (const uint8_t*)code, len, symAddr, 0, &insn );
    if( cnt > 0 )
    {
        if( insn[cnt-1].address - symAddr + insn[cnt-1].size < len ) m_disasmFail = insn[cnt-1].address - symAddr;
        int bytesMax = 0;
        int mLenMax = 0;
        m_asm.reserve( cnt );
        for( size_t i=0; i<cnt; i++ )
        {
            const auto& op = insn[i];
            const auto& detail = *op.detail;
            bool hasJump = false;
            bool jumpConditional = false;
            for( auto j=0; j<detail.groups_count; j++ )
            {
                if( detail.groups[j] == CS_GRP_JUMP || detail.groups[j] == CS_GRP_CALL || detail.groups[j] == CS_GRP_RET )
                {
                    hasJump = true;
                    break;
                }
            }
            uint64_t jumpAddr = 0;
            if( hasJump )
            {
                switch( m_cpuArch )
                {
                case CpuArchX86:
                case CpuArchX64:
                    if( detail.x86.op_count == 1 && detail.x86.operands[0].type == X86_OP_IMM )
                    {
                        jumpAddr = (uint64_t)detail.x86.operands[0].imm;
                    }
                    jumpConditional = IsJumpConditionalX86( op.mnemonic );
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
                    auto fit = std::lower_bound( insn, insn+cnt, jumpAddr, []( const auto& l, const auto& r ) { return l.address < r; } );
                    if( fit != insn+cnt && fit->address == jumpAddr )
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
                        jumpAddr = 0;
                    }
                }
                else
                {
                    m_jumpOut.emplace( op.address );
                }
            }
            std::vector<AsmOpParams> params;
            switch( m_cpuArch )
            {
            case CpuArchX86:
            case CpuArchX64:
                for( uint8_t i=0; i<detail.x86.op_count; i++ )
                {
                    uint8_t type = 0;
                    switch( detail.x86.operands[i].type )
                    {
                    case X86_OP_IMM:
                        type = 0;
                        break;
                    case X86_OP_REG:
                        type = 1;
                        break;
                    case X86_OP_MEM:
                        type = 2;
                        break;
                    default:
                        assert( false );
                        break;
                    }
                    params.emplace_back( AsmOpParams { type, uint16_t( detail.x86.operands[i].size * 8 ) } );
                }
                break;
            case CpuArchArm32:
                for( uint8_t i=0; i<detail.arm.op_count; i++ )
                {
                    uint8_t type = 0;
                    switch( detail.arm.operands[i].type )
                    {
                    case ARM_OP_IMM:
                        type = 0;
                        break;
                    case ARM_OP_REG:
                        type = 1;
                        break;
                    case ARM_OP_MEM:
                        type = 2;
                        break;
                    default:
                        type = 255;
                        break;
                    }
                    params.emplace_back( AsmOpParams { type, 0 } );
                }
                break;
            case CpuArchArm64:
                for( uint8_t i=0; i<detail.arm64.op_count; i++ )
                {
                    uint8_t type = 0;
                    switch( detail.arm64.operands[i].type )
                    {
                    case ARM64_OP_IMM:
                        type = 0;
                        break;
                    case ARM64_OP_REG:
                        type = 1;
                        break;
                    case ARM64_OP_MEM:
                        type = 2;
                        break;
                    default:
                        type = 255;
                        break;
                    }
                    params.emplace_back( AsmOpParams { type, 0 } );
                }
                break;
            default:
                assert( false );
                break;
            }
            LeaData leaData = LeaData::none;
            if( ( m_cpuArch == CpuArchX64 || m_cpuArch == CpuArchX86 ) && op.id == X86_INS_LEA )
            {
                assert( op.detail->x86.op_count == 2 );
                const auto opidx = m_atnt ? 0 : 1;
                assert( op.detail->x86.operands[opidx].type == X86_OP_MEM );
                auto& mem = op.detail->x86.operands[opidx].mem;
                if( mem.base == X86_REG_INVALID )
                {
                    if( mem.index == X86_REG_INVALID )
                    {
                        leaData = LeaData::d;
                    }
                    else
                    {
                        leaData = mem.disp == 0 ? LeaData::i : LeaData::id;
                    }
                }
                else if( mem.base == X86_REG_RIP )
                {
                    leaData = mem.disp == 0 ? LeaData::r : LeaData::rd;
                }
                else
                {
                    if( mem.index == X86_REG_INVALID )
                    {
                        leaData = mem.disp == 0 ? LeaData::b : LeaData::bd;
                    }
                    else
                    {
                        leaData = mem.disp == 0 ? LeaData::bi : LeaData::bid;
                    }
                }
            }
            m_asm.emplace_back( AsmLine { op.address, jumpAddr, op.mnemonic, op.op_str, (uint8_t)op.size, leaData, jumpConditional, std::move( params ) } );

#if CS_API_MAJOR >= 4
            auto& entry = m_asm.back();
            cs_regs read, write;
            uint8_t rcnt, wcnt;
            cs_regs_access( handle, &op, read, &rcnt, write, &wcnt );
            int idx;
            switch( m_cpuArch )
            {
            case CpuArchX86:
            case CpuArchX64:
                assert( rcnt < sizeof( entry.readX86 ) );
                assert( wcnt < sizeof( entry.writeX86 ) );
                idx = 0;
                for( int i=0; i<rcnt; i++ )
                {
                    if( s_regMapX86[read[i]] != RegsX86::invalid ) entry.readX86[idx++] = s_regMapX86[read[i]];
                    entry.readX86[idx] = RegsX86::invalid;
                }
                idx = 0;
                for( int i=0; i<wcnt; i++ )
                {
                    if( s_regMapX86[write[i]] != RegsX86::invalid ) entry.writeX86[idx++] = s_regMapX86[write[i]];
                    entry.writeX86[idx] = RegsX86::invalid;
                }
                break;
            default:
                break;
            }
#endif

            const auto mLen = (int)strlen( op.mnemonic );
            if( mLen > mLenMax ) mLenMax = mLen;
            if( op.size > bytesMax ) bytesMax = op.size;

            uint32_t mLineMax = 0;
            uint32_t srcline;
            const auto srcidx = worker.GetLocationForAddress( op.address, srcline );
            if( srcline != 0 )
            {
                if( srcline > mLineMax ) mLineMax = srcline;
                const auto idx = srcidx.Idx();
                auto sit = m_sourceFiles.find( idx );
                if( sit == m_sourceFiles.end() )
                {
                    m_sourceFiles.emplace( idx, srcline );
                }
            }
            char tmp[16];
            sprintf( tmp, "%" PRIu32, mLineMax );
            m_maxLine = strlen( tmp ) + 1;
        }
        cs_free( insn, cnt );
        m_maxMnemonicLen = mLenMax + 2;
        m_maxAsmBytes = bytesMax;
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
                size_t level = 0;
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

            uint32_t locNum = 0;
            for( auto& v : m_asm )
            {
                if( m_jumpTable.find( v.addr ) != m_jumpTable.end() )
                {
                    m_locMap.emplace( v.addr, locNum++ );
                }
            }
        }
    }
    cs_close( &handle );
    m_codeLen = len;
    ResetAsm();
    return true;
}

void SourceView::Render( const Worker& worker, View& view )
{
    m_highlightAddr.Decay( 0 );
    m_hoveredLine.Decay( 0 );
    m_hoveredSource.Decay( 0 );

    if( m_symAddr == 0 )
    {
        if( m_file ) TextFocused( ICON_FA_FILE " File:", m_file );
        if( m_data == m_dataBuf )
        {
            TextColoredUnformatted( ImVec4( 1.f, 1.f, 0.2f, 1.f ), ICON_FA_EXCLAMATION_TRIANGLE );
            ImGui::SameLine();
            TextColoredUnformatted( ImVec4( 1.f, 0.3f, 0.3f, 1.f ), "The source file contents might not reflect the actual profiled code!" );
            ImGui::SameLine();
            TextColoredUnformatted( ImVec4( 1.f, 1.f, 0.2f, 1.f ), ICON_FA_EXCLAMATION_TRIANGLE );
        }
        else
        {
            TextColoredUnformatted( ImVec4( 0.4f, 0.8f, 0.4f, 1.f ), ICON_FA_DATABASE );
            ImGui::SameLine();
            ImGui::TextUnformatted( "Source file cached during profiling run" );
        }

        RenderSimpleSourceView();
    }
    else
    {
        RenderSymbolView( worker, view );
    }
}

void SourceView::RenderSimpleSourceView()
{
    ImGui::SetNextWindowContentSize( ImVec2( m_srcWidth, 0 ) );
    ImGui::BeginChild( "##sourceView", ImVec2( 0, 0 ), true, ImGuiWindowFlags_HorizontalScrollbar );
    if( m_font ) ImGui::PushFont( m_font );

    auto draw = ImGui::GetWindowDrawList();
    const auto wpos = ImGui::GetWindowPos();
    const auto wh = ImGui::GetWindowHeight();
    const auto ty = ImGui::GetFontSize();
    const auto ts = ImGui::CalcTextSize( " " ).x;
    const auto lineCount = m_lines.size();
    const auto tmp = RealToString( lineCount );
    const auto maxLine = strlen( tmp );
    const auto lx = ts * maxLine + ty + round( ts*0.4f );
    draw->AddLine( wpos + ImVec2( lx, 0 ), wpos + ImVec2( lx, wh ), 0x08FFFFFF );

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
            RenderLine( line, lineNum++, 0, 0, 0, nullptr );
        }
        const auto win = ImGui::GetCurrentWindowRead();
        m_srcWidth = win->DC.CursorMaxPos.x - win->DC.CursorStartPos.x;
    }
    else
    {
        ImGuiListClipper clipper;
        clipper.Begin( (int)m_lines.size() );
        while( clipper.Step() )
        {
            for( auto i=clipper.DisplayStart; i<clipper.DisplayEnd; i++ )
            {
                RenderLine( m_lines[i], i+1, 0, 0, 0, nullptr );
            }
        }
    }
    if( m_font ) ImGui::PopFont();
    ImGui::EndChild();
}

void SourceView::RenderSymbolView( const Worker& worker, View& view )
{
    assert( m_symAddr != 0 );

    auto sym = worker.GetSymbolData( m_symAddr );
    assert( sym );
    if( sym->isInline )
    {
        auto parent = worker.GetSymbolData( m_baseAddr );
        if( parent )
        {
            TextFocused( ICON_FA_PUZZLE_PIECE " Symbol:", worker.GetString( parent->name ) );
        }
        else
        {
            char tmp[16];
            sprintf( tmp, "0x%" PRIx64, m_baseAddr );
            TextFocused( ICON_FA_PUZZLE_PIECE " Symbol:", tmp );
        }
    }
    else
    {
        TextFocused( ICON_FA_PUZZLE_PIECE " Symbol:", worker.GetString( sym->name ) );
    }
    ImGui::SameLine();
    TextDisabledUnformatted( worker.GetString( sym->imageName ) );
    ImGui::SameLine();
    ImGui::TextDisabled( "0x%" PRIx64, m_baseAddr );

    const bool limitView = view.m_statRange.active;
    auto inlineList = worker.GetInlineSymbolList( m_baseAddr, m_codeLen );
    if( inlineList )
    {
        SmallCheckbox( ICON_FA_SITEMAP " Function:", &m_calcInlineStats );
        ImGui::SameLine();
        ImGui::SetNextItemWidth( -1 );
        ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
        const auto currSymName = m_symAddr == m_baseAddr ? "[ - self - ]" : worker.GetString( sym->name );
        if( ImGui::BeginCombo( "##functionList", currSymName, ImGuiComboFlags_HeightLarge ) )
        {
            const auto symEnd = m_baseAddr + m_codeLen;
            unordered_flat_map<uint64_t, uint32_t> symStat;
            if( limitView )
            {
                symStat.emplace( m_baseAddr, CountAsmIpStats( m_baseAddr, worker, true, view ) );
                auto ptr = inlineList;
                while( *ptr < symEnd )
                {
                    symStat.emplace( *ptr, CountAsmIpStats( *ptr, worker, true, view ) );
                    ptr++;
                }
            }
            else
            {
                const auto& ss = worker.GetSymbolStats();
                for( auto& v : ss ) symStat.emplace( v.first, v.second.excl );
            }

            uint32_t totalSamples = 0;
            Vector<std::pair<uint64_t, uint32_t>> symInline;
            auto baseStatIt = symStat.find( m_baseAddr );
            if( baseStatIt == symStat.end() || baseStatIt->second == 0 )
            {
                symInline.push_back( std::make_pair( m_baseAddr, 0 ) );
            }
            else
            {
                symInline.push_back( std::make_pair( m_baseAddr, baseStatIt->second ) );
                totalSamples += baseStatIt->second;
            }
            while( *inlineList < symEnd )
            {
                if( *inlineList != m_baseAddr )
                {
                    auto statIt = symStat.find( *inlineList );
                    if( statIt == symStat.end() || statIt->second == 0 )
                    {
                        symInline.push_back_non_empty( std::make_pair( *inlineList, 0 ) );
                    }
                    else
                    {
                        symInline.push_back_non_empty( std::make_pair( *inlineList, statIt->second ) );
                        totalSamples += statIt->second;
                    }
                }
                inlineList++;
            }
            pdqsort_branchless( symInline.begin(), symInline.end(), []( const auto& l, const auto& r ) { return l.second == r.second ? l.first < r.first : l.second > r.second; } );

            if( totalSamples == 0 )
            {
                ImGui::Columns( 2 );
                static bool widthSet = false;
                if( !widthSet )
                {
                    widthSet = true;
                    const auto w = ImGui::GetWindowWidth();
                    const auto c1 = ImGui::CalcTextSize( "0xeeeeeeeeeeeeee" ).x;
                    ImGui::SetColumnWidth( 0, w - c1 );
                    ImGui::SetColumnWidth( 1, c1 );
                }
            }
            else
            {
                ImGui::Columns( 3 );
                static bool widthSet = false;
                if( !widthSet )
                {
                    widthSet = true;
                    const auto w = ImGui::GetWindowWidth();
                    const auto c0 = ImGui::CalcTextSize( "12345678901234567890" ).x;
                    const auto c2 = ImGui::CalcTextSize( "0xeeeeeeeeeeeeee" ).x;
                    ImGui::SetColumnWidth( 0, c0 );
                    ImGui::SetColumnWidth( 1, w - c0 - c2 );
                    ImGui::SetColumnWidth( 2, c2 );
                }
            }
            for( auto& v : symInline )
            {
                if( totalSamples != 0 )
                {
                    if( v.second != 0 )
                    {
                        ImGui::TextUnformatted( TimeToString( v.second * worker.GetSamplingPeriod() ) );
                        ImGui::SameLine();
                        ImGui::TextDisabled( "(%.2f%%)", 100.f * v.second / totalSamples );
                        if( ImGui::IsItemHovered() )
                        {
                            ImGui::BeginTooltip();
                            TextFocused( "Sample count:", RealToString( v.second ) );
                            ImGui::EndTooltip();
                        }
                    }
                    ImGui::NextColumn();
                }
                auto isym = worker.GetSymbolData( v.first );
                assert( isym );
                ImGui::PushID( v.first );
                const auto symName = v.first == m_baseAddr ? "[ - self - ]" : worker.GetString( isym->name );
                if( ImGui::Selectable( symName, v.first == m_symAddr, ImGuiSelectableFlags_SpanAllColumns ) )
                {
                    m_symAddr = v.first;
                    const auto sym = worker.GetSymbolData( v.first );
                    const char* file;
                    uint32_t line;
                    if( sym->isInline )
                    {
                        file = worker.GetString( sym->callFile );
                        line = sym->callLine;
                    }
                    else
                    {
                        file = worker.GetString( sym->file );
                        line = sym->line;
                    }
                    ParseSource( file, worker, view );
                    m_targetLine = line;
                    SelectLine( line, &worker, true );
                    SelectViewMode();
                }
                ImGui::PopID();
                ImGui::NextColumn();
                ImGui::TextDisabled( "0x%" PRIx64, v.first );
                ImGui::NextColumn();
            }
            ImGui::EndColumns();
            ImGui::EndCombo();
        }
        ImGui::PopStyleVar();
    }

    TextDisabledUnformatted( "Mode:" );
    ImGui::SameLine();
    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
    if( !m_lines.empty() )
    {
        ImGui::RadioButton( "Source", &m_displayMode, DisplaySource );
        if( !m_asm.empty() )
        {
            ImGui::SameLine();
            ImGui::RadioButton( "Assembly", &m_displayMode, DisplayAsm );
            ImGui::SameLine();
            ImGui::RadioButton( "Combined", &m_displayMode, DisplayMixed );
        }
    }
    else
    {
        ImGui::RadioButton( "Assembly", &m_displayMode, DisplayAsm );
    }

    if( !m_asm.empty() )
    {
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextFocused( ICON_FA_WEIGHT_HANGING " Code size:", MemSizeToString( m_codeLen ) );
    }

    uint32_t iptotalSrc = 0, iptotalAsm = 0;
    uint32_t ipmaxSrc = 0, ipmaxAsm = 0;
    unordered_flat_map<uint64_t, uint32_t> ipcountSrc, ipcountAsm;
    if( m_calcInlineStats )
    {
        GatherIpStats( m_symAddr, iptotalSrc, iptotalAsm, ipcountSrc, ipcountAsm, ipmaxSrc, ipmaxAsm, worker, limitView, view );
    }
    else
    {
        GatherIpStats( m_baseAddr, iptotalSrc, iptotalAsm, ipcountSrc, ipcountAsm, ipmaxSrc, ipmaxAsm, worker, limitView, view );
        auto iptr = worker.GetInlineSymbolList( m_baseAddr, m_codeLen );
        if( iptr )
        {
            const auto symEnd = m_baseAddr + m_codeLen;
            while( *iptr < symEnd )
            {
                GatherIpStats( *iptr, iptotalSrc, iptotalAsm, ipcountSrc, ipcountAsm, ipmaxSrc, ipmaxAsm, worker, limitView, view );
                iptr++;
            }
        }
        iptotalSrc = iptotalAsm;
    }
    if( iptotalAsm > 0 )
    {
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextFocused( ICON_FA_STOPWATCH " Time:", TimeToString( iptotalAsm * worker.GetSamplingPeriod() ) );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextFocused( ICON_FA_EYE_DROPPER " Samples:", RealToString( iptotalAsm ) );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        if( !worker.AreSymbolSamplesReady() )
        {
            view.m_statRange.active = false;
            bool val = false;
            ImGui::PushItemFlag( ImGuiItemFlags_Disabled, true );
            ImGui::PushStyleVar( ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * 0.5f );
            ImGui::Checkbox( "Limit range", &val );
            ImGui::PopItemFlag();
            ImGui::PopStyleVar();
            if( ImGui::IsItemHovered() )
            {
                ImGui::BeginTooltip();
                ImGui::TextUnformatted( "Waiting for background tasks to finish" );
                ImGui::EndTooltip();
            }
        }
        else
        {
            if( ImGui::Checkbox( "Limit range", &view.m_statRange.active ) )
            {
                if( view.m_statRange.active && view.m_statRange.min == 0 && view.m_statRange.max == 0 )
                {
                    const auto& vd = view.GetViewData();
                    view.m_statRange.min = vd.zvStart;
                    view.m_statRange.max = vd.zvEnd;
                }
            }
            if( view.m_statRange.active )
            {
                ImGui::SameLine();
                TextColoredUnformatted( 0xFF00FFFF, ICON_FA_EXCLAMATION_TRIANGLE );
                ImGui::SameLine();
                ToggleButton( ICON_FA_RULER " Limits", view.m_showRanges );
            }
        }
    }

    ImGui::PopStyleVar();
    ImGui::Separator();

    uint64_t jumpOut = 0;
    switch( m_displayMode )
    {
    case DisplaySource:
        RenderSymbolSourceView( iptotalSrc, ipcountSrc, ipcountAsm, ipmaxSrc, worker, view );
        break;
    case DisplayAsm:
        jumpOut = RenderSymbolAsmView( iptotalAsm, ipcountAsm, ipmaxAsm, worker, view );
        break;
    case DisplayMixed:
        ImGui::Columns( 2 );
        RenderSymbolSourceView( iptotalSrc, ipcountSrc, ipcountAsm, ipmaxSrc, worker, view );
        ImGui::NextColumn();
        jumpOut = RenderSymbolAsmView( iptotalAsm, ipcountAsm, ipmaxAsm, worker, view );
        ImGui::EndColumns();
        break;
    default:
        assert( false );
        break;
    }

    if( jumpOut != 0 )
    {
        auto sym = worker.GetSymbolData( jumpOut );
        if( sym )
        {
            auto line = sym->line;
            auto file = line == 0 ? nullptr : worker.GetString( sym->file );
            if( file && !SourceFileValid( file, worker.GetCaptureTime(), view, worker ) )
            {
                file = nullptr;
                line = 0;
            }
            if( line > 0 || sym->size.Val() > 0 )
            {
                OpenSymbol( file, line, jumpOut, jumpOut, worker, view );
            }
        }
    }
}

static uint32_t GetHotnessColor( uint32_t ipSum, uint32_t maxIpCount )
{
    const auto ipPercent = float( ipSum ) / maxIpCount;
    if( ipPercent <= 0.5f )
    {
        const auto a = int( ( ipPercent * 1.5f + 0.25f ) * 255 );
        return 0x000000FF | ( a << 24 );
    }
    else if( ipPercent <= 1.f )
    {
        const auto g = int( ( ipPercent - 0.5f ) * 511 );
        return 0xFF0000FF | ( g << 8 );
    }
    else if( ipPercent <= 2.f )
    {
        const auto b = int( ( ipPercent - 1.f ) * 255 );
        return 0xFF00FFFF | ( b << 16 );
    }
    else
    {
        return 0xFFFFFFFF;
    }

}

void SourceView::RenderSymbolSourceView( uint32_t iptotal, unordered_flat_map<uint64_t, uint32_t> ipcount, unordered_flat_map<uint64_t, uint32_t> ipcountAsm, uint32_t ipmax, const Worker& worker, const View& view )
{
    if( m_sourceFiles.empty() )
    {
        if( m_data == m_dataBuf )
        {
            TextColoredUnformatted( ImVec4( 1.f, 1.f, 0.2f, 1.f ), ICON_FA_EXCLAMATION_TRIANGLE );
            ImGui::SameLine();
            TextColoredUnformatted( ImVec4( 1.f, 0.3f, 0.3f, 1.f ), "The source file contents might not reflect the actual profiled code!" );
            ImGui::SameLine();
            TextColoredUnformatted( ImVec4( 1.f, 1.f, 0.2f, 1.f ), ICON_FA_EXCLAMATION_TRIANGLE );
        }
        else
        {
            TextColoredUnformatted( ImVec4( 0.4f, 0.8f, 0.4f, 1.f ), ICON_FA_DATABASE );
            ImGui::SameLine();
            ImGui::TextUnformatted( "Source file cached during profiling run" );
        }
    }
    else
    {
        if( m_data == m_dataBuf )
        {
            TextColoredUnformatted( ImVec4( 1.f, 1.f, 0.2f, 1.f ), ICON_FA_EXCLAMATION_TRIANGLE );
            if( ImGui::IsItemHovered() )
            {
                ImGui::BeginTooltip();
                TextColoredUnformatted( ImVec4( 1.f, 1.f, 0.2f, 1.f ), ICON_FA_EXCLAMATION_TRIANGLE );
                ImGui::SameLine();
                TextColoredUnformatted( ImVec4( 1.f, 0.3f, 0.3f, 1.f ), "The source file contents might not reflect the actual profiled code!" );
                ImGui::SameLine();
                TextColoredUnformatted( ImVec4( 1.f, 1.f, 0.2f, 1.f ), ICON_FA_EXCLAMATION_TRIANGLE );
                ImGui::EndTooltip();
            }
        }
        else
        {
            TextColoredUnformatted( ImVec4( 0.4f, 0.8f, 0.4f, 1.f ), ICON_FA_DATABASE );
            if( ImGui::IsItemHovered() )
            {
                ImGui::BeginTooltip();
                ImGui::TextUnformatted( "Source file cached during profiling run" );
                ImGui::EndTooltip();
            }
        }
        ImGui::SameLine();
        TextDisabledUnformatted( ICON_FA_FILE " File:" );
        ImGui::SameLine();
        const auto fileColor = GetHsvColor( m_fileStringIdx, 0 );
        SmallColorBox( fileColor );
        ImGui::SameLine();
        ImGui::SetNextItemWidth( -1 );
        ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
        if( ImGui::BeginCombo( "##fileList", m_file, ImGuiComboFlags_HeightLarge ) )
        {
            if( m_asm.empty() )
            {
                for( auto& v : m_sourceFiles )
                {
                    const auto color = GetHsvColor( v.first, 0 );
                    SmallColorBox( color );
                    ImGui::SameLine();
                    auto fstr = worker.GetString( StringIdx( v.first ) );
                    if( SourceFileValid( fstr, worker.GetCaptureTime(), view, worker ) )
                    {
                        ImGui::PushID( v.first );
                        if( ImGui::Selectable( fstr, fstr == m_file ) )
                        {
                            ParseSource( fstr, worker, view );
                            m_targetLine = v.second;
                            SelectLine( v.second, &worker );
                        }
                        ImGui::PopID();
                    }
                    else
                    {
                        TextDisabledUnformatted( fstr );
                    }
                }
            }
            else
            {
                uint32_t totalSamples = 0;
                unordered_flat_map<uint32_t, uint32_t> fileCounts;
                for( auto& v : m_asm )
                {
                    uint32_t srcline;
                    const auto srcidx = worker.GetLocationForAddress( v.addr, srcline );
                    if( srcline != 0 )
                    {
                        uint32_t cnt = 0;
                        auto ait = ipcountAsm.find( v.addr );
                        if( ait != ipcountAsm.end() ) cnt = ait->second;

                        auto fit = fileCounts.find( srcidx.Idx() );
                        if( fit == fileCounts.end() )
                        {
                            fileCounts.emplace( srcidx.Idx(), cnt );
                        }
                        else if( cnt != 0 )
                        {
                            fit->second += cnt;
                        }
                        totalSamples += cnt;
                    }
                }
                std::vector<std::pair<uint32_t, uint32_t>> fileCountsVec;
                fileCountsVec.reserve( fileCounts.size() );
                for( auto& v : fileCounts ) fileCountsVec.emplace_back( v.first, v.second );
                pdqsort_branchless( fileCountsVec.begin(), fileCountsVec.end(), [&worker] (const auto& l, const auto& r ) { return l.second == r.second ? strcmp( worker.GetString( l.first ), worker.GetString( r.first ) ) < 0 : l.second > r.second; } );

                if( totalSamples != 0 )
                {
                    ImGui::Columns( 2 );
                    static bool widthSet = false;
                    if( !widthSet )
                    {
                        widthSet = true;
                        const auto w = ImGui::GetWindowWidth();
                        const auto c0 = ImGui::CalcTextSize( "12345678901234567890" ).x;
                        ImGui::SetColumnWidth( 0, c0 );
                        ImGui::SetColumnWidth( 1, w - c0 );
                    }
                }
                for( auto& v : fileCountsVec )
                {
                    if( totalSamples != 0 )
                    {
                        auto fit = fileCounts.find( v.first );
                        assert( fit != fileCounts.end() );
                        if( fit->second != 0 )
                        {
                            ImGui::TextUnformatted( TimeToString( fit->second * worker.GetSamplingPeriod() ) );
                            ImGui::SameLine();
                            ImGui::TextDisabled( "(%.2f%%)", 100.f * fit->second / totalSamples );
                            if( ImGui::IsItemHovered() )
                            {
                                ImGui::BeginTooltip();
                                TextFocused( "Sample count:", RealToString( fit->second ) );
                                ImGui::EndTooltip();
                            }
                        }
                        ImGui::NextColumn();
                    }
                    const auto color = GetHsvColor( v.first, 0 );
                    SmallColorBox( color );
                    ImGui::SameLine();
                    auto fstr = worker.GetString( StringIdx( v.first ) );
                    if( SourceFileValid( fstr, worker.GetCaptureTime(), view, worker ) )
                    {
                        ImGui::PushID( v.first );
                        if( ImGui::Selectable( fstr, fstr == m_file, ImGuiSelectableFlags_SpanAllColumns ) )
                        {
                            uint32_t line = 0;
                            for( auto& file : m_sourceFiles )
                            {
                                if( file.first == v.first )
                                {
                                    line = file.second;
                                    break;
                                }
                            }
                            ParseSource( fstr, worker, view );
                            m_targetLine = line;
                            SelectLine( line, &worker );
                        }
                        ImGui::PopID();
                    }
                    else
                    {
                        TextDisabledUnformatted( fstr );
                    }
                    if( totalSamples != 0 ) ImGui::NextColumn();
                }
                if( totalSamples != 0 ) ImGui::EndColumns();
            }
            ImGui::EndCombo();
        }
        ImGui::PopStyleVar();
    }

    const float bottom = m_srcSampleSelect.empty() ? 0 : ImGui::GetFrameHeight();
    ImGui::SetNextWindowContentSize( ImVec2( m_srcWidth, 0 ) );
    ImGui::BeginChild( "##sourceView", ImVec2( 0, -bottom ), true, ImGuiWindowFlags_NoMove | ImGuiWindowFlags_HorizontalScrollbar );
    if( m_font ) ImGui::PushFont( m_font );

    auto draw = ImGui::GetWindowDrawList();
    const auto wpos = ImGui::GetWindowPos() - ImVec2( ImGui::GetCurrentWindowRead()->Scroll.x, 0 );
    const auto wh = ImGui::GetWindowHeight();
    const auto ty = ImGui::GetFontSize();
    const auto ts = ImGui::CalcTextSize( " " ).x;
    const auto lineCount = m_lines.size();
    const auto tmp = RealToString( lineCount );
    const auto maxLine = strlen( tmp );
    auto lx = ts * maxLine + ty + round( ts*0.4f );
    if( iptotal != 0 ) lx += ts * 7 + ty;
    if( !m_asm.empty() )
    {
        const auto tmp = RealToString( m_asm.size() );
        const auto maxAsm = strlen( tmp ) + 1;
        lx += ts * maxAsm + ty;
    }
    draw->AddLine( wpos + ImVec2( lx, 0 ), wpos + ImVec2( lx, wh ), 0x08FFFFFF );

    m_selectedAddressesHover.clear();
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
            RenderLine( line, lineNum++, 0, iptotal, ipmax, &worker );
        }
        const auto win = ImGui::GetCurrentWindowRead();
        m_srcWidth = win->DC.CursorMaxPos.x - win->DC.CursorStartPos.x;
    }
    else
    {
        ImGuiListClipper clipper;
        clipper.Begin( (int)m_lines.size() );
        while( clipper.Step() )
        {
            if( iptotal == 0 )
            {
                for( auto i=clipper.DisplayStart; i<clipper.DisplayEnd; i++ )
                {
                    RenderLine( m_lines[i], i+1, 0, 0, 0, &worker );
                }
            }
            else
            {
                for( auto i=clipper.DisplayStart; i<clipper.DisplayEnd; i++ )
                {
                    auto it = ipcount.find( i+1 );
                    const auto ipcnt = it == ipcount.end() ? 0 : it->second;
                    RenderLine( m_lines[i], i+1, ipcnt, iptotal, ipmax, &worker );
                }
            }
        }
    }

    const auto win = ImGui::GetCurrentWindowRead();
    if( win->ScrollbarY )
    {
        auto draw = ImGui::GetWindowDrawList();
        auto rect = ImGui::GetWindowScrollbarRect( win, ImGuiAxis_Y );
        ImGui::PushClipRect( rect.Min, rect.Max, false );
        if( m_selectedLine != 0 )
        {
            const auto ly = round( rect.Min.y + ( m_selectedLine - 0.5f ) / m_lines.size() * rect.GetHeight() );
            draw->AddLine( ImVec2( rect.Min.x, ly ), ImVec2( rect.Max.x, ly ), 0x8899994C, 3 );
        }
        if( m_fileStringIdx == m_hoveredSource && m_hoveredLine != 0 )
        {
            const auto ly = round( rect.Min.y + ( m_hoveredLine - 0.5f ) / m_lines.size() * rect.GetHeight() );
            draw->AddLine( ImVec2( rect.Min.x, ly ), ImVec2( rect.Max.x, ly ), 0x88888888, 3 );
        }

        std::vector<std::pair<uint64_t, uint32_t>> ipData;
        ipData.reserve( ipcount.size() );
        for( auto& v : ipcount ) ipData.emplace_back( v.first, v.second );
        for( uint32_t lineNum = 1; lineNum <= m_lines.size(); lineNum++ )
        {
            if( ipcount.find( lineNum ) == ipcount.end() )
            {
                auto addresses = worker.GetAddressesForLocation( m_fileStringIdx, lineNum );
                if( addresses )
                {
                    for( auto& addr : *addresses )
                    {
                        if( addr >= m_baseAddr && addr < m_baseAddr + m_codeLen )
                        {
                            ipData.emplace_back( lineNum, 0 );
                            break;
                        }
                    }
                }
            }
        }
        pdqsort_branchless( ipData.begin(), ipData.end(), []( const auto& l, const auto& r ) { return l.first < r.first; } );

        const auto step = uint32_t( m_lines.size() * 2 / rect.GetHeight() );
        const auto x14 = round( rect.Min.x + rect.GetWidth() * 0.4f );
        const auto x34 = round( rect.Min.x + rect.GetWidth() * 0.6f );

        auto it = ipData.begin();
        while( it != ipData.end() )
        {
            const auto firstLine = it->first;
            uint32_t ipSum = 0;
            while( it != ipData.end() && it->first <= firstLine + step )
            {
                ipSum += it->second;
                ++it;
            }
            const auto ly = round( rect.Min.y + float( firstLine ) / m_lines.size() * rect.GetHeight() );
            const uint32_t color = ipSum == 0 ? 0x22FFFFFF : GetHotnessColor( ipSum, ipmax );
            draw->AddRectFilled( ImVec2( x14, ly ), ImVec2( x34, ly+3 ), color );
        }

        ImGui::PopClipRect();
    }

    if( m_font ) ImGui::PopFont();
    ImGui::EndChild();

    if( !m_srcSampleSelect.empty() )
    {
        uint32_t count = 0;
        uint32_t numLines = 0;
        for( auto& idx : m_srcSampleSelect )
        {
            auto it = ipcount.find( idx );
            if( it != ipcount.end() )
            {
                count += it->second;
                numLines++;
            }
        }

        ImGui::BeginChild( "##srcSelect" );
        if( ImGui::SmallButton( ICON_FA_TIMES ) )
        {
            m_srcSampleSelect.clear();
            m_srcGroupSelect = -1;
        }
        ImGui::SameLine();
        char buf[16];
        auto end = PrintFloat( buf, buf+16, 100.f * count / iptotal, 2 );
        memcpy( end, "%", 2 );
        TextFocused( "Selected:", buf );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextFocused( "Time:", TimeToString( count * worker.GetSamplingPeriod() ) );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextFocused( "Sample count:", RealToString( count ) );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextFocused( "Lines:", RealToString( numLines ) );
        ImGui::EndChild();
    }
}

static constexpr char HexPrint[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

static int PrintHexBytesRaw( char* buf, const uint8_t* bytes, size_t len )
{
    const auto start = buf;
    for( size_t i=0; i<len; i++ )
    {
        const auto byte = bytes[i];
        *buf++ = HexPrint[byte >> 4];
        *buf++ = HexPrint[byte & 0xF];
        *buf++ = ' ';
    }
    *--buf = '\0';
    return buf - start;
}

static int PrintHexBytesArm( char* buf, const uint8_t* bytes )
{
    const auto start = buf;
    for( int i=3; i>=0; i-- )
    {
        const auto byte = bytes[i];
        *buf++ = HexPrint[byte >> 4];
        *buf++ = HexPrint[byte & 0xF];
        *buf++ = ' ';
    }
    *--buf = '\0';
    return buf - start;
}

static int PrintHexBytes( char* buf, const uint8_t* bytes, size_t len, CpuArchitecture arch )
{
    switch( arch )
    {
    case CpuArchX86:
    case CpuArchX64:
        return PrintHexBytesRaw( buf, bytes, len );
    case CpuArchArm32:
    case CpuArchArm64:
        assert( len == 4 );
        return PrintHexBytesArm( buf, bytes );
    default:
        assert( false );
        return 0;
    }
}

uint64_t SourceView::RenderSymbolAsmView( uint32_t iptotal, unordered_flat_map<uint64_t, uint32_t> ipcount, uint32_t ipmax, const Worker& worker, View& view )
{
    if( m_disasmFail >= 0 )
    {
        TextColoredUnformatted( ImVec4( 1.f, 1.f, 0.2f, 1.f ), ICON_FA_EXCLAMATION_TRIANGLE );
        if( ImGui::IsItemHovered() )
        {
            const bool clicked = ImGui::IsItemClicked();
            ImGui::BeginTooltip();
            TextColoredUnformatted( ImVec4( 1, 0, 0, 1 ), "Disassembly failure." );
            ImGui::TextUnformatted( "Some instructions weren't properly decoded. Possible reasons:" );
            ImGui::TextUnformatted( " 1. Old version of capstone library doesn't support some instructions." );
            ImGui::TextUnformatted( " 2. Trying to decode data part of the symbol (e.g. jump arrays, etc.)" );
            TextFocused( "Code size:", RealToString( m_codeLen ) );
            TextFocused( "Disassembled bytes:", RealToString( m_disasmFail ) );
            char tmp[64];
            auto bytesLeft = std::min( 16u, m_codeLen - m_disasmFail );
            auto code = worker.GetSymbolCode( m_baseAddr, m_codeLen );
            assert( code );
            PrintHexBytesRaw( tmp, (const uint8_t*)code, bytesLeft );
            TextFocused( "Failure bytes:", tmp );
            TextDisabledUnformatted( "Click to copy to clipboard." );
            ImGui::EndTooltip();
            if( clicked ) ImGui::SetClipboardText( tmp );
        }
        ImGui::SameLine();
    }
    SmallCheckbox( ICON_FA_SEARCH_LOCATION " Relative loc.", &m_asmRelative );
    if( !m_sourceFiles.empty() )
    {
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        SmallCheckbox( ICON_FA_FILE_IMPORT " Source loc.", &m_asmShowSourceLocation );
    }
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    SmallCheckbox( ICON_FA_COGS " Machine code", &m_asmBytes );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    SmallCheckbox( ICON_FA_SHARE " Jumps", &m_showJumps );

    if( m_cpuArch == CpuArchX64 || m_cpuArch == CpuArchX86 )
    {
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        if( SmallCheckbox( "AT&T", &m_atnt ) ) Disassemble( m_baseAddr, worker );

        if( !m_atnt )
        {
            ImGui::SameLine();
            ImGui::Spacing();
            ImGui::SameLine();
            float mw = 0;
            for( auto& v : s_uArchUx )
            {
                const auto w = ImGui::CalcTextSize( v.uArch ).x;
                if( w > mw ) mw = w;
            }
            if( m_selMicroArch == m_profileMicroArch )
            {
                TextColoredUnformatted( ImVec4( 0.4f, 0.8f, 0.4f, 1.f ), ICON_FA_MICROCHIP );
                if( ImGui::IsItemHovered() )
                {
                    ImGui::BeginTooltip();
                    ImGui::TextUnformatted( "Selected microarchitecture is the same as the profiled application was running on" );
                    ImGui::EndTooltip();
                }
            }
            else
            {
                TextColoredUnformatted( ImVec4( 1.f, 0.3f, 0.3f, 1.f ), ICON_FA_MICROCHIP );
                if( ImGui::IsItemHovered() )
                {
                    ImGui::BeginTooltip();
                    ImGui::TextUnformatted( "Selected microarchitecture does not match the one profiled application was running on" );
                    if( m_profileMicroArch >= 0 )
                    {
                        ImGui::Text( "Measurements were performed on the %s microarchitecture", s_uArchUx[m_profileMicroArch].uArch );
                    }
                    else
                    {
                        ImGui::TextUnformatted( "Measurements were performed on an unknown microarchitecture" );
                    }
                    ImGui::EndTooltip();
                }
            }
            ImGui::SameLine( 0, 0 );
            ImGui::TextUnformatted( " \xce\xbc""arch:" );
            ImGui::SameLine();
            ImGui::SetNextItemWidth( mw + ImGui::GetFontSize() );
            ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
            if( ImGui::BeginCombo( "##uarch", s_uArchUx[m_selMicroArch].uArch, ImGuiComboFlags_HeightLarge ) )
            {
                int idx = 0;
                for( auto& v : s_uArchUx )
                {
                    if( ImGui::Selectable( v.uArch, idx == m_selMicroArch ) ) SelectMicroArchitecture( v.moniker );
                    ImGui::SameLine();
                    TextDisabledUnformatted( v.cpuName );
                    idx++;
                }
                ImGui::EndCombo();
            }
            ImGui::PopStyleVar();

            ImGui::SameLine();
            ImGui::Spacing();
            ImGui::SameLine();
            SmallCheckbox( ICON_FA_TRUCK_LOADING " Latency", &m_showLatency );
        }
    }

#ifndef TRACY_NO_FILESELECTOR
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    if( ImGui::SmallButton( ICON_FA_FILE_IMPORT " Save" ) )
    {
        Save( worker );
    }
#endif

    const float bottom = m_asmSampleSelect.empty() ? 0 : ImGui::GetFrameHeight();
    ImGui::SetNextWindowContentSize( ImVec2( m_asmWidth, 0 ) );
    ImGui::BeginChild( "##asmView", ImVec2( 0, -bottom ), true, ImGuiWindowFlags_NoMove | ImGuiWindowFlags_HorizontalScrollbar );
    if( m_font ) ImGui::PushFont( m_font );

    int maxAddrLen;
    {
        char tmp[32];
        sprintf( tmp, "%" PRIx64, m_baseAddr + m_codeLen );
        maxAddrLen = strlen( tmp );
    }

    uint64_t selJumpStart = 0;
    uint64_t selJumpEnd;
    uint64_t selJumpTarget;
    uint64_t jumpOut = 0;

    if( m_targetAddr != 0 )
    {
        for( auto& line : m_asm )
        {
            if( m_targetAddr == line.addr )
            {
                m_targetAddr = 0;
                ImGui::SetScrollHereY();
            }
            RenderAsmLine( line, 0, iptotal, ipmax, worker, jumpOut, maxAddrLen, view );
        }
        const auto win = ImGui::GetCurrentWindowRead();
        m_asmWidth = win->DC.CursorMaxPos.x - win->DC.CursorStartPos.x;
    }
    else
    {
        const auto th = (int)ImGui::GetTextLineHeightWithSpacing();
        ImGuiListClipper clipper;
        clipper.Begin( (int)m_asm.size(), th );
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
                    RenderAsmLine( m_asm[i], 0, 0, 0, worker, jumpOut, maxAddrLen, view );
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
                    RenderAsmLine( line, ipcnt, iptotal, ipmax, worker, jumpOut, maxAddrLen, view );
                    insList.emplace_back( line.addr );
                }
            }
            if( m_showJumps && !m_jumpTable.empty() )
            {
                auto draw = ImGui::GetWindowDrawList();
                const auto ts = ImGui::CalcTextSize( " " );
                const auto th2 = floor( ts.y / 2 );
                const auto th4 = floor( ts.y / 4 );
                const auto xoff = ( iptotal == 0 ? 0 : ( 7 * ts.x + ts.y ) ) + (3+maxAddrLen) * ts.x + ( ( m_asmShowSourceLocation && !m_sourceFiles.empty() ) ? 36 * ts.x : 0 ) + ( m_asmBytes ? m_maxAsmBytes*3 * ts.x : 0 );
                const auto minAddr = m_asm[clipper.DisplayStart].addr;
                const auto maxAddr = m_asm[clipper.DisplayEnd-1].addr;
                const auto mjl = m_maxJumpLevel;
                const auto JumpArrow = JumpArrowBase * ts.y / 15;

                int i = -1;
                for( auto& v : m_jumpTable )
                {
                    i++;
                    if( v.second.min > maxAddr || v.second.max < minAddr ) continue;
                    const auto col = GetHsvColor( i, 0 );

                    auto it0 = std::lower_bound( insList.begin(), insList.end(), v.second.min );
                    auto it1 = std::lower_bound( insList.begin(), insList.end(), v.second.max );
                    const auto y0 = ( it0 == insList.end() || *it0 != v.second.min ) ? -th : ( it0 - insList.begin() ) * th;
                    const auto y1 = it1 == insList.end() ? ( insList.size() + 1 ) * th  : ( it1 - insList.begin() ) * th;

                    float thickness = 1;
                    if( ImGui::IsWindowHovered() && ImGui::IsMouseHoveringRect( wpos + ImVec2( xoff + JumpSeparation * ( mjl - v.second.level ) - JumpSeparation / 2, y0 + th2 ), wpos + ImVec2( xoff + JumpSeparation * ( mjl - v.second.level ) + JumpSeparation / 2, y1 + th2 ) ) )
                    {
                        thickness = 2;
                        if( m_font ) ImGui::PopFont();
                        ImGui::BeginTooltip();
                        char tmp[32];
                        sprintf( tmp, "+%" PRIu64, v.first - m_baseAddr );
                        TextFocused( "Jump target:", tmp );
                        ImGui::SameLine();
                        sprintf( tmp, "(0x%" PRIx64 ")", v.first );
                        TextDisabledUnformatted( tmp );
                        auto lit = m_locMap.find( v.first );
                        assert( lit != m_locMap.end() );
                        sprintf( tmp, ".L%" PRIu32, lit->second );
                        TextFocused( "Jump label:", tmp );
                        uint32_t srcline;
                        const auto srcidx = worker.GetLocationForAddress( v.first, srcline );
                        if( srcline != 0 )
                        {
                            const auto fileName = worker.GetString( srcidx );
                            const auto fileColor = GetHsvColor( srcidx.Idx(), 0 );
                            TextDisabledUnformatted( "Target location:" );
                            ImGui::SameLine();
                            SmallColorBox( fileColor );
                            ImGui::SameLine();
                            ImGui::Text( "%s:%i", fileName, srcline );
                        }
                        TextFocused( "Jump range:", MemSizeToString( v.second.max - v.second.min ) );
                        TextFocused( "Jump sources:", RealToString( v.second.source.size() ) );
                        ImGui::EndTooltip();
                        if( m_font ) ImGui::PushFont( m_font );
                        if( ImGui::IsMouseClicked( 0 ) )
                        {
                            m_targetAddr = v.first;
                            m_selectedAddresses.clear();
                            m_selectedAddresses.emplace( v.first );
                        }
#ifndef TRACY_NO_FILESELECTOR
                        else if( ImGui::IsMouseClicked( 1 ) )
                        {
                            ImGui::OpenPopup( "jumpPopup" );
                            m_jumpPopupAddr = v.first;
                        }
#endif
                        selJumpStart = v.second.min;
                        selJumpEnd = v.second.max;
                        selJumpTarget = v.first;
                    }

                    draw->AddLine( wpos + ImVec2( xoff + JumpSeparation * ( mjl - v.second.level ), y0 + th2 ), wpos + ImVec2( xoff + JumpSeparation * ( mjl - v.second.level ), y1 + th2 ), col, thickness );

                    if( v.first >= minAddr && v.first <= maxAddr )
                    {
                        auto iit = std::lower_bound( insList.begin(), insList.end(), v.first );
                        assert( iit != insList.end() );
                        const auto y = ( iit - insList.begin() ) * th;
                        draw->AddLine( wpos + ImVec2( xoff + JumpSeparation * ( mjl - v.second.level ), y + th2 ), wpos + ImVec2( xoff + JumpSeparation * mjl + JumpArrow + 1, y + th2 ), col, thickness );
                        draw->AddLine( wpos + ImVec2( xoff + JumpSeparation * mjl + JumpArrow, y + th2 ), wpos + ImVec2( xoff + JumpSeparation * mjl + JumpArrow - th4, y + th2 - th4 ), col, thickness );
                        draw->AddLine( wpos + ImVec2( xoff + JumpSeparation * mjl + JumpArrow, y + th2 ), wpos + ImVec2( xoff + JumpSeparation * mjl + JumpArrow - th4, y + th2 + th4 ), col, thickness );
                    }
                    for( auto& s : v.second.source )
                    {
                        if( s >= minAddr && s <= maxAddr )
                        {
                            auto iit = std::lower_bound( insList.begin(), insList.end(), s );
                            assert( iit != insList.end() );
                            const auto y = ( iit - insList.begin() ) * th;
                            draw->AddLine( wpos + ImVec2( xoff + JumpSeparation * ( mjl - v.second.level ), y + th2 ), wpos + ImVec2( xoff + JumpSeparation * mjl + JumpArrow, y + th2 ), col, thickness );
                        }
                    }
                }
            }
        }

#ifndef TRACY_NO_FILESELECTOR
        if( m_font ) ImGui::PopFont();
        if( ImGui::BeginPopup( "jumpPopup" ) )
        {
            if( ImGui::Button( ICON_FA_FILE_IMPORT " Save jump range" ) )
            {
                auto it = m_jumpTable.find( m_jumpPopupAddr );
                assert( it != m_jumpTable.end() );

                size_t minIdx = 0, maxIdx = 0;
                size_t i;
                for( i=0; i<m_asm.size(); i++ )
                {
                    if( m_asm[i].addr == it->second.min )
                    {
                        minIdx = i++;
                        break;
                    }
                }
                assert( i != m_asm.size() );
                for( ; i<m_asm.size(); i++ )
                {
                    if( m_asm[i].addr == it->second.max )
                    {
                        maxIdx = i+1;
                        break;
                    }
                }
                assert( i != m_asm.size() );

                Save( worker, minIdx, maxIdx );
                ImGui::CloseCurrentPopup();
            }
            ImGui::EndPopup();
        }
        if( m_font ) ImGui::PushFont( m_font );
#endif
    }

    const auto win = ImGui::GetCurrentWindowRead();
    if( win->ScrollbarY )
    {
        auto draw = ImGui::GetWindowDrawList();
        auto rect = ImGui::GetWindowScrollbarRect( win, ImGuiAxis_Y );
        ImGui::PushClipRect( rect.Min, rect.Max, false );
        std::vector<uint32_t> lineOff;
        lineOff.reserve( std::max( m_selectedAddresses.size(), m_selectedAddressesHover.size() ) );
        if( !m_selectedAddresses.empty() )
        {
            for( size_t i=0; i<m_asm.size(); i++ )
            {
                if( m_selectedAddresses.find( m_asm[i].addr ) != m_selectedAddresses.end() )
                {
                    lineOff.push_back( uint32_t( i ) );
                }
            }
            float lastLine = 0;
            for( auto& v : lineOff )
            {
                const auto ly = round( rect.Min.y + ( v - 0.5f ) / m_asm.size() * rect.GetHeight() );
                if( ly > lastLine )
                {
                    lastLine = ly;
                    draw->AddLine( ImVec2( rect.Min.x, ly ), ImVec2( rect.Max.x, ly ), 0x8899994C, 1 );
                }
            }
        }
        if( !m_selectedAddressesHover.empty() )
        {
            lineOff.clear();
            for( size_t i=0; i<m_asm.size(); i++ )
            {
                if( m_selectedAddressesHover.find( m_asm[i].addr ) != m_selectedAddressesHover.end() )
                {
                    lineOff.push_back( uint32_t( i ) );
                }
            }
            float lastLine = 0;
            for( auto& v : lineOff )
            {
                const auto ly = round( rect.Min.y + ( v - 0.5f ) / m_asm.size() * rect.GetHeight() );
                if( ly > lastLine )
                {
                    lastLine = ly;
                    draw->AddLine( ImVec2( rect.Min.x, ly ), ImVec2( rect.Max.x, ly ), 0x88888888, 1 );
                }
            }
        }

        uint32_t selJumpLineStart, selJumpLineEnd, selJumpLineTarget;
        std::vector<std::pair<uint64_t, uint32_t>> ipData;
        ipData.reserve( ipcount.size() );
        if( selJumpStart == 0 )
        {
            for( size_t i=0; i<m_asm.size(); i++ )
            {
                auto it = ipcount.find( m_asm[i].addr );
                if( it == ipcount.end() ) continue;
                ipData.emplace_back( i, it->second );
            }
        }
        else
        {
            for( size_t i=0; i<m_asm.size(); i++ )
            {
                if( selJumpStart == m_asm[i].addr ) selJumpLineStart = i;
                if( selJumpEnd == m_asm[i].addr ) selJumpLineEnd = i;
                if( selJumpTarget == m_asm[i].addr ) selJumpLineTarget = i;

                auto it = ipcount.find( m_asm[i].addr );
                if( it == ipcount.end() ) continue;
                ipData.emplace_back( i, it->second );
            }
        }
        pdqsort_branchless( ipData.begin(), ipData.end(), []( const auto& l, const auto& r ) { return l.first < r.first; } );

        const auto step = uint32_t( m_asm.size() * 2 / rect.GetHeight() );
        const auto x40 = round( rect.Min.x + rect.GetWidth() * 0.4f );
        const auto x60 = round( rect.Min.x + rect.GetWidth() * 0.6f );

        auto it = ipData.begin();
        while( it != ipData.end() )
        {
            const auto firstLine = it->first;
            uint32_t ipSum = 0;
            while( it != ipData.end() && it->first <= firstLine + step )
            {
                ipSum += it->second;
                ++it;
            }
            const auto ly = round( rect.Min.y + float( firstLine ) / m_asm.size() * rect.GetHeight() );
            const uint32_t color = GetHotnessColor( ipSum, ipmax );
            draw->AddRectFilled( ImVec2( x40, ly ), ImVec2( x60, ly+3 ), color );
        }

        if( selJumpStart != 0 )
        {
            const auto yStart = rect.Min.y + float( selJumpLineStart ) / m_asm.size() * rect.GetHeight();
            const auto yEnd = rect.Min.y + float( selJumpLineEnd ) / m_asm.size() * rect.GetHeight();
            const auto yTarget = rect.Min.y + float( selJumpLineTarget ) / m_asm.size() * rect.GetHeight();
            const auto x50 = round( rect.Min.x + rect.GetWidth() * 0.5f ) - 1;
            const auto x25 = round( rect.Min.x + rect.GetWidth() * 0.25f );
            const auto x75 = round( rect.Min.x + rect.GetWidth() * 0.75f );
            draw->AddLine( ImVec2( x50, yStart ), ImVec2( x50, yEnd ), 0xFF00FF00 );
            draw->AddLine( ImVec2( x25, yTarget ), ImVec2( x75, yTarget ), 0xFF00FF00 );
        }

        if( m_asmSelected >= 0 )
        {
            const auto x0 = rect.Min.x;
            const auto x1 = rect.Min.x + rect.GetWidth() * 0.2f;
            float sy;
            for( int i=0; i<(int)m_asm.size(); i++ )
            {
                if( i == m_asmSelected )
                {
                    sy = round( rect.Min.y + ( i - 0.5f ) / m_asm.size() * rect.GetHeight() );
                }
                else if( m_asm[i].regData[0] != 0 )
                {
                    int flags = 0;
                    int idx = 0;
                    for(;;)
                    {
                        const auto& v = m_asm[i].regData[idx++];
                        if( v == 0 ) break;
                        flags |= v & FlagMask;
                    }
                    uint32_t col = 0;
                    if( ( flags & ( WriteBit | ReadBit ) ) == ( WriteBit | ReadBit ) ) col = 0xFF00FFFF;
                    else if( flags & WriteBit ) col = 0xFF0000FF;
                    else if( flags & ReadBit ) col = 0xFF00FF00;
                    if( col != 0 )
                    {
                        const auto ly = round( rect.Min.y + ( i - 0.5f ) / m_asm.size() * rect.GetHeight() );
                        draw->AddLine( ImVec2( x0, ly ), ImVec2( x1, ly ), col, 3 );
                    }
                }
            }
            draw->AddLine( ImVec2( x0, sy ), ImVec2( x1, sy ), 0xFFFF9900, 3 );
        }
    }

    if( m_font ) ImGui::PopFont();
    ImGui::EndChild();

    if( !m_asmSampleSelect.empty() )
    {
        uint32_t count = 0;
        uint32_t numLines = 0;
        for( auto& idx : m_asmSampleSelect )
        {
            auto it = ipcount.find( m_asm[idx].addr );
            if( it != ipcount.end() )
            {
                count += it->second;
                numLines++;
            }
        }

        ImGui::BeginChild( "##asmSelect" );
        if( ImGui::SmallButton( ICON_FA_TIMES ) )
        {
            m_asmSampleSelect.clear();
            m_asmGroupSelect = -1;
        }
        ImGui::SameLine();
        char buf[16];
        auto end = PrintFloat( buf, buf+16, 100.f * count / iptotal, 2 );
        memcpy( end, "%", 2 );
        TextFocused( "Selected:", buf );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextFocused( "Time:", TimeToString( count * worker.GetSamplingPeriod() ) );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextFocused( "Sample count:", RealToString( count ) );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextFocused( "Lines:", RealToString( numLines ) );
        ImGui::EndChild();
    }

    return jumpOut;
}

static bool PrintPercentage( float val, uint32_t col = 0xFFFFFFFF )
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
    DrawTextContrast( draw, wpos + ImVec2( htw, 0 ), col, buf );

    ImGui::ItemSize( ImVec2( stw * 7, ty ), 0 );
    return ImGui::IsWindowHovered() && ImGui::IsMouseHoveringRect( wpos, wpos + ImVec2( stw * 7, ty ) );
}

static const ImVec4 SyntaxColors[] = {
    { 0.7f,  0.7f,  0.7f,  1 },    // default
    { 0.45f, 0.68f, 0.32f, 1 },    // comment
    { 0.72f, 0.37f, 0.12f, 1 },    // preprocessor
    { 0.64f, 0.64f, 1,     1 },    // string
    { 0.64f, 0.82f, 1,     1 },    // char literal
    { 1,     0.91f, 0.53f, 1 },    // keyword
    { 0.81f, 0.6f,  0.91f, 1 },    // number
    { 0.9f,  0.9f,  0.9f,  1 },    // punctuation
    { 0.78f, 0.46f, 0.75f, 1 },    // type
    { 0.21f, 0.69f, 0.89f, 1 },    // special
};

void SourceView::RenderLine( const Line& line, int lineNum, uint32_t ipcnt, uint32_t iptotal, uint32_t ipmax, const Worker* worker )
{
    const auto ty = ImGui::GetFontSize();
    auto draw = ImGui::GetWindowDrawList();
    const auto w = std::max( m_srcWidth, ImGui::GetWindowWidth() );
    const auto wpos = ImGui::GetCursorScreenPos();
    if( m_fileStringIdx == m_hoveredSource && lineNum == m_hoveredLine )
    {
        draw->AddRectFilled( wpos, wpos + ImVec2( w, ty+1 ), 0x22FFFFFF );
    }
    else if( lineNum == m_selectedLine )
    {
        draw->AddRectFilled( wpos, wpos + ImVec2( w, ty+1 ), 0xFF333322 );
    }

    bool mouseHandled = false;
    if( iptotal != 0 )
    {
        if( ipcnt == 0 )
        {
            const auto ts = ImGui::CalcTextSize( " " );
            ImGui::ItemSize( ImVec2( 7 * ts.x, ts.y ) );
        }
        else
        {
            auto sit = m_srcSampleSelect.find( lineNum );
            if( PrintPercentage( 100.f * ipcnt / iptotal, sit == m_srcSampleSelect.end() ? 0xFFFFFFFF : 0xFF8888FF ) )
            {
                if( m_font ) ImGui::PopFont();
                ImGui::BeginTooltip();
                if( worker ) TextFocused( "Time:", TimeToString( ipcnt * worker->GetSamplingPeriod() ) );
                TextFocused( "Sample count:", RealToString( ipcnt ) );
                ImGui::EndTooltip();
                if( m_font ) ImGui::PushFont( m_font );

                if( ImGui::IsMouseClicked( 0 ) )
                {
                    mouseHandled = true;
                    auto& io = ImGui::GetIO();
                    if( io.KeyCtrl )
                    {
                        m_srcGroupSelect = lineNum;
                        if( sit == m_srcSampleSelect.end() )
                        {
                            m_srcSampleSelect.emplace( lineNum );
                        }
                        else
                        {
                            m_srcSampleSelect.erase( sit );
                        }
                    }
                    else if( io.KeyShift )
                    {
                        m_srcSampleSelect.clear();
                        if( m_srcGroupSelect == -1 )
                        {
                            m_srcGroupSelect = lineNum;
                            m_srcSampleSelect.insert( lineNum );
                        }
                        else
                        {
                            if( lineNum < m_srcGroupSelect )
                            {
                                for( int i=lineNum; i<=m_srcGroupSelect; i++ )
                                {
                                    m_srcSampleSelect.insert( i );
                                }
                            }
                            else
                            {
                                for( int i=m_srcGroupSelect; i<=lineNum; i++ )
                                {
                                    m_srcSampleSelect.insert( i );
                                }
                            }
                        }
                    }
                    else
                    {
                        m_srcSampleSelect.clear();
                        m_srcSampleSelect.insert( lineNum );
                        m_srcGroupSelect = lineNum;
                    }
                }
                else if( ImGui::IsMouseClicked( 1 ) )
                {
                    mouseHandled = true;
                    m_srcSampleSelect.clear();
                    m_srcGroupSelect = -1;
                }
            }
            draw->AddLine( wpos + ImVec2( 0, 1 ), wpos + ImVec2( 0, ty-2 ), GetHotnessColor( ipcnt, ipmax ) );
        }
        ImGui::SameLine( 0, ty );
    }

    const auto lineCount = m_lines.size();
    const auto tmp = RealToString( lineCount );
    const auto maxLine = strlen( tmp );
    const auto lineString = RealToString( lineNum );
    const auto linesz = strlen( lineString );
    char buf[16];
    memset( buf, ' ', maxLine - linesz );
    memcpy( buf + maxLine - linesz, lineString, linesz+1 );
    TextDisabledUnformatted( buf );
    ImGui::SameLine( 0, ty );

    uint32_t match = 0;
    if( !m_asm.empty() )
    {
        assert( worker );
        const auto stw = ImGui::CalcTextSize( " " ).x;
        auto addresses = worker->GetAddressesForLocation( m_fileStringIdx, lineNum );
        if( addresses )
        {
            for( auto& addr : *addresses )
            {
                match += ( addr >= m_baseAddr && addr < m_baseAddr + m_codeLen );
            }
        }
        const auto tmp = RealToString( m_asm.size() );
        const auto maxAsm = strlen( tmp ) + 1;
        if( match > 0 )
        {
            const auto asmString = RealToString( match );
            sprintf( buf, "@%s", asmString );
            const auto asmsz = strlen( buf );
            TextDisabledUnformatted( buf );
            ImGui::SameLine( 0, 0 );
            ImGui::ItemSize( ImVec2( stw * ( maxAsm - asmsz ), ty ), 0 );
        }
        else
        {
            ImGui::ItemSize( ImVec2( stw * maxAsm, ty ), 0 );
        }
    }

    ImGui::SameLine( 0, ty );
    auto ptr = line.begin;
    auto it = line.tokens.begin();
    while( ptr < line.end )
    {
        if( it == line.tokens.end() )
        {
            ImGui::TextUnformatted( ptr, line.end );
            ImGui::SameLine( 0, 0 );
            break;
        }
        if( ptr < it->begin )
        {
            ImGui::TextUnformatted( ptr, it->begin );
            ImGui::SameLine( 0, 0 );
        }
        TextColoredUnformatted( SyntaxColors[(int)it->color], it->begin, it->end );
        ImGui::SameLine( 0, 0 );
        ptr = it->end;
        ++it;
    }
    ImGui::ItemSize( ImVec2( 0, 0 ), 0 );

    if( match > 0 && ImGui::IsWindowHovered() && ImGui::IsMouseHoveringRect( wpos, wpos + ImVec2( w, ty+1 ) ) )
    {
        draw->AddRectFilled( wpos, wpos + ImVec2( w, ty+1 ), 0x11FFFFFF );
        if( !mouseHandled && ( ImGui::IsMouseClicked( 0 ) || ImGui::IsMouseClicked( 1 ) ) )
        {
            m_displayMode = DisplayMixed;
            SelectLine( lineNum, worker, ImGui::IsMouseClicked( 1 ) );
        }
        else
        {
            SelectAsmLinesHover( m_fileStringIdx, lineNum, *worker );
        }
    }

    draw->AddLine( wpos + ImVec2( 0, ty+2 ), wpos + ImVec2( w, ty+2 ), 0x08FFFFFF );
}

void SourceView::RenderAsmLine( AsmLine& line, uint32_t ipcnt, uint32_t iptotal, uint32_t ipmax, const Worker& worker, uint64_t& jumpOut, int maxAddrLen, View& view )
{
    const auto ty = ImGui::GetFontSize();
    auto draw = ImGui::GetWindowDrawList();
    const auto w = std::max( m_asmWidth, ImGui::GetWindowWidth() );
    const auto wpos = ImGui::GetCursorScreenPos();
    if( m_selectedAddressesHover.find( line.addr ) != m_selectedAddressesHover.end() )
    {
        draw->AddRectFilled( wpos, wpos + ImVec2( w, ty+1 ), 0x22FFFFFF );
    }
    else if( m_selectedAddresses.find( line.addr ) != m_selectedAddresses.end() )
    {
        draw->AddRectFilled( wpos, wpos + ImVec2( w, ty+1 ), 0xFF333322 );
    }
    if( line.addr == m_highlightAddr )
    {
        draw->AddRectFilled( wpos, wpos + ImVec2( w, ty+1 ), 0xFF222233 );
    }

    const auto asmIdx = &line - m_asm.data();

    if( iptotal != 0 )
    {
        if( ipcnt == 0 )
        {
            const auto ts = ImGui::CalcTextSize( " " );
            ImGui::ItemSize( ImVec2( 7 * ts.x, ts.y ) );
        }
        else
        {
            const auto idx = &line - m_asm.data();
            auto sit = m_asmSampleSelect.find( idx );
            if( PrintPercentage( 100.f * ipcnt / iptotal, sit == m_asmSampleSelect.end() ? 0xFFFFFFFF : 0xFF8888FF ) )
            {
                if( m_font ) ImGui::PopFont();
                ImGui::BeginTooltip();
                TextFocused( "Time:", TimeToString( ipcnt * worker.GetSamplingPeriod() ) );
                TextFocused( "Sample count:", RealToString( ipcnt ) );
                ImGui::EndTooltip();
                if( m_font ) ImGui::PushFont( m_font );

                if( ImGui::IsMouseClicked( 0 ) )
                {
                    auto& io = ImGui::GetIO();
                    if( io.KeyCtrl )
                    {
                        m_asmGroupSelect = idx;
                        if( sit == m_asmSampleSelect.end() )
                        {
                            m_asmSampleSelect.emplace( idx );
                        }
                        else
                        {
                            m_asmSampleSelect.erase( sit );
                        }
                    }
                    else if( io.KeyShift )
                    {
                        m_asmSampleSelect.clear();
                        if( m_asmGroupSelect == -1 )
                        {
                            m_asmGroupSelect = idx;
                            m_asmSampleSelect.insert( idx );
                        }
                        else
                        {
                            if( idx < m_asmGroupSelect )
                            {
                                for( int i=idx; i<=m_asmGroupSelect; i++ )
                                {
                                    m_asmSampleSelect.insert( i );
                                }
                            }
                            else
                            {
                                for( int i=m_asmGroupSelect; i<=idx; i++ )
                                {
                                    m_asmSampleSelect.insert( i );
                                }
                            }
                        }
                    }
                    else
                    {
                        m_asmSampleSelect.clear();
                        m_asmSampleSelect.insert( idx );
                        m_asmGroupSelect = idx;
                    }
                }
                else if( ImGui::IsMouseClicked( 1 ) )
                {
                    m_asmSampleSelect.clear();
                    m_asmGroupSelect = -1;
                }
                else if( ImGui::IsMouseClicked( 2 ) )
                {
                    const auto cfi = worker.PackPointer( line.addr );
                    auto inlineList = worker.GetInlineSymbolList( m_baseAddr, m_codeLen );
                    if( inlineList )
                    {
                        bool found = false;
                        const auto symEnd = m_baseAddr + m_codeLen;
                        while( *inlineList < symEnd )
                        {
                            auto ipmap = worker.GetSymbolInstructionPointers( *inlineList );
                            if( ipmap )
                            {
                                if( ipmap->find( cfi ) != ipmap->end() )
                                {
                                    view.ShowSampleParents( *inlineList );
                                    found = true;
                                    break;
                                }
                            }
                            inlineList++;
                        }
                        if( !found )
                        {
                            view.ShowSampleParents( m_baseAddr );
                        }
                    }
                    else
                    {
                        view.ShowSampleParents( m_baseAddr );
                    }
                }
            }
            draw->AddLine( wpos + ImVec2( 0, 1 ), wpos + ImVec2( 0, ty-2 ), GetHotnessColor( ipcnt, ipmax ) );
        }
        ImGui::SameLine( 0, ty );
    }

    char buf[256];
    if( m_asmCountBase >= 0 )
    {
        sprintf( buf, "[%i]", int( asmIdx - m_asmCountBase ) );
    }
    else if( m_asmRelative )
    {
        sprintf( buf, "+%" PRIu64, line.addr - m_baseAddr );
    }
    else
    {
        sprintf( buf, "%" PRIx64, line.addr );
    }
    const auto asz = strlen( buf );
    memset( buf+asz, ' ', maxAddrLen-asz );
    buf[maxAddrLen] = '\0';
    if( m_asmCountBase >= 0 )
    {
        TextColoredUnformatted( asmIdx - m_asmCountBase < 0 ? 0xFFBB6666 : 0xFF66BBBB, buf );
    }
    else
    {
        TextDisabledUnformatted( buf );
    }
    if( ImGui::IsItemClicked( 0 ) )
    {
        m_asmCountBase = asmIdx;
    }
    else if( ImGui::IsItemClicked( 1 ) )
    {
        m_asmCountBase = -1;
    }

    const auto stw = ImGui::CalcTextSize( " " ).x;
    bool lineHovered = false;
    if( m_asmShowSourceLocation && !m_sourceFiles.empty() )
    {
        ImGui::SameLine();
        uint32_t srcline;
        const auto srcidx = worker.GetLocationForAddress( line.addr, srcline );
        if( srcline != 0 )
        {
            const auto fileName = worker.GetString( srcidx );
            const auto fileColor = GetHsvColor( srcidx.Idx(), 0 );
            SmallColorBox( fileColor );
            ImGui::SameLine();
            char buf[64];
            const auto fnsz = strlen( fileName );
            if( fnsz < 30 - m_maxLine )
            {
                sprintf( buf, "%s:%i", fileName, srcline );
            }
            else
            {
                sprintf( buf, "...%s:%i", fileName+fnsz-(30-3-1-m_maxLine), srcline );
            }
            const auto bufsz = strlen( buf );
            TextDisabledUnformatted( buf );
            if( ImGui::IsItemHovered() )
            {
                lineHovered = true;
                if( m_font ) ImGui::PopFont();
                ImGui::BeginTooltip();
                TextFocused( "File:", fileName );
                TextFocused( "Line:", RealToString( srcline ) );
                ImGui::EndTooltip();
                if( m_font ) ImGui::PushFont( m_font );
                if( ImGui::IsItemClicked( 0 ) || ImGui::IsItemClicked( 1 ) )
                {
                    if( m_file == fileName )
                    {
                        if( ImGui::IsMouseClicked( 1 ) ) m_targetLine = srcline;
                        SelectLine( srcline, &worker, false );
                        m_displayMode = DisplayMixed;
                    }
                    else if( SourceFileValid( fileName, worker.GetCaptureTime(), view, worker ) )
                    {
                        ParseSource( fileName, worker, view );
                        m_targetLine = srcline;
                        SelectLine( srcline, &worker, false );
                        SelectViewMode();
                    }
                    else
                    {
                        SelectAsmLines( srcidx.Idx(), srcline, worker, false );
                    }
                }
                else
                {
                    m_hoveredLine = srcline;
                    m_hoveredSource = srcidx.Idx();
                }
            }
            ImGui::SameLine( 0, 0 );
            ImGui::ItemSize( ImVec2( stw * ( 32 - bufsz ), ty ), 0 );
        }
        else
        {
            SmallColorBox( 0 );
            ImGui::SameLine();
            TextDisabledUnformatted( "[unknown]" );
            ImGui::SameLine( 0, 0 );
            ImGui::ItemSize( ImVec2( stw * 23, ty ), 0 );
        }
    }
    if( m_asmBytes )
    {
        auto code = (const uint8_t*)worker.GetSymbolCode( m_baseAddr, m_codeLen );
        assert( code );
        char tmp[64];
        const auto len = PrintHexBytes( tmp, code + line.addr - m_baseAddr, line.len, worker.GetCpuArch() );
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 0.5, 0.5, 1, 1 ), tmp );
        ImGui::SameLine( 0, 0 );
        ImGui::ItemSize( ImVec2( stw * ( m_maxAsmBytes*3 - len ), ty ), 0 );
    }
    if( m_showJumps )
    {
        const auto JumpArrow = JumpArrowBase * ty / 15;
        ImGui::SameLine( 0, 2*ty + JumpArrow + m_maxJumpLevel * JumpSeparation );
        auto jit = m_jumpOut.find( line.addr );
        if( jit != m_jumpOut.end() )
        {
            const auto ts = ImGui::CalcTextSize( " " );
            const auto th2 = floor( ts.y / 2 );
            const auto th4 = floor( ts.y / 4 );
            const auto& mjl = m_maxJumpLevel;
            const auto col = GetHsvColor( line.jumpAddr, 6 );
            const auto xoff = ( iptotal == 0 ? 0 : ( 7 * ts.x + ts.y ) ) + (3+maxAddrLen) * ts.x + ( ( m_asmShowSourceLocation && !m_sourceFiles.empty() ) ? 36 * ts.x : 0 ) + ( m_asmBytes ? m_maxAsmBytes*3 * ts.x : 0 );

            draw->AddLine( wpos + ImVec2( xoff + JumpSeparation * mjl + th2, th2 ), wpos + ImVec2( xoff + JumpSeparation * mjl + th2 + JumpArrow / 2, th2 ), col );
            draw->AddLine( wpos + ImVec2( xoff + JumpSeparation * mjl + th2, th2 ), wpos + ImVec2( xoff + JumpSeparation * mjl + th2 + th4, th2 - th4 ), col );
            draw->AddLine( wpos + ImVec2( xoff + JumpSeparation * mjl + th2, th2 ), wpos + ImVec2( xoff + JumpSeparation * mjl + th2 + th4, th2 + th4 ), col );
        }
    }
    else
    {
        ImGui::SameLine( 0, ty );
    }

    int opdesc = 0;
    const AsmVar* asmVar = nullptr;
    if( !m_atnt && ( m_cpuArch == CpuArchX64 || m_cpuArch == CpuArchX86 ) )
    {
        auto uarch = MicroArchitectureData[m_idxMicroArch];
        char tmp[32];
        for( size_t i=0; i<line.mnemonic.size(); i++ )
        {
            auto c = line.mnemonic[i];
            if( c >= 'a' && c <= 'z' ) c = c - 'a' + 'A';
            tmp[i] = c;
        }
        tmp[line.mnemonic.size()] = '\0';
        const char* mnemonic = tmp;
        if( strcmp( mnemonic, "LEA" ) == 0 )
        {
            static constexpr const char* LeaTable[] = { "LEA", "LEA_B", "LEA_BD", "LEA_BI", "LEA_BID", "LEA_D", "LEA_I", "LEA_ID", "LEA_R", "LEA_RD" };
            mnemonic = LeaTable[(int)line.leaData];
        }
        auto it = m_microArchOpMap.find( mnemonic );
        if( it != m_microArchOpMap.end() )
        {
            const auto opid = it->second;
            auto oit = std::lower_bound( uarch->ops, uarch->ops + uarch->numOps, opid, []( const auto& l, const auto& r ) { return l->id < r; } );
            if( oit != uarch->ops + uarch->numOps && (*oit)->id == opid )
            {
                const auto& op = *oit;
                opdesc = op->descId;
                std::vector<std::pair<int, int>> res;
                res.reserve( op->numVariants );
                for( int i=0; i<op->numVariants; i++ )
                {
                    const auto& var = *op->variant[i];
                    if( var.descNum == (int)line.params.size() )
                    {
                        int penalty = 0;
                        bool match = true;
                        for( int j=0; j<var.descNum; j++ )
                        {
                            if( var.desc[j].type != line.params[j].type )
                            {
                                match = false;
                                break;
                            }
                            if( var.desc[j].width != line.params[j].width ) penalty++;
                        }
                        if( match )
                        {
                            res.emplace_back( i, penalty );
                        }
                    }
                }
                if( !res.empty() )
                {
                    pdqsort_branchless( res.begin(), res.end(), []( const auto& l, const auto& r ) { return l.second < r.second; } );
                    asmVar = op->variant[res[0].first];
                }
            }
        }
    }

    if( m_showLatency && asmVar && asmVar->minlat >= 0 )
    {
        const auto pos = ImVec2( (int)ImGui::GetCursorScreenPos().x, (int)ImGui::GetCursorScreenPos().y );
        const auto ty = ImGui::GetFontSize();

        if( asmVar->minlat == 0 )
        {
            draw->AddLine( pos + ImVec2( 0, -1 ), pos + ImVec2( 0, ty ), 0x660000FF );
        }
        else
        {
            draw->AddRectFilled( pos, pos + ImVec2( ty * asmVar->minlat + 1, ty + 1 ), 0x660000FF );
        }
        if( asmVar->minlat != asmVar->maxlat )
        {
            draw->AddRectFilled( pos + ImVec2( ty * asmVar->minlat + 1, 0 ), pos + ImVec2( ty * asmVar->maxlat + 1, ty + 1 ), 0x5500FFFF );
        }
    }

    const auto msz = line.mnemonic.size();
    memcpy( buf, line.mnemonic.c_str(), msz );
    memset( buf+msz, ' ', m_maxMnemonicLen-msz );
    bool hasJump = false;
    if( line.jumpAddr != 0 )
    {
        auto lit = m_locMap.find( line.jumpAddr );
        if( lit != m_locMap.end() )
        {
            char tmp[64];
            sprintf( tmp, ".L%" PRIu32, lit->second );
            strcpy( buf+m_maxMnemonicLen, tmp );
            hasJump = true;
        }
    }
    if( !hasJump )
    {
        memcpy( buf+m_maxMnemonicLen, line.operands.c_str(), line.operands.size() + 1 );
    }

    if( asmIdx == m_asmSelected )
    {
        TextColoredUnformatted( ImVec4( 1, 0.25f, 0.25f, 1 ), buf );
    }
    else if( line.regData[0] != 0 )
    {
        bool hasDepencency = false;
        int idx = 0;
        for(;;)
        {
            if( line.regData[idx] == 0 ) break;
            if( line.regData[idx] & ( WriteBit | ReadBit ) )
            {
                hasDepencency = true;
                break;
            }
            idx++;
        }
        if( hasDepencency )
        {
            TextColoredUnformatted( ImVec4( 1, 0.5f, 1, 1 ), buf );
        }
        else
        {
            ImGui::TextUnformatted( buf );
        }
    }
    else
    {
        ImGui::TextUnformatted( buf );
    }

    if( ImGui::IsItemHovered() )
    {
        if( asmVar )
        {
            const auto& var = *asmVar;
            if( m_font ) ImGui::PopFont();
            ImGui::BeginTooltip();
            if( opdesc != 0 )
            {
                ImGui::TextUnformatted( OpDescList[opdesc] );
                ImGui::Separator();
            }
            TextFocused( "Throughput:", RealToString( var.tp ) );
            ImGui::SameLine();
            TextDisabledUnformatted( "(cycles per instruction, lower is better)" );
            if( var.maxlat >= 0 )
            {
                TextDisabledUnformatted( "Latency:" );
                ImGui::SameLine();
                if( var.minlat == var.maxlat && var.minbound == var.maxbound )
                {
                    if( var.minbound )
                    {
                        ImGui::Text( "\xe2\x89\xa4%s", RealToString( var.minlat ) );
                    }
                    else
                    {
                        ImGui::TextUnformatted( RealToString( var.minlat ) );
                    }
                }
                else
                {
                    if( var.minbound )
                    {
                        ImGui::Text( "[\xe2\x89\xa4%s", RealToString( var.minlat ) );
                    }
                    else
                    {
                        ImGui::Text( "[%s", RealToString( var.minlat ) );
                    }
                    ImGui::SameLine( 0, 0 );
                    if( var.maxbound )
                    {
                        ImGui::Text( " \xE2\x80\x93 \xe2\x89\xa4%s]", RealToString( var.maxlat ) );
                    }
                    else
                    {
                        ImGui::Text( " \xE2\x80\x93 %s]", RealToString( var.maxlat ) );
                    }
                }
                ImGui::SameLine();
                TextDisabledUnformatted( "(cycles in execution, may vary by used output)" );
            }
            TextFocused( "\xce\xbcops:", RealToString( var.uops ) );
            if( var.port != -1 ) TextFocused( "Ports:", PortList[var.port] );
            ImGui::Separator();
            TextFocused( "ISA set:", IsaList[var.isaSet] );
            if( var.descNum > 0 )
            {
                TextDisabledUnformatted( "Operands:" );
                ImGui::SameLine();
                bool first = true;
                for( int i=0; i<var.descNum; i++ )
                {
                    const char* t = "?";
                    switch( var.desc[i].type )
                    {
                    case 0:
                        t = "Imm";
                        break;
                    case 1:
                        t = "Reg";
                        break;
                    case 2:
                        t = var.desc[i].width == 0 ? "AGen" : "Mem";
                        break;
                    default:
                        assert( false );
                        break;
                    }
                    if( first )
                    {
                        first = false;
                        if( var.desc[i].width == 0 )
                        {
                            ImGui::TextUnformatted( t );
                        }
                        else
                        {
                            ImGui::Text( "%s%i", t, var.desc[i].width );
                        }
                    }
                    else
                    {
                        ImGui::SameLine( 0, 0 );
                        if( var.desc[i].width == 0 )
                        {
                            ImGui::Text( ", %s", t );
                        }
                        else
                        {
                            ImGui::Text( ", %s%i", t, var.desc[i].width );
                        }
                    }
                }
            }
            ImGui::EndTooltip();
            if( m_font ) ImGui::PushFont( m_font );
        }
        if( m_cpuArch == CpuArchX86 || m_cpuArch == CpuArchX64 )
        {
            if( line.readX86[0] != RegsX86::invalid || line.writeX86[0] != RegsX86::invalid )
            {
                if( m_font ) ImGui::PopFont();
                ImGui::BeginTooltip();
                if( asmVar ) ImGui::Separator();
                if( line.readX86[0] != RegsX86::invalid )
                {
                    TextDisabledUnformatted( "Read:" );
                    ImGui::SameLine();
                    int idx = 0;
                    for(;;)
                    {
                        if( line.readX86[idx] == RegsX86::invalid ) break;
                        if( idx == 0 )
                        {
                            ImGui::TextUnformatted( s_regNameX86[(int)line.readX86[idx++]] );
                        }
                        else
                        {
                            ImGui::SameLine( 0, 0 );
                            ImGui::Text( ", %s", s_regNameX86[(int)line.readX86[idx++]] );
                        }
                    }
                }
                if( line.writeX86[0] != RegsX86::invalid )
                {
                    TextDisabledUnformatted( "Write:" );
                    ImGui::SameLine();
                    int idx = 0;
                    for(;;)
                    {
                        if( line.writeX86[idx] == RegsX86::invalid ) break;
                        if( idx == 0 )
                        {
                            ImGui::TextUnformatted( s_regNameX86[(int)line.writeX86[idx++]] );
                        }
                        else
                        {
                            ImGui::SameLine( 0, 0 );
                            ImGui::Text( ", %s", s_regNameX86[(int)line.writeX86[idx++]] );
                        }
                    }
                }
                ImGui::EndTooltip();
                if( m_font ) ImGui::PushFont( m_font );
            }
        }
        if( ImGui::IsMouseClicked( 0 ) )
        {
            m_asmSelected = asmIdx;
            ResetAsm();
            int idx = 0;
            for(;;)
            {
                if( line.readX86[idx] == RegsX86::invalid ) break;
                line.regData[idx] = ReadBit | (int)line.readX86[idx];
                FollowWrite( asmIdx, line.readX86[idx++], 64 );
            }
            idx = 0;
            for(;;)
            {
                if( line.writeX86[idx] == RegsX86::invalid ) break;
                int ridx = 0;
                for(;;)
                {
                    if( line.regData[ridx] == 0 )
                    {
                        line.regData[ridx] = WriteBit | (int)line.writeX86[idx];
                        break;
                    }
                    else if( ( line.regData[ridx] & RegMask ) == (int)line.writeX86[idx] )
                    {
                        line.regData[ridx] |= WriteBit;
                        break;
                    }
                    ridx++;
                }
                FollowRead( asmIdx, line.writeX86[idx++], 64 );
            }
        }
        else if( ImGui::IsMouseClicked( 1 ) )
        {
            m_asmSelected = -1;
            ResetAsm();
        }
    }

    auto lit = m_locMap.find( line.addr );
    if( lit != m_locMap.end() )
    {
        ImGui::SameLine();
        ImGui::TextDisabled( "; .L%" PRIu32, lit->second );
    }

    if( line.regData[0] != 0 )
    {
        if( !line.params.empty() )
        {
            ImGui::SameLine();
            ImGui::Spacing();
            ImGui::SameLine();
        }
        else
        {
            ImGui::SameLine( 0, 0 );
        }
        TextColoredUnformatted( ImVec4( 0.5f, 0.5, 1, 1 ), "{" );
        ImGui::SameLine( 0, 0 );
        int idx = 0;
        for(;;)
        {
            ImVec4 col;
            if( line.regData[idx] == 0 ) break;
            if( ( line.regData[idx] & ( WriteBit | ReadBit ) ) == ( WriteBit | ReadBit ) ) col = ImVec4( 1, 1, 0.5f, 1 );
            else if( line.regData[idx] & WriteBit ) col = ImVec4( 1, 0.5f, 0.5f, 1 );
            else if( line.regData[idx] & ReadBit ) col = ImVec4( 0.5f, 1, 0.5f, 1 );
            else col = ImVec4( 0.5f, 0.5f, 0.5f, 1 );
            if( idx > 0 )
            {
                ImGui::SameLine( 0, 0 );
                TextColoredUnformatted( ImVec4( 0.5f, 0.5, 1, 1 ), ", " );
                ImGui::SameLine( 0, 0 );
            }
            TextColoredUnformatted( col, s_regNameX86[line.regData[idx++] & RegMask] );
        }
        ImGui::SameLine( 0, 0 );
        TextColoredUnformatted( ImVec4( 0.5f, 0.5, 1, 1 ), "}" );
    }

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
                        m_selectedAddresses.clear();
                        m_selectedAddresses.emplace( line.jumpAddr );
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

    if( lineHovered )
    {
        draw->AddRectFilled( wpos, wpos + ImVec2( w, ty+1 ), 0x11FFFFFF );
    }

    draw->AddLine( wpos + ImVec2( 0, ty+2 ), wpos + ImVec2( w, ty+2 ), 0x08FFFFFF );
}

void SourceView::SelectLine( uint32_t line, const Worker* worker, bool changeAsmLine, uint64_t targetAddr )
{
    m_selectedLine = line;
    if( m_symAddr == 0 ) return;
    assert( worker );
    SelectAsmLines( m_fileStringIdx, line, *worker, changeAsmLine, targetAddr );
}

void SourceView::SelectAsmLines( uint32_t file, uint32_t line, const Worker& worker, bool changeAsmLine, uint64_t targetAddr )
{
    m_selectedAddresses.clear();
    auto addresses = worker.GetAddressesForLocation( file, line );
    if( addresses )
    {
        const auto& addr = *addresses;
        if( changeAsmLine )
        {
            if( targetAddr != 0 )
            {
                m_targetAddr = targetAddr;
            }
            else
            {
                for( auto& v : addr )
                {
                    if( v >= m_baseAddr && v < m_baseAddr + m_codeLen )
                    {
                        m_targetAddr = v;
                        break;
                    }
                }
            }
        }
        for( auto& v : addr )
        {
            if( v >= m_baseAddr && v < m_baseAddr + m_codeLen )
            {
                m_selectedAddresses.emplace( v );
            }
        }
    }
}

void SourceView::SelectAsmLinesHover( uint32_t file, uint32_t line, const Worker& worker )
{
    assert( m_selectedAddressesHover.empty() );
    auto addresses = worker.GetAddressesForLocation( file, line );
    if( addresses )
    {
        for( auto& v : *addresses )
        {
            if( v >= m_baseAddr && v < m_baseAddr + m_codeLen )
            {
                m_selectedAddressesHover.emplace( v );
            }
        }
    }
}

void SourceView::GatherIpStats( uint64_t addr, uint32_t& iptotalSrc, uint32_t& iptotalAsm, unordered_flat_map<uint64_t, uint32_t>& ipcountSrc, unordered_flat_map<uint64_t, uint32_t>& ipcountAsm, uint32_t& ipmaxSrc, uint32_t& ipmaxAsm, const Worker& worker, bool limitView, const View& view )
{
    if( limitView )
    {
        auto vec = worker.GetSamplesForSymbol( addr );
        if( !vec ) return;
        auto it = std::lower_bound( vec->begin(), vec->end(), view.m_statRange.min, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
        if( it == vec->end() ) return;
        auto end = std::lower_bound( it, vec->end(), view.m_statRange.max, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
        iptotalAsm += end - it;
        while( it != end )
        {
            if( m_file )
            {
                auto frame = worker.GetCallstackFrame( it->ip );
                if( frame )
                {
                    auto ffn = worker.GetString( frame->data[0].file );
                    if( strcmp( ffn, m_file ) == 0 )
                    {
                        const auto line = frame->data[0].line;
                        if( line != 0 )
                        {
                            auto sit = ipcountSrc.find( line );
                            if( sit == ipcountSrc.end() )
                            {
                                ipcountSrc.emplace( line, 1 );
                                if( ipmaxSrc < 1 ) ipmaxSrc = 1;
                            }
                            else
                            {
                                const auto sum = sit->second + 1;
                                sit->second = sum;
                                if( ipmaxSrc < sum ) ipmaxSrc = sum;
                            }
                            iptotalSrc++;
                        }
                    }
                }
            }

            auto addr = worker.GetCanonicalPointer( it->ip );
            auto sit = ipcountAsm.find( addr );
            if( sit == ipcountAsm.end() )
            {
                ipcountAsm.emplace( addr, 1 );
                if( ipmaxAsm < 1 ) ipmaxAsm = 1;
            }
            else
            {
                const auto sum = sit->second + 1;
                sit->second = sum;
                if( ipmaxAsm < sum ) ipmaxAsm = sum;
            }

            ++it;
        }
    }
    else
    {
        auto ipmap = worker.GetSymbolInstructionPointers( addr );
        if( !ipmap ) return;
        for( auto& ip : *ipmap )
        {
            if( m_file )
            {
                auto frame = worker.GetCallstackFrame( ip.first );
                if( frame )
                {
                    auto ffn = worker.GetString( frame->data[0].file );
                    if( strcmp( ffn, m_file ) == 0 )
                    {
                        const auto line = frame->data[0].line;
                        if( line != 0 )
                        {
                            auto it = ipcountSrc.find( line );
                            if( it == ipcountSrc.end() )
                            {
                                ipcountSrc.emplace( line, ip.second );
                                if( ipmaxSrc < ip.second ) ipmaxSrc = ip.second;
                            }
                            else
                            {
                                const auto sum = it->second + ip.second;
                                it->second = sum;
                                if( ipmaxSrc < sum ) ipmaxSrc = sum;
                            }
                            iptotalSrc += ip.second;
                        }
                    }
                }
            }

            auto addr = worker.GetCanonicalPointer( ip.first );
            assert( ipcountAsm.find( addr ) == ipcountAsm.end() );
            ipcountAsm.emplace( addr, ip.second );
            iptotalAsm += ip.second;
            if( ipmaxAsm < ip.second ) ipmaxAsm = ip.second;
        }
    }
}

uint32_t SourceView::CountAsmIpStats( uint64_t addr, const Worker& worker, bool limitView, const View& view )
{
    if( limitView )
    {
        auto vec = worker.GetSamplesForSymbol( addr );
        if( !vec ) return 0;
        auto it = std::lower_bound( vec->begin(), vec->end(), view.m_statRange.min, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
        if( it == vec->end() ) return 0;
        auto end = std::lower_bound( it, vec->end(), view.m_statRange.max, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
        return end - it;
    }
    else
    {
        uint32_t cnt = 0;
        auto ipmap = worker.GetSymbolInstructionPointers( addr );
        if( !ipmap ) return 0;
        for( auto& ip : *ipmap ) cnt += ip.second;
        return cnt;
    }
}

namespace {
static unordered_flat_set<const char*, charutil::Hasher, charutil::Comparator> GetKeywords()
{
    unordered_flat_set<const char*, charutil::Hasher, charutil::Comparator> ret;
    for( auto& v : {
        "alignas", "alignof", "and", "and_eq", "asm", "atomic_cancel", "atomic_commit", "atomic_noexcept",
        "bitand", "bitor", "break", "case", "catch", "class", "compl", "concept", "const", "consteval",
        "constexpr", "constinit", "const_cast", "continue", "co_await", "co_return", "co_yield", "decltype",
        "default", "delete", "do", "dynamic_cast", "else", "enum", "explicit", "export", "extern", "for",
        "friend", "if", "inline", "mutable", "namespace", "new", "noexcept", "not", "not_eq", "operator",
        "or", "or_eq", "private", "protected", "public", "reflexpr", "register", "reinterpret_cast",
        "return", "requires", "sizeof", "static", "static_assert", "static_cast", "struct", "switch",
        "synchronized", "template", "thread_local", "throw", "try", "typedef", "typeid", "typename",
        "union", "using", "virtual", "volatile", "while", "xor", "xor_eq", "override", "final", "import",
        "module", "transaction_safe", "transaction_safe_dynamic" } )
    {
        ret.insert( v );
    }
    return ret;
}
static unordered_flat_set<const char*, charutil::Hasher, charutil::Comparator> GetTypes()
{
    unordered_flat_set<const char*, charutil::Hasher, charutil::Comparator> ret;
    for( auto& v : {
        "bool", "char", "char8_t", "char16_t", "char32_t", "double", "float", "int", "long", "short", "signed",
        "unsigned", "void", "wchar_t", "size_t", "int8_t", "int16_t", "int32_t", "int64_t", "int_fast8_t",
        "int_fast16_t", "int_fast32_t", "int_fast64_t", "int_least8_t", "int_least16_t", "int_least32_t",
        "int_least64_t", "intmax_t", "intptr_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t", "uint_fast8_t",
        "uint_fast16_t", "uint_fast32_t", "uint_fast64_t", "uint_least8_t", "uint_least16_t", "uint_least32_t",
        "uint_least64_t", "uintmax_t", "uintptr_t", "type_info", "bad_typeid", "bad_cast", "type_index",
        "clock_t", "time_t", "tm", "timespec", "ptrdiff_t", "nullptr_t", "max_align_t", "auto",

        "__m64", "__m128", "__m128i", "__m128d", "__m256", "__m256i", "__m256d", "__m512", "__m512i",
        "__m512d", "__mmask8", "__mmask16", "__mmask32", "__mmask64",

        "int8x8_t", "int16x4_t", "int32x2_t", "int64x1_t", "uint8x8_t", "uint16x4_t", "uint32x2_t",
        "uint64x1_t", "float32x2_t", "poly8x8_t", "poly16x4_t", "int8x16_t", "int16x8_t", "int32x4_t",
        "int64x2_t", "uint8x16_t", "uint16x8_t", "uint32x4_t", "uint64x2_t", "float32x4_t", "poly8x16_t",
        "poly16x8_t",

        "int8x8x2_t", "int16x4x2_t", "int32x2x2_t", "int64x1x2_t", "uint8x8x2_t", "uint16x4x2_t",
        "uint32x2x2_t", "uint64x1x2_t", "float32x2x2_t", "poly8x8x2_t", "poly16x4x2_t", "int8x16x2_t",
        "int16x8x2_t", "int32x4x2_t", "int64x2x2_t", "uint8x16x2_t", "uint16x8x2_t", "uint32x4x2_t",
        "uint64x2x2_t", "float32x4x2_t", "poly8x16x2_t", "poly16x8x2_t",

        "int8x8x3_t", "int16x4x3_t", "int32x2x3_t", "int64x1x3_t", "uint8x8x3_t", "uint16x4x3_t",
        "uint32x2x3_t", "uint64x1x3_t", "float32x2x3_t", "poly8x8x3_t", "poly16x4x3_t", "int8x16x3_t",
        "int16x8x3_t", "int32x4x3_t", "int64x2x3_t", "uint8x16x3_t", "uint16x8x3_t", "uint32x4x3_t",
        "uint64x2x3_t", "float32x4x3_t", "poly8x16x3_t", "poly16x8x3_t",

        "int8x8x4_t", "int16x4x4_t", "int32x2x4_t", "int64x1x4_t", "uint8x8x4_t", "uint16x4x4_t",
        "uint32x2x4_t", "uint64x1x4_t", "float32x2x4_t", "poly8x8x4_t", "poly16x4x4_t", "int8x16x4_t",
        "int16x8x4_t", "int32x4x4_t", "int64x2x4_t", "uint8x16x4_t", "uint16x8x4_t", "uint32x4x4_t",
        "uint64x2x4_t", "float32x4x4_t", "poly8x16x4_t", "poly16x8x4_t" } )
    {
        ret.insert( v );
    }
    return ret;
}
static unordered_flat_set<const char*, charutil::Hasher, charutil::Comparator> GetSpecial()
{
    unordered_flat_set<const char*, charutil::Hasher, charutil::Comparator> ret;
    for( auto& v : { "this", "nullptr", "true", "false", "goto", "NULL" } )
    {
        ret.insert( v );
    }
    return ret;
}
}

static bool TokenizeNumber( const char*& begin, const char* end )
{
    const bool startNum = *begin >= '0' && *begin <= '9';
    if( *begin != '+' && *begin != '-' && !startNum ) return false;
    begin++;
    bool hasNum = startNum;
    while( begin < end && ( ( *begin >= '0' && *begin <= '9' ) || *begin == '\'' ) )
    {
        hasNum = true;
        begin++;
    }
    if( !hasNum ) return false;
    bool isFloat = false, isBinary = false;
    if( begin < end )
    {
        if( *begin == '.' )
        {
            isFloat = true;
            begin++;
            while( begin < end && ( ( *begin >= '0' && *begin <= '9' ) || *begin == '\'' ) ) begin++;
        }
        else if( *begin == 'x' || *begin == 'X' )
        {
            // hexadecimal
            begin++;
            while( begin < end && ( ( *begin >= '0' && *begin <= '9' ) || ( *begin >= 'a' && *begin <= 'f' ) || ( *begin >= 'A' && *begin <= 'F' ) || *begin == '\'' ) ) begin++;
        }
        else if( *begin == 'b' || *begin == 'B' )
        {
            isBinary = true;
            begin++;
            while( begin < end && ( ( *begin == '0' || *begin == '1' ) || *begin == '\'' ) ) begin++;
        }
    }
    if( !isBinary )
    {
        if( begin < end && ( *begin == 'e' || *begin == 'E' || *begin == 'p' || *begin == 'P' ) )
        {
            isFloat = true;
            begin++;
            if( begin < end && ( *begin == '+' || *begin == '-' ) ) begin++;
            bool hasDigits = false;
            while( begin < end && ( ( *begin >= '0' && *begin <= '9' ) || ( *begin >= 'a' && *begin <= 'f' ) || ( *begin >= 'A' && *begin <= 'F' ) || *begin == '\'' ) )
            {
                hasDigits = true;
                begin++;
            }
            if( !hasDigits ) return false;
        }
        if( begin < end && ( *begin == 'f' || *begin == 'F' || *begin == 'l' || *begin == 'L' ) ) begin++;
    }
    if( !isFloat )
    {
        while( begin < end && ( *begin == 'u' || *begin == 'U' || *begin == 'l' || *begin == 'L' ) ) begin++;
    }
    return true;
}

SourceView::TokenColor SourceView::IdentifyToken( const char*& begin, const char* end )
{
    static const auto s_keywords = GetKeywords();
    static const auto s_types = GetTypes();
    static const auto s_special = GetSpecial();

    if( *begin == '"' )
    {
        begin++;
        while( begin < end )
        {
            if( *begin == '"' )
            {
                begin++;
                break;
            }
            begin += 1 + ( *begin == '\\' && end - begin > 1 && *(begin+1) == '"' );
        }
        return TokenColor::String;
    }
    if( *begin == '\'' )
    {
        begin++;
        if( begin < end && *begin == '\\' ) begin++;
        if( begin < end ) begin++;
        if( begin < end && *begin == '\'' ) begin++;
        return TokenColor::CharacterLiteral;
    }
    if( ( *begin >= 'a' && *begin <= 'z' ) || ( *begin >= 'A' && *begin <= 'Z' ) || *begin == '_' )
    {
        const char* tmp = begin;
        begin++;
        while( begin < end && ( ( *begin >= 'a' && *begin <= 'z' ) || ( *begin >= 'A' && *begin <= 'Z' ) || ( *begin >= '0' && *begin <= '9' ) || *begin == '_' ) ) begin++;
        if( begin - tmp <= 24 )
        {
            char buf[25];
            memcpy( buf, tmp, begin-tmp );
            buf[begin-tmp] = '\0';
            if( s_keywords.find( buf ) != s_keywords.end() ) return TokenColor::Keyword;
            if( s_types.find( buf ) != s_types.end() ) return TokenColor::Type;
            if( s_special.find( buf ) != s_special.end() ) return TokenColor::Special;
        }
        return TokenColor::Default;
    }
    const char* tmp = begin;
    if( TokenizeNumber( begin, end ) ) return TokenColor::Number;
    begin = tmp;
    if( *begin == '/' && end - begin > 1 )
    {
        if( *(begin+1) == '/' )
        {
            begin = end;
            return TokenColor::Comment;
        }
        if( *(begin+1) == '*' )
        {
            begin += 2;
            for(;;)
            {
                while( begin < end && *begin != '*' ) begin++;
                if( begin == end )
                {
                    m_tokenizer.isInComment = true;
                    return TokenColor::Comment;
                }
                begin++;
                if( begin < end && *begin == '/' )
                {
                    begin++;
                    return TokenColor::Comment;
                }
            }
        }
    }
    while( begin < end )
    {
        switch( *begin )
        {
        case '[':
        case ']':
        case '{':
        case '}':
        case '!':
        case '%':
        case '^':
        case '&':
        case '*':
        case '(':
        case ')':
        case '-':
        case '+':
        case '=':
        case '~':
        case '|':
        case '<':
        case '>':
        case '?':
        case ':':
        case '/':
        case ';':
        case ',':
        case '.':
            begin++;
            break;
        default:
            goto out;
        }
    }
out:
    if( begin != tmp ) return TokenColor::Punctuation;
    begin = end;
    return TokenColor::Default;
}

std::vector<SourceView::Token> SourceView::Tokenize( const char* begin, const char* end )
{
    std::vector<Token> ret;
    if( m_tokenizer.isInPreprocessor )
    {
        if( begin == end )
        {
            m_tokenizer.isInPreprocessor = false;
            return ret;
        }
        if( *(end-1) != '\\' ) m_tokenizer.isInPreprocessor = false;
        ret.emplace_back( Token { begin, end, TokenColor::Preprocessor } );
        return ret;
    }
    const bool first = !m_tokenizer.isInComment;
    while( begin != end )
    {
        if( m_tokenizer.isInComment )
        {
            const auto pos = begin;
            for(;;)
            {
                while( begin != end && *begin != '*' ) begin++;
                begin++;
                if( begin < end )
                {
                    if( *begin == '/' )
                    {
                        begin++;
                        ret.emplace_back( Token { pos, begin, TokenColor::Comment } );
                        m_tokenizer.isInComment = false;
                        break;
                    }
                }
                else
                {
                    ret.emplace_back( Token { pos, end, TokenColor::Comment } );
                    return ret;
                }
            }
        }
        else
        {
            while( begin != end && isspace( *begin ) ) begin++;
            if( first && begin < end && *begin == '#' )
            {
                if( *(end-1) == '\\' ) m_tokenizer.isInPreprocessor = true;
                ret.emplace_back( Token { begin, end, TokenColor::Preprocessor } );
                return ret;
            }
            const auto pos = begin;
            const auto col = IdentifyToken( begin, end );
            ret.emplace_back( Token { pos, begin, col } );
        }
    }
    return ret;
}

void SourceView::SelectMicroArchitecture( const char* moniker )
{
    int idx = 0;
    for( auto& v : s_uArchUx )
    {
        if( strcmp( v.moniker, moniker ) == 0 )
        {
            m_selMicroArch = idx;
            break;
        }
        idx++;
    }
    for( idx=0; idx<MicroArchitectureNum; idx++ )
    {
        if( strcmp( MicroArchitectureList[idx], moniker ) == 0 )
        {
            m_idxMicroArch = idx;
            break;
        }
    }
    assert( idx != MicroArchitectureNum );
}

void SourceView::ResetAsm()
{
    for( auto& line : m_asm ) memset( line.regData, 0, sizeof( line.regData ) );
}

void SourceView::FollowRead( size_t line, RegsX86 reg, size_t limit )
{
    if( limit == 0 ) return;
    const auto& data = m_asm[line];
    if( m_jumpOut.find( data.addr ) != m_jumpOut.end() && !data.jumpConditional ) return;
    if( data.jumpAddr != 0 )
    {
        auto fit = std::lower_bound( m_asm.begin(), m_asm.end(), data.jumpAddr, []( const auto& l, const auto& r ) { return l.addr < r; } );
        if( fit != m_asm.end() && fit->addr == data.jumpAddr )
        {
            CheckRead( fit - m_asm.begin(), reg, limit );
        }
        if( !data.jumpConditional ) return;
    }
    if( line+1 < m_asm.size() )
    {
        CheckRead( line+1, reg, limit );
    }
}

void SourceView::FollowWrite( size_t line, RegsX86 reg, size_t limit )
{
    if( limit == 0 ) return;
    const auto& data = m_asm[line];
    if( m_jumpOut.find( data.addr ) != m_jumpOut.end() && !data.jumpConditional ) return;
    auto it = m_jumpTable.find( data.addr );
    if( it != m_jumpTable.end() )
    {
        for( auto& v : it->second.source )
        {
            auto fit = std::lower_bound( m_asm.begin(), m_asm.end(), v, []( const auto& l, const auto& r ) { return l.addr < r; } );
            assert( fit != m_asm.end() && fit->addr == v );
            CheckWrite( fit - m_asm.begin(), reg, limit );
        }
    }
    if( line > 0 )
    {
        CheckWrite( line-1, reg, limit );
    }
}

void SourceView::CheckRead( size_t line, RegsX86 reg, size_t limit )
{
    assert( limit > 0 );
    auto& data = m_asm[line];
    int idx = 0;
    for(;;)
    {
        if( data.readX86[idx] == RegsX86::invalid )
        {
            idx = 0;
            for(;;)
            {
                if( data.writeX86[idx] == RegsX86::invalid )
                {
                    FollowRead( line, reg, limit - 1 );
                    return;
                }
                if( data.writeX86[idx] == reg )
                {
                    idx = 0;
                    for(;;)
                    {
                        if( data.regData[idx] == 0 )
                        {
                            data.regData[idx] = ReuseBit | (int)reg;
                            return;
                        }
                        if( ( data.regData[idx] & RegMask ) == (int)reg )
                        {
                            data.regData[idx] |= ReuseBit;
                            return;
                        }
                        idx++;
                    }
                }
                idx++;
            }
        }
        if( data.readX86[idx] == reg )
        {
            idx = 0;
            for(;;)
            {
                if( data.regData[idx] == 0 )
                {
                    data.regData[idx] = ReadBit | (int)reg;
                    return;
                }
                if( ( data.regData[idx] & RegMask ) == (int)reg )
                {
                    data.regData[idx] |= ReadBit;
                    return;
                }
                idx++;
            }
        }
        idx++;
    }
}

void SourceView::CheckWrite( size_t line, RegsX86 reg, size_t limit )
{
    assert( limit > 0 );
    auto& data = m_asm[line];
    int idx = 0;
    for(;;)
    {
        if( data.writeX86[idx] == RegsX86::invalid )
        {
            idx = 0;
            for(;;)
            {
                if( data.readX86[idx] == RegsX86::invalid )
                {
                    FollowWrite( line, reg, limit - 1 );
                    return;
                }
                if( data.readX86[idx] == reg )
                {
                    idx = 0;
                    for(;;)
                    {
                        if( data.regData[idx] == 0 )
                        {
                            data.regData[idx] = ReuseBit | (int)reg;
                            return;
                        }
                        if( ( data.regData[idx] & RegMask ) == (int)reg )
                        {
                            data.regData[idx] |= ReuseBit;
                            return;
                        }
                        idx++;
                    }
                }
                idx++;
            }

        }
        if( data.writeX86[idx] == reg )
        {
            idx = 0;
            for(;;)
            {
                if( data.regData[idx] == 0 )
                {
                    data.regData[idx] = WriteBit | (int)reg;
                    return;
                }
                else if( ( data.regData[idx] & RegMask ) == (int)reg )
                {
                    data.regData[idx] |= WriteBit;
                    return;
                }
                idx++;
            }
        }
        idx++;
    }
}

void SourceView::Save( const Worker& worker, size_t start, size_t stop )
{
    assert( start < m_asm.size() );
    assert( start < stop );

    nfdchar_t* fn;
    auto res = NFD_SaveDialog( "asm", nullptr, &fn, m_gwcb ? m_gwcb() : nullptr );
    if( res == NFD_OKAY )
    {
        FILE* f = nullptr;
        const auto sz = strlen( fn );
        if( sz < 5 || memcmp( fn + sz - 4, ".asm", 4 ) != 0 )
        {
            char tmp[1024];
            sprintf( tmp, "%s.asm", fn );
            f = fopen( tmp, "wb" );
        }
        else
        {
            f = fopen( fn, "wb" );
        }
        if( f )
        {
            char tmp[16];
            auto sym = worker.GetSymbolData( m_symAddr );
            assert( sym );
            const char* symName;
            if( sym->isInline )
            {
                auto parent = worker.GetSymbolData( m_baseAddr );
                if( parent )
                {
                    symName = worker.GetString( parent->name );
                }
                else
                {
                    sprintf( tmp, "0x%" PRIx64, m_baseAddr );
                    symName = tmp;
                }
            }
            else
            {
                symName = worker.GetString( sym->name );
            }
            fprintf( f, "; Tracy Profiler disassembly of symbol %s [%s]\n\n", symName, worker.GetCaptureProgram().c_str() );
            if( !m_atnt ) fprintf( f, ".intel_syntax\n\n" );

            const auto end = m_asm.size() < stop ? m_asm.size() : stop;
            for( size_t i=start; i<end; i++ )
            {
                const auto& v = m_asm[i];
                auto it = m_locMap.find( v.addr );
                if( it != m_locMap.end() )
                {
                    fprintf( f, ".L%" PRIu32 ":\n", it->second );
                }
                bool hasJump = false;
                if( v.jumpAddr != 0 )
                {
                    auto lit = m_locMap.find( v.jumpAddr );
                    if( lit != m_locMap.end() )
                    {
                        fprintf( f, "\t%-*s.L%" PRIu32 "\n", m_maxMnemonicLen, v.mnemonic.c_str(), lit->second );
                        hasJump = true;
                    }
                }
                if( !hasJump )
                {
                    if( v.operands.empty() )
                    {
                        fprintf( f, "\t%s\n", v.mnemonic.c_str() );
                    }
                    else
                    {
                        fprintf( f, "\t%-*s%s\n", m_maxMnemonicLen, v.mnemonic.c_str(), v.operands.c_str() );
                    }
                }
            }
            fclose( f );
        }
    }
}

}
