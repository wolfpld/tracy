#include <capstone.h>
#include <string.h>

#include "TracyDisassembly.hpp"
#include "tracy_pdqsort.h"
#include "../server/TracyWorker.hpp"

namespace tracy
{

static RegsX86 s_regMapX86[X86_REG_ENDING];

struct InitRegMapX86
{
    InitRegMapX86()
    {
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
        s_regMapX86[X86_REG_BPL] = RegsX86::rbp;
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
};

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

DisasmData Disassemble( uint64_t symAddr, const Worker& worker )
{
    DisasmData data = {};
    data.disasmFail = -1;

    if( symAddr == 0 ) return data;
    data.cpuArch = worker.GetCpuArch();
    if( data.cpuArch == CpuArchUnknown ) return data;
    uint32_t len;
    auto code = worker.GetSymbolCode( symAddr, len );
    if( !code ) return data;
    data.codeLen = len;

    static InitRegMapX86 regMapInit;

    csh handle;
    cs_err rval = CS_ERR_ARCH;
    switch( data.cpuArch )
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
        rval = cs_open( CS_ARCH_AARCH64, CS_MODE_ARM, &handle );
        break;
    default:
        assert( false );
        break;
    }
    if( rval != CS_ERR_OK ) return data;

    Tokenizer tokenizer;

    cs_option( handle, CS_OPT_DETAIL, CS_OPT_ON );
    cs_option( handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL );
    cs_insn* insn;
    size_t cnt = cs_disasm( handle, (const uint8_t*)code, len, symAddr, 0, &insn );
    if( cnt > 0 )
    {
        if( insn[cnt-1].address - symAddr + insn[cnt-1].size < len ) data.disasmFail = insn[cnt-1].address - symAddr;
        int bytesMax = 0;
        int mLenMax = 0;
        int oLenMax = 0;
        data.lines.reserve( cnt );
        for( size_t i=0; i<cnt; i++ )
        {
            const auto& op = insn[i];
            const auto& detail = *op.detail;
            bool hasJump = false;
            bool jumpConditional = false;
            AsmOpType opType = AsmOpType::None;
            for( auto j=0; j<detail.groups_count; j++ )
            {
                if( detail.groups[j] == CS_GRP_JUMP || detail.groups[j] == CS_GRP_CALL || detail.groups[j] == CS_GRP_RET )
                {
                    hasJump = true;
                    break;
                }
            }
            for( auto j=0; j<detail.groups_count; j++ )
            {
                if( detail.groups[j] == CS_GRP_JUMP && opType < AsmOpType::Jump ) opType = AsmOpType::Jump;
                else if( detail.groups[j] == CS_GRP_BRANCH_RELATIVE && opType < AsmOpType::Branch ) opType = AsmOpType::Branch;
                else if( detail.groups[j] == CS_GRP_CALL && opType < AsmOpType::Call ) opType = AsmOpType::Call;
                else if( detail.groups[j] == CS_GRP_RET && opType < AsmOpType::Ret ) opType = AsmOpType::Ret;
                else if( detail.groups[j] == CS_GRP_PRIVILEGE && opType < AsmOpType::Privileged )
                {
                    opType = AsmOpType::Privileged;
                    break;
                }
            }
            uint64_t jumpAddr = 0;
            if( hasJump )
            {
                switch( data.cpuArch )
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
                    if( detail.aarch64.op_count == 1 && detail.aarch64.operands[0].type == AARCH64_OP_IMM )
                    {
                        jumpAddr = (uint64_t)detail.aarch64.operands[0].imm;
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
                        auto it = data.jumpTable.find( jumpAddr );
                        if( it == data.jumpTable.end() )
                        {
                            data.jumpTable.emplace( jumpAddr, AsmJumpData { min, max, 0, { op.address } } );
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
                    data.jumpOut.emplace( op.address );
                }
            }
            std::vector<AsmOpParams> params;
            switch( data.cpuArch )
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
                for( uint8_t i=0; i<detail.aarch64.op_count; i++ )
                {
                    uint8_t type = 0;
                    switch( detail.aarch64.operands[i].type )
                    {
                    case AARCH64_OP_IMM:
                        type = 0;
                        break;
                    case AARCH64_OP_REG:
                        type = 1;
                        break;
                    case AARCH64_OP_MEM:
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
            AsmLeaData leaData = AsmLeaData::none;
            if( ( data.cpuArch == CpuArchX64 || data.cpuArch == CpuArchX86 ) && op.id == X86_INS_LEA )
            {
                assert( op.detail->x86.op_count == 2 );
                assert( op.detail->x86.operands[1].type == X86_OP_MEM );
                auto& mem = op.detail->x86.operands[1].mem;
                if( mem.base == X86_REG_INVALID )
                {
                    if( mem.index == X86_REG_INVALID )
                    {
                        leaData = AsmLeaData::d;
                    }
                    else
                    {
                        leaData = mem.disp == 0 ? AsmLeaData::i : AsmLeaData::id;
                    }
                }
                else if( mem.base == X86_REG_RIP )
                {
                    leaData = mem.disp == 0 ? AsmLeaData::r : AsmLeaData::rd;
                }
                else
                {
                    if( mem.index == X86_REG_INVALID )
                    {
                        leaData = mem.disp == 0 ? AsmLeaData::b : AsmLeaData::bd;
                    }
                    else
                    {
                        leaData = mem.disp == 0 ? AsmLeaData::bi : AsmLeaData::bid;
                    }
                }
            }
            data.lines.emplace_back( AsmLine { op.address, jumpAddr, op.mnemonic, op.op_str, (uint8_t)op.size, leaData, opType, jumpConditional, std::move( params ) } );
            const auto& operands = data.lines.back().operands;
            data.lines.back().opTokens = tokenizer.TokenizeAsm( operands.c_str(), operands.c_str() + operands.size() );

#if CS_API_MAJOR >= 4
            auto& entry = data.lines.back();
            cs_regs read, write;
            uint8_t rcnt, wcnt;
            cs_regs_access( handle, &op, read, &rcnt, write, &wcnt );
            int idx;
            switch( data.cpuArch )
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
            const auto oLen = (int)strlen( op.op_str );
            if( oLen > oLenMax ) oLenMax = oLen;
            if( op.size > bytesMax ) bytesMax = op.size;

            uint32_t mLineMax = 0;
            uint32_t srcline;
            const auto srcidx = worker.GetLocationForAddress( op.address, srcline );
            if( srcidx.Active() )
            {
                mLineMax = srcline;
                const auto idx = srcidx.Idx();
                auto sit = data.sourceFiles.find( idx );
                if( sit == data.sourceFiles.end() ) data.sourceFiles.emplace( idx, srcline );
            }
            char tmp[16];
            sprintf( tmp, "%" PRIu32, mLineMax );
            data.maxLine = std::max( data.maxLine, strlen( tmp ) + 1 );
        }
        cs_free( insn, cnt );
        data.maxMnemonicLen = mLenMax + 1;
        data.maxOperandLen = oLenMax + 1;
        data.maxAsmBytes = bytesMax;
        if( !data.jumpTable.empty() )
        {
            struct JumpRange
            {
                uint64_t target;
                uint64_t len;
            };
            std::vector<JumpRange> jumpRange;
            jumpRange.reserve( data.jumpTable.size() );
            for( auto& v : data.jumpTable )
            {
                pdqsort_branchless( v.second.source.begin(), v.second.source.end() );
                jumpRange.emplace_back( JumpRange { v.first, v.second.max - v.second.min } );
            }
            pdqsort_branchless( jumpRange.begin(), jumpRange.end(), []( const auto& l, const auto& r ) { return l.len < r.len; } );
            std::vector<std::vector<std::pair<uint64_t, uint64_t>>> levelRanges;
            for( auto& v : jumpRange )
            {
                auto it = data.jumpTable.find( v.target );
                assert( it != data.jumpTable.end() );
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
                if( level > data.maxJumpLevel ) data.maxJumpLevel = level;
            }

            uint32_t locNum = 0;
            for( auto& v : data.lines )
            {
                if( data.jumpTable.contains( v.addr ) )
                {
                    data.locMap.emplace( v.addr, locNum++ );
                }
            }
        }
    }
    cs_close( &handle );

    return data;
}

}
