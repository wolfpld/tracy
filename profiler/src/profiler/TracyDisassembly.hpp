#ifndef __TRACYDISASSEMBLY_HPP__
#define __TRACYDISASSEMBLY_HPP__

#include <nlohmann/json.hpp>
#include <stdint.h>
#include <string>
#include <vector>

#include "tracy_robin_hood.h"
#include "TracyProtocol.hpp"
#include "TracySourceTokenizer.hpp"

namespace tracy
{

class View;
class Worker;

enum class RegsX86 : uint8_t
{
    invalid, flags,
    rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8, r9, r10, r11, r12, r13, r14, r15,
    mm0, mm1, mm2, mm3, mm4, mm5, mm6, mm7,
    xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9,
    xmm10, xmm11, xmm12, xmm13, xmm14, xmm15, xmm16, xmm17, xmm18, xmm19,
    xmm20, xmm21, xmm22, xmm23, xmm24, xmm25, xmm26, xmm27, xmm28, xmm29,
    xmm30, xmm31, k0, k1, k2, k3, k4, k5, k6, k7,
    NUMBER_OF_ENTRIES
};

enum class AsmLeaData : uint8_t
{
    none,
    b,
    bd,
    bi,
    bid,
    d,
    i,
    id,
    r,
    rd
};

enum class AsmOpType : uint8_t
{
    None,
    Jump,
    Branch,
    Call,
    Ret,
    Privileged
};

struct AsmOpParams
{
    uint8_t type;
    uint16_t width;
};

struct AsmJumpData
{
    uint64_t min;
    uint64_t max;
    size_t level;
    std::vector<uint64_t> source;
};

struct AsmLine
{
    uint64_t addr;
    uint64_t jumpAddr;
    std::string mnemonic;
    std::string operands;
    uint8_t len;
    AsmLeaData leaData;
    AsmOpType opType;
    bool jumpConditional;
    std::vector<AsmOpParams> params;
    std::vector<Tokenizer::AsmToken> opTokens;
    union
    {
        RegsX86 readX86[12];
    };
    union
    {
        RegsX86 writeX86[20];
    };
    uint16_t regData[20];
};

struct DisasmData
{
    std::vector<AsmLine> lines;
    unordered_flat_map<uint64_t, uint32_t> locMap;
    unordered_flat_map<uint64_t, AsmJumpData> jumpTable;
    unordered_flat_set<uint64_t> jumpOut;
    unordered_flat_map<uint32_t, uint32_t> sourceFiles;

    size_t maxJumpLevel;
    int32_t disasmFail;
    uint32_t codeLen;
    size_t maxLine;
    int maxMnemonicLen;
    int maxOperandLen;
    uint8_t maxAsmBytes;

    CpuArchitecture cpuArch;
};

struct AddrStat
{
    uint64_t local;
    uint64_t ext;

    AddrStat& operator+=( const AddrStat& other )
    {
        local += other.local;
        ext += other.ext;
        return *this;
    }
};

struct AddrStatData
{
    AddrStat ipTotalSrc = {};
    AddrStat ipTotalAsm = {};
    AddrStat ipMaxSrc = {};
    AddrStat ipMaxAsm = {};
    AddrStat hwMaxSrc = {};
    AddrStat hwMaxAsm = {};
    unordered_flat_map<uint64_t, AddrStat> ipCountSrc, ipCountAsm;
    unordered_flat_map<uint64_t, AddrStat> hwCountSrc, hwCountAsm;
};

DisasmData Disassemble( uint64_t symAddr, const Worker& worker );
std::string FormatDisassemblyLine( const AsmLine& opcode, Worker& worker, std::vector<std::string>& sources, uint64_t symAddr, const AddrStatData& as, const unordered_flat_map<uint64_t, uint32_t>& locMap );
nlohmann::json JsonDisassembly( uint64_t symAddr, Worker& worker, const View& view );

void GatherIpStats( uint64_t baseAddr, AddrStatData& as, const Worker& worker, bool limitView, const View& view, const char* filename, bool propagateInlines );
void GatherAdditionalIpStats( uint64_t baseAddr, AddrStatData& as, const Worker& worker, bool limitView, const View& view, const char* filename, bool propagateInlines );

}

#endif
