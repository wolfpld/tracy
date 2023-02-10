#ifndef __TRACYSOURCEVIEW_HPP__
#define __TRACYSOURCEVIEW_HPP__

#include <limits>
#include <string>
#include <vector>

#include "tracy_robin_hood.h"
#include "TracyCharUtil.hpp"
#include "TracyDecayValue.hpp"
#include "TracySourceContents.hpp"
#include "TracySourceTokenizer.hpp"
#include "../public/common/TracyForceInline.hpp"
#include "../public/common/TracyProtocol.hpp"

struct ImFont;
struct ImVec2;

namespace tracy
{

class View;
class Worker;
struct CallstackFrameData;

class SourceView
{
public:
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

    enum class CostType
    {
        SampleCount,
        Cycles,
        SlowBranches,
        SlowCache,
        Retirements,
        BranchesTaken,
        BranchMiss,
        CacheAccess,
        CacheMiss
    };

private:
    struct AsmOpParams
    {
        uint8_t type;
        uint16_t width;
    };

    enum class LeaData : uint8_t
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

    enum { ReadBit  = 0x100 };
    enum { WriteBit = 0x200 };
    enum { ReuseBit = 0x400 };
    enum { RegMask  = 0x0FF };
    enum { FlagMask = 0xF00 };

    enum class OpType : uint8_t
    {
        None,
        Jump,
        Branch,
        Call,
        Ret,
        Privileged
    };

    struct AsmLine
    {
        uint64_t addr;
        uint64_t jumpAddr;
        std::string mnemonic;
        std::string operands;
        uint8_t len;
        LeaData leaData;
        OpType opType;
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

    enum { AsmLineSize = sizeof( AsmLine ) };

    struct JumpData
    {
        uint64_t min;
        uint64_t max;
        size_t level;
        std::vector<uint64_t> source;
    };

    enum
    {
        DisplaySource,
        DisplayAsm,
        DisplayMixed
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

public:
    SourceView();

    void UpdateFont( ImFont* fixed, ImFont* small, ImFont* big ) { m_font = fixed; m_smallFont = small; m_bigFont = big; }
    void SetCpuId( uint32_t cpuid );

    void OpenSource( const char* fileName, int line, const View& view, const Worker& worker );
    void OpenSymbol( const char* fileName, int line, uint64_t baseAddr, uint64_t symAddr, Worker& worker, const View& view );
    void Render( Worker& worker, View& view );

    void CalcInlineStats( bool val ) { m_calcInlineStats = val; }
    bool IsSymbolView() const { return !m_asm.empty(); }

private:
    void ParseSource( const char* fileName, const Worker& worker, const View& view );
    bool Disassemble( uint64_t symAddr, const Worker& worker );

    void SelectViewMode();

    void RenderSimpleSourceView();
    void RenderSymbolView( Worker& worker, View& view );

    void RenderSymbolSourceView( const AddrStatData& as, Worker& worker, const View& view );
    uint64_t RenderSymbolAsmView( const AddrStatData& as, Worker& worker, View& view );

    void RenderLine( const Tokenizer::Line& line, int lineNum, const AddrStat& ipcnt, const AddrStatData& as, Worker* worker, const View* view );
    void RenderAsmLine( AsmLine& line, const AddrStat& ipcnt, const AddrStatData& as, Worker& worker, uint64_t& jumpOut, int maxAddrLen, int maxAddrLenRel, View& view );
    void RenderHwLinePart( size_t cycles, size_t retired, size_t branchRetired, size_t branchMiss, size_t cacheRef, size_t cacheMiss, size_t branchRel, size_t branchRelMax, size_t cacheRel, size_t cacheRelMax, const ImVec2& ts );

    void SelectLine( uint32_t line, const Worker* worker, bool updateAsmLine = true, uint64_t targetAddr = 0, bool changeAsmLine = true );
    void SelectAsmLines( uint32_t file, uint32_t line, const Worker& worker, bool updateAsmLine = true, uint64_t targetAddr = 0, bool changeAsmLine = true );
    void SelectAsmLinesHover( uint32_t file, uint32_t line, const Worker& worker );

    void GatherIpHwStats( AddrStatData& as, Worker& worker, const View& view, CostType cost );
    void GatherIpStats( uint64_t baseAddr, AddrStatData& as, const Worker& worker, bool limitView, const View& view );
    void GatherAdditionalIpStats( uint64_t baseAddr, AddrStatData& as, const Worker& worker, bool limitView, const View& view );
    void GatherChildStats( uint64_t baseAddr, unordered_flat_map<uint64_t, uint32_t>& vec, Worker& worker, bool limitView, const View& view );

    uint32_t CountAsmIpStats( uint64_t baseAddr, const Worker& worker, bool limitView, const View& view );
    void CountHwStats( AddrStatData& as, Worker& worker, const View& view );

    void SelectMicroArchitecture( const char* moniker );

    void ResetAsm();
    void FollowRead( size_t line, RegsX86 reg, size_t limit );
    void FollowWrite( size_t line, RegsX86 reg, size_t limit );
    void CheckRead( size_t line, RegsX86 reg, size_t limit );
    void CheckWrite( size_t line, RegsX86 reg, size_t limit );

    bool IsInContext( const Worker& worker, uint64_t addr ) const;
    const std::vector<uint64_t>* GetAddressesForLocation( uint32_t fileStringIdx, uint32_t line, const Worker& worker );

    tracy_force_inline float CalcJumpSeparation( float scale );

#ifndef TRACY_NO_FILESELECTOR
    void Save( const Worker& worker, size_t start = 0, size_t stop = std::numeric_limits<size_t>::max() );
#endif

    tracy_force_inline void SetFont();
    tracy_force_inline void UnsetFont();

    ImFont* m_font;
    ImFont* m_smallFont;
    ImFont* m_bigFont;
    uint64_t m_symAddr;
    uint64_t m_baseAddr;
    uint64_t m_targetAddr;
    int m_targetLine;
    int m_selectedLine;
    int m_asmSelected;
    DecayValue<int> m_hoveredLine;
    DecayValue<uint32_t> m_hoveredSource;
    int m_displayMode;
    uint32_t m_codeLen;
    int32_t m_disasmFail;
    DecayValue<uint64_t> m_highlightAddr;
    int m_asmCountBase;
    bool m_asmRelative;
    bool m_asmBytes;
    bool m_asmShowSourceLocation;
    bool m_calcInlineStats;
    uint8_t m_maxAsmBytes;
    uint64_t m_jumpPopupAddr;
    const CallstackFrameData* m_localCallstackPopup;
    bool m_hwSamples, m_hwSamplesRelative;
    bool m_childCalls;
    bool m_childCallList;
    bool m_propagateInlines;
    CostType m_cost;

    SourceContents m_source;
    SourceContents m_sourceTooltip;
    std::vector<AsmLine> m_asm;

    unordered_flat_map<uint64_t, uint32_t> m_locMap;
    unordered_flat_map<uint64_t, JumpData> m_jumpTable;
    unordered_flat_set<uint64_t> m_jumpOut;
    size_t m_maxJumpLevel;
    bool m_showJumps;

    unordered_flat_map<uint64_t, std::vector<uint64_t>> m_locationAddress;
    bool m_locAddrIsProp;

    unordered_flat_map<uint32_t, uint32_t> m_sourceFiles;
    unordered_flat_set<uint64_t> m_selectedAddresses;
    unordered_flat_set<uint64_t> m_selectedAddressesHover;

    uint32_t m_maxLine;
    int m_maxMnemonicLen;
    int m_maxOperandLen;

    unordered_flat_map<const char*, int, charutil::Hasher, charutil::Comparator> m_microArchOpMap;
    CpuArchitecture m_cpuArch;
    int m_selMicroArch;
    int m_idxMicroArch, m_profileMicroArch;

    unordered_flat_set<uint32_t> m_asmSampleSelect;
    unordered_flat_set<uint32_t> m_srcSampleSelect;
    int32_t m_asmGroupSelect = -1;
    int32_t m_srcGroupSelect = -1;

    float m_srcWidth;
    float m_asmWidth;
    float m_jumpOffset;

    Tokenizer m_tokenizer;

    struct
    {
        uint32_t file = 0;
        uint32_t line = 0;
        size_t sel;
        std::vector<uint64_t> target;
    } m_asmTarget;
};

}

#endif
