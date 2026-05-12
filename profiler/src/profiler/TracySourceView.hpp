#ifndef __TRACYSOURCEVIEW_HPP__
#define __TRACYSOURCEVIEW_HPP__

#include <limits>
#include <tuple>
#include <vector>

#include "tracy_robin_hood.h"
#include "TracyCharUtil.hpp"
#include "TracyDecayValue.hpp"
#include "TracyDisassembly.hpp"
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
    static constexpr int ReadBit  = 0x100;
    static constexpr int WriteBit = 0x200;
    static constexpr int ReuseBit = 0x400;
    static constexpr int RegMask  = 0x0FF;
    static constexpr int FlagMask = 0xF00;

    enum
    {
        DisplaySource,
        DisplayAsm,
        DisplayMixed
    };

    struct History
    {
        const char* fileName;
        int64_t line;
        uint64_t baseAddr;
        uint64_t symAddr;
    };

public:
    SourceView();

    void SetCpuId( uint32_t cpuid );

    void OpenSource( const char* fileName, int line, const View& view, const Worker& worker );
    void OpenSymbol( const char* fileName, int line, uint64_t baseAddr, uint64_t symAddr, Worker& worker, const View& view, bool updateHistory = true );
    void Render( Worker& worker, View& view );

    bool SwitchTo( const char* fileName, int line, const Worker& worker, const View& view );

    void CalcInlineStats( bool val ) { m_calcInlineStats = val; }
    bool IsSymbolView() const { return !m_asm.empty(); }

private:
    void ParseSource( const char* fileName, const Worker& worker, const View& view );
    bool Disassemble( uint64_t symAddr, const Worker& worker );

    void SelectViewMode();

    void RenderSimpleSourceView();
    void RenderSymbolView( Worker& worker, View& view );

    void RenderSymbolSourceView( const AddrStatData& as, Worker& worker, View& view, bool hasInlines );
    uint64_t RenderSymbolAsmView( const AddrStatData& as, Worker& worker, View& view );

    void RenderLine( const Tokenizer::Line& line, int lineNum, const AddrStat& ipcnt, const AddrStatData& as, Worker* worker, const View* view );
    void RenderAsmLine( AsmLine& line, const AddrStat& ipcnt, const AddrStatData& as, Worker& worker, uint64_t& jumpOut, int maxAddrLen, int maxAddrLenRel, View& view );
    void RenderHwLinePart( size_t cycles, size_t retired, size_t branchRetired, size_t branchMiss, size_t cacheRef, size_t cacheMiss, size_t branchRel, size_t branchRelMax, size_t cacheRel, size_t cacheRelMax, const ImVec2& ts );

    void SelectLine( uint32_t line, const Worker* worker, bool updateAsmLine = true, uint64_t targetAddr = 0, bool changeAsmLine = true );
    void SelectAsmLines( uint32_t file, uint32_t line, const Worker& worker, bool updateAsmLine = true, uint64_t targetAddr = 0, bool changeAsmLine = true );
    void SelectAsmLinesHover( uint32_t file, uint32_t line, const Worker& worker );

    void GatherIpHwStats( AddrStatData& as, Worker& worker, const View& view, CostType cost );
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
    std::tuple<size_t, size_t> GetJumpRange( const AsmJumpData& jump );

    void AttachRangeToLlm( size_t start, size_t stop, Worker& worker, View& view );

#ifndef TRACY_NO_FILESELECTOR
    void Save( const Worker& worker, size_t start = 0, size_t stop = std::numeric_limits<size_t>::max() );
#endif

    tracy_force_inline void SetFont();
    tracy_force_inline void UnsetFont();

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
    unordered_flat_map<uint64_t, AsmJumpData> m_jumpTable;
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

    struct
    {
        uint32_t file = 0;
        uint32_t line = 0;
        size_t sel;
        std::vector<uint64_t> target;
    } m_asmTarget;

    std::vector<History> m_history;
    size_t m_historyCursor = 0;

    float m_childCallHeight = 0;
};

}

#endif
