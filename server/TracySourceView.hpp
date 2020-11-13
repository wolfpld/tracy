#ifndef __TRACYSOURCEVIEW_HPP__
#define __TRACYSOURCEVIEW_HPP__

#include <limits>
#include <string>
#include <vector>

#include "tracy_robin_hood.h"
#include "TracyCharUtil.hpp"
#include "TracyDecayValue.hpp"
#include "../common/TracyProtocol.hpp"

struct ImFont;

namespace tracy
{

class View;
class Worker;

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

private:
    enum class TokenColor : uint8_t
    {
        Default,
        Comment,
        Preprocessor,
        String,
        CharacterLiteral,
        Keyword,
        Number,
        Punctuation,
        Type,
        Special
    };

    struct Token
    {
        const char* begin;
        const char* end;
        TokenColor color;
    };

    struct Line
    {
        const char* begin;
        const char* end;
        std::vector<Token> tokens;
    };

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

    struct AsmLine
    {
        uint64_t addr;
        uint64_t jumpAddr;
        std::string mnemonic;
        std::string operands;
        uint8_t len;
        LeaData leaData;
        bool jumpConditional;
        std::vector<AsmOpParams> params;
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

public:
    using GetWindowCallback = void*(*)();

    SourceView( ImFont* font, GetWindowCallback gwcb );
    ~SourceView();

    void SetCpuId( uint32_t cpuid );

    void OpenSource( const char* fileName, int line, const View& view, const Worker& worker );
    void OpenSymbol( const char* fileName, int line, uint64_t baseAddr, uint64_t symAddr, const Worker& worker, const View& view );
    void Render( const Worker& worker, View& view );

    void CalcInlineStats( bool val ) { m_calcInlineStats = val; }
    bool IsSymbolView() const { return !m_asm.empty(); }

private:
    void ParseSource( const char* fileName, const Worker& worker, const View& view );
    bool Disassemble( uint64_t symAddr, const Worker& worker );

    void SelectViewMode();

    void RenderSimpleSourceView();
    void RenderSymbolView( const Worker& worker, View& view );

    void RenderSymbolSourceView( uint32_t iptotal, unordered_flat_map<uint64_t, uint32_t> ipcount, unordered_flat_map<uint64_t, uint32_t> ipcountAsm, uint32_t ipmax, const Worker& worker, const View& view );
    uint64_t RenderSymbolAsmView( uint32_t iptotal, unordered_flat_map<uint64_t, uint32_t> ipcount, uint32_t ipmax, const Worker& worker, View& view );

    void RenderLine( const Line& line, int lineNum, uint32_t ipcnt, uint32_t iptotal, uint32_t ipmax, const Worker* worker );
    void RenderAsmLine( AsmLine& line, uint32_t ipcnt, uint32_t iptotal, uint32_t ipmax, const Worker& worker, uint64_t& jumpOut, int maxAddrLen, View& view );

    void SelectLine( uint32_t line, const Worker* worker, bool changeAsmLine = true, uint64_t targetAddr = 0 );
    void SelectAsmLines( uint32_t file, uint32_t line, const Worker& worker, bool changeAsmLine = true, uint64_t targetAddr = 0 );
    void SelectAsmLinesHover( uint32_t file, uint32_t line, const Worker& worker );

    void GatherIpStats( uint64_t addr, uint32_t& iptotalSrc, uint32_t& iptotalAsm, unordered_flat_map<uint64_t, uint32_t>& ipcountSrc, unordered_flat_map<uint64_t, uint32_t>& ipcountAsm, uint32_t& ipmaxSrc, uint32_t& ipmaxAsm, const Worker& worker, bool limitView, const View& view );
    uint32_t CountAsmIpStats( uint64_t addr, const Worker& worker, bool limitView, const View& view );

    void SelectMicroArchitecture( const char* moniker );

    TokenColor IdentifyToken( const char*& begin, const char* end );
    std::vector<Token> Tokenize( const char* begin, const char* end );

    void ResetAsm();
    void FollowRead( size_t line, RegsX86 reg, size_t limit );
    void FollowWrite( size_t line, RegsX86 reg, size_t limit );
    void CheckRead( size_t line, RegsX86 reg, size_t limit );
    void CheckWrite( size_t line, RegsX86 reg, size_t limit );

#ifndef TRACY_NO_FILESELECTOR
    void Save( const Worker& worker, size_t start = 0, size_t stop = std::numeric_limits<size_t>::max() );
#endif

    struct TokenizerState
    {
        void Reset()
        {
            isInComment = false;
            isInPreprocessor = false;
        }

        bool isInComment;
        bool isInPreprocessor;
    };

    ImFont* m_font;
    const char* m_file;
    uint32_t m_fileStringIdx;
    uint64_t m_symAddr;
    uint64_t m_baseAddr;
    uint64_t m_targetAddr;
    const char* m_data;
    char* m_dataBuf;
    size_t m_dataSize;
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
    bool m_atnt;
    uint64_t m_jumpPopupAddr;

    std::vector<Line> m_lines;
    std::vector<AsmLine> m_asm;

    unordered_flat_map<uint64_t, uint32_t> m_locMap;
    unordered_flat_map<uint64_t, JumpData> m_jumpTable;
    unordered_flat_set<uint64_t> m_jumpOut;
    size_t m_maxJumpLevel;
    bool m_showJumps;

    unordered_flat_map<uint32_t, uint32_t> m_sourceFiles;
    unordered_flat_set<uint64_t> m_selectedAddresses;
    unordered_flat_set<uint64_t> m_selectedAddressesHover;

    uint32_t m_maxLine;
    int m_maxMnemonicLen;

    TokenizerState m_tokenizer;

    unordered_flat_map<const char*, int, charutil::Hasher, charutil::Comparator> m_microArchOpMap;
    CpuArchitecture m_cpuArch;
    int m_selMicroArch;
    int m_idxMicroArch, m_profileMicroArch;
    bool m_showLatency;

    unordered_flat_set<uint32_t> m_asmSampleSelect;
    unordered_flat_set<uint32_t> m_srcSampleSelect;
    int32_t m_asmGroupSelect = -1;
    int32_t m_srcGroupSelect = -1;

    float m_srcWidth;
    float m_asmWidth;

    GetWindowCallback m_gwcb;
};

}

#endif
