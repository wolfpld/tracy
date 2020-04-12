#ifndef __TRACYSOURCEVIEW_HPP__
#define __TRACYSOURCEVIEW_HPP__

#include <string>
#include <vector>

#include "tracy_robin_hood.h"
#include "TracyDecayValue.hpp"

struct ImFont;

namespace tracy
{

class Worker;

class SourceView
{
    struct Line
    {
        const char* begin;
        const char* end;
    };

    struct AsmLine
    {
        uint64_t addr;
        uint64_t jumpAddr;
        std::string mnemonic;
        std::string operands;
    };

    struct JumpData
    {
        uint64_t min;
        uint64_t max;
        int level;
        std::vector<uint64_t> source;
    };

    enum
    {
        DisplaySource,
        DisplayAsm,
        DisplayMixed
    };

public:
    SourceView( ImFont* font );
    ~SourceView();

    void OpenSource( const char* fileName, int line );
    void OpenSymbol( const char* fileName, int line, uint64_t baseAddr, uint64_t symAddr, const Worker& worker );
    void Render( const Worker& worker );

    void CalcInlineStats( bool val ) { m_calcInlineStats = val; }

private:
    void ParseSource( const char* fileName, const Worker* worker );
    bool Disassemble( uint64_t symAddr, const Worker& worker );

    void RenderSimpleSourceView();
    void RenderSymbolView( const Worker& worker );

    void RenderSymbolSourceView( uint32_t iptotal, unordered_flat_map<uint64_t, uint32_t> ipcount, unordered_flat_map<uint64_t, uint32_t> ipcountAsm, uint32_t ipmax, const Worker& worker );
    uint64_t RenderSymbolAsmView( uint32_t iptotal, unordered_flat_map<uint64_t, uint32_t> ipcount, uint32_t ipmax, const Worker& worker );

    void RenderLine( const Line& line, int lineNum, uint32_t ipcnt, uint32_t iptotal, uint32_t ipmax, const Worker* worker );
    void RenderAsmLine( const AsmLine& line, uint32_t ipcnt, uint32_t iptotal, uint32_t ipmax, const Worker& worker, uint64_t& jumpOut, int maxAddrLen );

    void SelectLine( uint32_t line, const Worker* worker, bool changeAsmLine = true, uint64_t targetAddr = 0 );
    void SelectAsmLines( uint32_t file, uint32_t line, const Worker& worker, bool changeAsmLine = true, uint64_t targetAddr = 0 );
    void SelectAsmLinesHover( uint32_t file, uint32_t line, const Worker& worker );

    void GatherIpStats( uint64_t addr, uint32_t& iptotalSrc, uint32_t& iptotalAsm, unordered_flat_map<uint64_t, uint32_t>& ipcountSrc, unordered_flat_map<uint64_t, uint32_t>& ipcountAsm, uint32_t& ipmaxSrc, uint32_t& ipmaxAsm, const Worker& worker );

    ImFont* m_font;
    const char* m_file;
    uint32_t m_fileStringIdx;
    uint64_t m_symAddr;
    uint64_t m_baseAddr;
    uint64_t m_targetAddr;
    char* m_data;
    size_t m_dataSize;
    int m_targetLine;
    int m_selectedLine;
    DecayValue<int> m_hoveredLine;
    DecayValue<uint32_t> m_hoveredSource;
    int m_displayMode;
    uint32_t m_codeLen;
    DecayValue<uint64_t> m_highlightAddr;
    bool m_asmRelative;
    bool m_asmShowSourceLocation;
    bool m_calcInlineStats;

    std::vector<Line> m_lines;
    std::vector<AsmLine> m_asm;

    unordered_flat_map<uint64_t, JumpData> m_jumpTable;
    unordered_flat_set<uint64_t> m_jumpOut;
    int m_maxJumpLevel;
    bool m_showJumps;

    unordered_flat_map<uint32_t, uint32_t> m_sourceFiles;
    unordered_flat_set<uint64_t> m_selectedAddresses;
    unordered_flat_set<uint64_t> m_selectedAddressesHover;

    uint32_t m_maxLine;
    int m_maxMnemonicLen;
};

}

#endif
