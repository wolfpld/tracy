#ifndef __TRACYSOURCEVIEW_HPP__
#define __TRACYSOURCEVIEW_HPP__

#include <string>
#include <vector>

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

public:
    SourceView( ImFont* font );
    ~SourceView();

    void Open( const char* fileName, int line, uint64_t baseAddr, uint64_t symAddr, const Worker& worker );
    void Render( const Worker& worker );

private:
    void RenderLine( const Line& line, int lineNum, uint32_t ipcnt, uint32_t iptotal );
    void RenderAsmLine( const AsmLine& line, uint32_t ipcnt, uint32_t iptotal, const Worker& worker, uint64_t& jumpOut );

    bool Disassemble( uint64_t symAddr, const Worker& worker );

    ImFont* m_font;
    const char* m_file;
    uint32_t m_fileStringIdx;
    uint64_t m_symAddr;
    uint64_t m_currentAddr;
    uint64_t m_baseAddr;
    uint64_t m_targetAddr;
    char* m_data;
    size_t m_dataSize;
    int m_targetLine;
    int m_selectedLine;
    bool m_showAsm;
    uint32_t m_codeLen;
    DecayValue<uint64_t> m_highlightAddr;
    bool m_asmRelative;
    bool m_asmShowSourceLocation;

    std::vector<Line> m_lines;
    std::vector<AsmLine> m_asm;
};

}

#endif
