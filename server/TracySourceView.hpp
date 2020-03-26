#include <string>
#include <vector>

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
        std::string mnemonic;
        std::string operands;
    };

public:
    SourceView( ImFont* font );
    ~SourceView();

    void Open( const char* fileName, int line, uint64_t symAddr, const Worker& worker );
    void Render( const Worker& worker );

private:
    void RenderLine( const Line& line, int lineNum, uint32_t ipcnt, uint32_t iptotal );
    void RenderAsmLine( const AsmLine& line, uint32_t ipcnt, uint32_t iptotal );

    bool Disassemble( uint64_t symAddr, const Worker& worker );

    ImFont* m_font;
    const char* m_file;
    uint64_t m_symAddr;
    uint64_t m_targetAddr;
    char* m_data;
    size_t m_dataSize;
    int m_targetLine;
    int m_selectedLine;
    bool m_showAsm;
    uint32_t m_codeLen;

    std::vector<Line> m_lines;
    std::vector<AsmLine> m_asm;
};

}
