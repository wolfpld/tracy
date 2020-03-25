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

public:
    SourceView( ImFont* font );
    ~SourceView();

    void Open( const char* fileName, int line, uint64_t symAddr );
    void Render( const Worker& worker );

private:
    void RenderLine( const Line& line, int lineNum, uint32_t ipcnt, uint32_t iptotal );

    ImFont* m_font;
    const char* m_file;
    uint64_t m_symAddr;
    char* m_data;
    size_t m_dataSize;
    int m_targetLine;
    int m_selectedLine;

    std::vector<Line> m_lines;
};

}
