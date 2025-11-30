#include "TracyEmbed.hpp"
#include "TracyManualData.hpp"

#define XXH_INLINE_ALL
#include "tracy_xxhash.h"

#include "data/Manual.hpp"

namespace tracy
{

TracyManualData::TracyManualData()
{
    auto data = Unembed( Manual );
    m_hash = XXH3_64bits( data->data(), data->size() );

    std::string_view manual( data->data(), data->size() );
    const auto sz = (int)data->size();

    std::vector<int> levels = { 0 };
    std::vector<std::string> chapterNames = { "Title Page" };

    int manualChunkPos = 0;
    int pos = 0;
    while( pos < sz )
    {
        std::string::size_type next = pos;
        for(;;)
        {
            next = manual.find( '\n', next );
            if( next == std::string_view::npos )
            {
                next = sz;
                break;
            }
            if( next+1 >= sz || manual[next+1] == '\n' ) break;
            next++;
        }
        if( next != pos )
        {
            std::string_view line( manual.data() + pos, next - pos );
            if( line[0] == '#' )
            {
                if( manualChunkPos != pos )
                {
                    AddManualChunk( manual, manualChunkPos, pos, levels, chapterNames );
                    manualChunkPos = pos;
                }

                int level = 1;
                if( line.find( ".unnumbered}" ) == std::string_view::npos )
                {
                    while( level < line.size() && line[level] == '#' ) level++;
                    if( level != levels.size() )
                    {
                        levels.resize( level, 0 );
                        chapterNames.resize( level );
                    }
                    levels[level - 1]++;
                }

                chapterNames[level - 1] = line.substr( level + 1 );
            }
        }
        pos = next + 1;
        while( pos < sz && manual[pos] == '\n' ) pos++;
    }
    if( manualChunkPos != pos )
    {
        AddManualChunk( manual, manualChunkPos, pos, levels, chapterNames );
    }
}

void TracyManualData::AddManualChunk( const std::string_view& manual, int start, int end, const std::vector<int>& levels, const std::vector<std::string>& chapterNames )
{
    while( manual[start] != '\n' ) start++;
    while( manual[start] == '\n' ) start++;
    while( manual[end-1] == '\n' ) end--;

    if( end > start )
    {
        std::string text, section, title, parents;
        text = std::string( manual.data() + start, end - start );
        if( levels[0] != 0 )
        {
            section = std::to_string( levels[0] );
            for( size_t i=1; i<levels.size(); i++ ) section += "." + std::to_string( levels[i] );
        }
        if( levels.size() == 1 )
        {
            title = chapterNames[0];
        }
        else
        {
            title = chapterNames[levels.size()-1];
            parents = chapterNames[0];
            for( size_t i=1; i<levels.size() - 1; i++ ) parents += " > " + chapterNames[i];
        }
        std::string link;
        auto linkpos = title.find( '{' );
        if( linkpos != std::string::npos )
        {
            link = title.substr( linkpos + 1, title.size() - linkpos - 2 );
            title = title.substr( 0, linkpos - 1 );
            if( link.ends_with( ".unnumbered" ) ) link = link.substr( 0, link.size() - 12 );
        }
        m_manualChunks.emplace_back( ManualChunk {
            .text = std::move( text ),
            .section = std::move( section ),
            .title = std::move( title ),
            .parents = std::move( parents ),
            .link = std::move( link ),
            .level = (int)levels.size() - 1
        } );
    }
}

}
