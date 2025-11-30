#ifndef __TRACYMANUALDATA_HPP__
#define __TRACYMANUALDATA_HPP__

#include <stdint.h>
#include <string>
#include <string_view>
#include <vector>

namespace tracy
{

class TracyManualData
{
public:
    struct ManualChunk
    {
        std::string text;
        std::string section;
        std::string title;
        std::string parents;
        std::string link;
        int level;
    };

    TracyManualData();

    [[nodiscard]] const std::vector<ManualChunk>& GetChunks() const { return m_manualChunks; }
    [[nodiscard]] uint64_t GetHash() const { return m_hash; }

private:
    void AddManualChunk( const std::string_view& manual, int manualChunkPos, int pos, const std::vector<int>& levels, const std::vector<std::string>& chapterNames );

    std::vector<ManualChunk> m_manualChunks;
    uint64_t m_hash;
};

}

#endif
