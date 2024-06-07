#ifndef __TRACYACHIEVEMENTS_HPP__
#define __TRACYACHIEVEMENTS_HPP__

#include <stdint.h>
#include <string>
#include <vector>

#include "imgui.h"

#include "TracyCharUtil.hpp"
#include "tracy_robin_hood.h"

namespace tracy
{

namespace data
{

struct ctx
{
    ImFont* big;
    ImFont* small;
    ImFont* fixed;
};

struct AchievementItem
{
    const char* id;
    const char* name;
    void(*description)(const ctx&);
    AchievementItem** items;
    bool keepOpen;
    uint64_t unlockTime;
    uint64_t doneTime;
    bool hideCompleted;
    bool hideNew;
};

struct AchievementCategory
{
    const char* id;
    const char* name;
    AchievementItem** items;
    uint64_t unlockTime;
};

}

class AchievementsMgr
{
    struct AchievementPair
    {
        data::AchievementItem* item;
        data::AchievementCategory* category;
    };

public:
    AchievementsMgr();

    void Achieve( const char* id );
    data::AchievementCategory** GetCategories() const;

    data::AchievementItem* GetNextQueue();
    void PopQueue();

    bool NeedsUpdates() const;

private:
    void FillMap( data::AchievementItem** items, data::AchievementCategory* category );

    std::vector<data::AchievementItem*> m_queue;
    tracy::unordered_flat_map<const char*, AchievementPair, charutil::Hasher, charutil::Comparator> m_map;
};

}

#endif
