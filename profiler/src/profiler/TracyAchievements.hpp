#ifndef __TRACYACHIEVEMENTS_HPP__
#define __TRACYACHIEVEMENTS_HPP__

#include <stdint.h>
#include <string>
#include <vector>

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
public:
    AchievementsMgr();

    const std::string* GetNextQueue();
    void PopQueue();

    bool NeedsUpdates() const;

private:
    std::vector<std::string> m_queue;
};

}

#endif
