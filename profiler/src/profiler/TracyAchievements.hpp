#ifndef __TRACYACHIEVEMENTS_HPP__
#define __TRACYACHIEVEMENTS_HPP__

#include <string>
#include <vector>

namespace tracy
{

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
