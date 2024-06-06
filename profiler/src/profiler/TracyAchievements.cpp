#include <assert.h>

#include "TracyAchievements.hpp"

namespace tracy
{

AchievementsMgr::AchievementsMgr()
{
    m_queue.emplace_back( "Discover achievements!" );
    m_queue.emplace_back( "Achievements are fun!" );
    m_queue.emplace_back( "The new beginnings are always the best!" );
}

const std::string* AchievementsMgr::GetNextQueue()
{
    if( m_queue.empty() ) return nullptr;
    return &m_queue.front();
}

void AchievementsMgr::PopQueue()
{
    assert( !m_queue.empty() );
    m_queue.erase( m_queue.begin() );
}

bool AchievementsMgr::NeedsUpdates() const
{
    return false;
}

}
