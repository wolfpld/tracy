#include <assert.h>
#include <time.h>

#include "TracyAchievements.hpp"

namespace tracy
{

namespace data { extern AchievementCategory* AchievementCategories[]; }

AchievementsMgr::AchievementsMgr()
{
    auto cat = data::AchievementCategories;
    while( *cat )
    {
        FillMap( (*cat)->items, *cat );
        cat++;
    }
}

void AchievementsMgr::Achieve( const char* id )
{
    auto it = m_map.find( id );
    assert( it != m_map.end() );
    if( it->second.item->doneTime > 0 ) return;

    const auto t = uint64_t( time( nullptr ) );

    it->second.item->doneTime = uint64_t( t );
    m_queue.push_back( it->second.item );

    auto c = it->second.item->items;
    if( c )
    {
        while( *c ) (*c++)->unlockTime = t;
    }
}

data::AchievementCategory** AchievementsMgr::GetCategories() const
{
    return data::AchievementCategories;
}

data::AchievementItem* AchievementsMgr::GetNextQueue()
{
    if( m_queue.empty() ) return nullptr;
    return m_queue.front();
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

void AchievementsMgr::FillMap( data::AchievementItem** items, data::AchievementCategory* category )
{
    while( *items )
    {
        m_map.emplace( (*items)->id, AchievementPair { *items, category } );
        if( (*items)->items) FillMap( (*items)->items, category );
        items++;
    }
}

}
