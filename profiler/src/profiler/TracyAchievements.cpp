#include <assert.h>
#include <inttypes.h>
#include <time.h>

#include "../ini.h"

#include "TracyAchievements.hpp"
#include "TracyStorage.hpp"

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

    const auto fn = tracy::GetSavePath( "achievements.ini" );
    auto ini = ini_load( fn );
    if( !ini ) return;

    for( auto& v : m_map )
    {
        uint64_t unlockTime, doneTime;
        int hideCompleted, hideNew;

        if( ini_sget( ini, v.first, "unlockTime", "%" PRIu64, &unlockTime ) &&
            ini_sget( ini, v.first, "doneTime", "%" PRIu64, &doneTime ) &&
            ini_sget( ini, v.first, "hideCompleted", "%d", &hideCompleted ) &&
            ini_sget( ini, v.first, "hideNew", "%d", &hideNew ) )
        {
            auto& it = v.second.item;
            it->unlockTime = unlockTime;
            it->doneTime = doneTime;
            it->hideCompleted = hideCompleted != 0;
            it->hideNew = hideNew != 0;
        }
    }

    ini_free( ini );
}

AchievementsMgr::~AchievementsMgr()
{
    const auto fn = tracy::GetSavePath( "achievements.ini" );
    FILE* f = fopen( fn, "wb" );
    if( !f ) return;

    for( auto& v : m_map )
    {
        auto& it = v.second.item;
        fprintf( f, "[%s]\n", it->id );
        fprintf( f, "unlockTime=%" PRIu64 "\n", it->unlockTime );
        fprintf( f, "doneTime=%" PRIu64 "\n", it->doneTime );
        fprintf( f, "hideCompleted=%d\n", it->hideCompleted ? 1 : 0 );
        fprintf( f, "hideNew=%d\n\n", it->hideNew ? 1 : 0 );
    }

    fclose( f );
}

void AchievementsMgr::Achieve( const char* id )
{
    auto it = m_map.find( id );
    assert( it != m_map.end() );
    if( it->second.item->unlockTime == 0 ) return;
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

bool AchievementsMgr::NeedsAttention() const
{
    for( auto& v : m_map )
    {
        auto& it = v.second.item;
        if( it->unlockTime > 0 && !it->hideNew ) return true;
        if( it->doneTime > 0 && !it->hideCompleted ) return true;
    }
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
