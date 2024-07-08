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

    for( auto& v : m_map )
    {
        auto& it = v.second.item;
        if( it->doneTime > 0 )
        {
            auto c = it->items;
            if( c )
            {
                while( *c )
                {
                    if( (*c)->unlockTime == 0 ) (*c)->unlockTime = it->doneTime;
                    c++;
                }
            }
            c = it->unlocks;
            if( c )
            {
                while( *c )
                {
                    if( (*c)->unlockTime == 0 ) (*c)->unlockTime = it->doneTime;
                    c++;
                }
            }
        }
    }

    for( auto& v : m_map )
    {
        if( v.second.category->unlockTime == 0 && v.second.item->unlockTime > 0 )
        {
            v.second.category->unlockTime = v.second.item->unlockTime;
        }
    }

    auto c = data::AchievementCategories;
    while( *c )
    {
        if( (*c)->unlockTime > 0 )
        {
            auto items = (*c)->items;
            while( *items )
            {
                if( (*items)->unlockTime == 0 ) (*items)->unlockTime = (*c)->unlockTime;
                items++;
            }
        }
        c++;
    }

    ini_free( ini );
}

AchievementsMgr::~AchievementsMgr()
{
    Save();
}

void AchievementsMgr::Achieve( const char* id )
{
    auto it = m_map.find( id );
    assert( it != m_map.end() );
    auto& a = *it->second.item;

    if( a.unlockTime == 0 ) return;
    if( a.doneTime > 0 ) return;

    const auto t = uint64_t( time( nullptr ) );

    a.doneTime = uint64_t( t );
    m_queue.push_back( &a );

    auto c = a.items;
    if( c )
    {
        while( *c ) (*c++)->unlockTime = t;
    }
    c = a.unlocks;
    if( c )
    {
        while( *c )
        {
            (*c)->unlockTime = t;
            auto cit = m_map.find( (*c)->id );
            if( cit->second.category->unlockTime == 0 ) cit->second.category->unlockTime = t;
            c++;
        }
    }

    Save();
}

data::AchievementCategory** AchievementsMgr::GetCategories() const
{
    return data::AchievementCategories;
}

data::AchievementCategory* AchievementsMgr::GetCategoryForAchievement( const char* id ) const
{
    auto it = m_map.find( id );
    assert( it != m_map.end() );
    return it->second.category;
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

bool AchievementsMgr::CategoryNeedsAttention( const char* id ) const
{
    auto c = data::AchievementCategories;
    while( *c )
    {
        if( strcmp( (*c)->id, id ) == 0 )
        {
            for( auto& v : m_map )
            {
                if( v.second.category == (*c) )
                {
                    auto& it = v.second.item;
                    if( it->unlockTime > 0 && !it->hideNew ) return true;
                    if( it->doneTime > 0 && !it->hideCompleted ) return true;
                }
            }
            return false;
        }
        c++;
    }
    assert( false );
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

void AchievementsMgr::Save()
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

}
