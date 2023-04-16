#ifndef __TRACYSTRINGDISCOVERY_HPP__
#define __TRACYSTRINGDISCOVERY_HPP__

#include "../public/common/TracyForceInline.hpp"
#include "tracy_robin_hood.h"
#include "TracyCharUtil.hpp"
#include "TracyEvent.hpp"
#include "TracyVector.hpp"

namespace tracy
{

template<typename T>
class StringDiscovery
{
public:
    tracy_force_inline Vector<T>& Data() { return m_data; }
    tracy_force_inline const Vector<T>& Data() const { return m_data; }

    tracy_force_inline bool IsPending() const { return !m_pending.empty(); }

    // Merge( destination, postponed )
    template<typename U>
    tracy_force_inline void StringDiscovered( uint64_t name, const StringLocation& sl, U& stringMap, std::function<void(T,T)> Merge )
    {
        auto pit = m_pending.find( name );
        assert( pit != m_pending.end() );

        auto it = m_rev.find( sl.ptr );
        if( it == m_rev.end() )
        {
            m_map.emplace( name, pit->second );
            m_rev.emplace( sl.ptr, pit->second );
            m_data.push_back( pit->second );
            stringMap.emplace( name, sl.ptr );
        }
        else
        {
            auto item = it->second;
            m_map.emplace( name, item );
            Merge( item, pit->second );
        }

        m_pending.erase( pit );
    }

    tracy_force_inline T Retrieve( uint64_t name, const std::function<T(uint64_t)>& Create, const std::function<void(uint64_t)>& Query )
    {
        auto it = m_map.find( name );
        if( it == m_map.end() )
        {
            auto pit = m_pending.find( name );
            if( pit == m_pending.end() )
            {
                T item = Create( name );
                m_pending.emplace( name, item );
                Query( name );
                return item;
            }
            else
            {
                return pit->second;
            }
        }
        else
        {
            return it->second;
        }
    }

    tracy_force_inline void AddExternal( const T& val )
    {
        m_data.push_back( val );
    }

private:
    Vector<T> m_data;
    unordered_flat_map<uint64_t, T> m_pending;
    unordered_flat_map<uint64_t, T> m_map;
    unordered_flat_map<const char*, T, charutil::Hasher, charutil::Comparator> m_rev;
};

}

#endif
