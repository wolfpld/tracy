#include "TracyContext.hpp"

namespace tracy
{

const ThreadData* ZoneContext::GetThreadData( uint64_t tid ) const
{
    auto it = threadData.find( tid );
    if( it == threadData.end() ) return nullptr;
    return it->second;
}

#ifndef TRACY_NO_STATISTICS
ZoneContext::SourceLocationZones& ZoneContext::GetZonesForSourceLocation( int16_t srcloc )
{
    assert( AreSourceLocationZonesReady() );
    static SourceLocationZones empty;
    auto it = sourceLocationZones.find( srcloc );
    return it != sourceLocationZones.end() ? it->second : empty;
}

const ZoneContext::SourceLocationZones& ZoneContext::GetZonesForSourceLocation( int16_t srcloc ) const
{
    assert( AreSourceLocationZonesReady() );
    static const SourceLocationZones empty;
    auto it = sourceLocationZones.find( srcloc );
    return it != sourceLocationZones.end() ? it->second : empty;
}

ZoneContext::SourceLocationZones* ZoneContext::GetSourceLocationZonesReal( uint16_t srcloc )
{
    auto it = sourceLocationZones.find( srcloc );
    assert( it != sourceLocationZones.end() );
    srclocZonesLast.first = srcloc;
    srclocZonesLast.second = &it->second;
    return &it->second;
}

void ZoneContext::InitSourceLocationZones( uint16_t srcloc )
{
    auto res = sourceLocationZones.emplace( srcloc, SourceLocationZones() );
    srclocZonesLast.first = srcloc;
    srclocZonesLast.second = &res.first->second;
}

#else
uint64_t* ZoneContext::GetSourceLocationZonesCntReal( uint16_t srcloc )
{
    auto it = sourceLocationZonesCnt.find( srcloc );
    assert( it != sourceLocationZonesCnt.end() );
    srclocCntLast.first = srcloc;
    srclocCntLast.second = &it->second;
    return &it->second;
}

void InitSourceLocationZonesCnt( uint16_t srcloc )
{
    auto res = sourceLocationZonesCnt.emplace( srcloc, 0 );
    srclocCntLast.first = srcloc;
    srclocCntLast.second = &res.first->second;
}

#endif

} // namespace tracy
