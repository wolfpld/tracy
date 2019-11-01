#ifndef __TRACYVIEWDATA_HPP__
#define __TRACYVIEWDATA_HPP__

#include <stdint.h>

namespace tracy
{

struct ViewData
{
    int64_t zvStart = 0;
    int64_t zvEnd = 0;
    int32_t zvHeight = 0;
    int32_t zvScroll = 0;
    int32_t frameScale = 0;
    int32_t frameStart = 0;

    uint8_t drawGpuZones = true;
    uint8_t drawZones = true;
    uint8_t drawLocks = true;
    uint8_t drawPlots = true;
    uint8_t onlyContendedLocks = true;
    uint8_t drawEmptyLabels = false;
    uint8_t drawContextSwitches = true;
    uint8_t darkenContextSwitches = true;
    uint8_t drawCpuData = true;
    uint8_t drawCpuUsageGraph = true;
    uint8_t dynamicColors = 1;
};

struct Annotation
{
    std::string text;
    int64_t start;
    int64_t end;
    uint32_t color;
};

}

#endif
