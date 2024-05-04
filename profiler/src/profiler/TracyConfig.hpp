#ifndef __TRACYCONFIG_HPP__
#define __TRACYCONFIG_HPP__

namespace tracy
{

struct Config
{
    bool threadedRendering = true;
    bool focusLostLimit = true;
    int targetFps = 60;
    bool memoryLimit = false;
    int memoryLimitPercent = 80;
};

}

#endif
