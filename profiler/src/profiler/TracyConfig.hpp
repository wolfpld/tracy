#ifndef __TRACYCONFIG_HPP__
#define __TRACYCONFIG_HPP__

namespace tracy
{

struct Config
{
    bool threadedRendering = true;
    int targetFps = 60;
};

}

#endif
