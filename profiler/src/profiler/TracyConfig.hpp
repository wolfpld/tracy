#ifndef __TRACYCONFIG_HPP__
#define __TRACYCONFIG_HPP__

#include <string>

#include "TracyUtility.hpp"

namespace tracy
{

struct Config
{
    bool threadedRendering = true;
    bool focusLostLimit = true;
    int targetFps = 60;
    double horizontalScrollMultiplier = 1.0;
    double verticalScrollMultiplier = 1.0;
    bool memoryLimit = false;
    int memoryLimitPercent = 80;
    bool achievements = false;
    bool achievementsAsked = false;
    int dynamicColors = 1;
    bool forceColors = false;
    int shortenName = (int)ShortenName::NoSpaceAndNormalize;
    bool saveUserScale = false;
    float userScale = 1.0f;
#ifdef __EMSCRIPTEN__
    bool llm = false;
#else
    bool llm = true;
#endif
    std::string llmAddress = "http://localhost:11434";
    std::string llmModel;
    std::string llmEmbeddingsModel;
    std::string llmUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";
    std::string llmSearchIdentifier;
    std::string llmSearchApiKey;
    bool symbolsAttemptResolutionByServer = false;
    bool symbolsPreventResolutionByClient = false;
};

extern Config s_config;

void LoadConfig();
bool SaveConfig();

}

#endif
