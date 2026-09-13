#ifndef __TRACYCONFIG_HPP__
#define __TRACYCONFIG_HPP__

#include <string>

#include "TracyUtility.hpp"

namespace tracy
{

inline constexpr float s_zoomPresets[] = {
    1.f/2, 1.f/1.75f, 1.f/1.5f, 1.f/1.25f, 1.f, 1.25f, 1.5f, 1.75f, 2.f, 2.25f, 2.5f, 2.75f, 3.f
};
constexpr int s_zoomPresetCount = sizeof( s_zoomPresets ) / sizeof( *s_zoomPresets );
constexpr int s_zoomPreset100 = 4;

struct Config
{
    bool threadedRendering = true;
    bool focusLostLimit = true;
    int targetFps = 60;
    bool drawFrameTargets = false;
    double horizontalScrollMultiplier = 1.0;
    double verticalScrollMultiplier = 1.0;
    bool memoryLimit = false;
    int memoryLimitPercent = 80;
    bool achievements = false;
    bool achievementsAsked = false;
    int dynamicColors = 1;
    bool forceColors = false;
    bool ghostZones = true;
    int shortenName = (int)ShortenName::NoSpaceAndNormalize;
    bool drawSamples = true;
    bool drawContextSwitches = true;
    int plotHeight = 100;
    bool saveUserScale = false;
    int zoomLevel = s_zoomPreset100;

    // LLM assistant settings
#ifdef __EMSCRIPTEN__
    bool llm = false;
#else
    bool llm = true;
#endif
    std::string llmAddress = "http://localhost:8080";
    std::string llmModel;
    std::string llmFastModel;
    std::string llmEmbeddingsModel;
    std::string llmUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";
    std::string llmSearchIdentifier;
    std::string llmSearchApiKey;
    std::string llmSearchBraveApiKey;
    bool llmSeparateFastModel = false;
    bool llmAnnotateCallstacks = false;
    bool llmLimitToolReplySize = false;
    int llmMaxToolReplySizeValue = 48*1024;
    bool llmSummary = true;
    bool llmSuggestion = true;
    int llmPersonality = 0;
};

extern Config s_config;

void LoadConfig();
bool SaveConfig();

}

#endif
