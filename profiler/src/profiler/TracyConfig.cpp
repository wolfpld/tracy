#include <stdio.h>

#include "TracyConfig.hpp"
#include "TracyStorage.hpp"

#include "../ini.h"

namespace tracy
{

Config s_config;

void LoadConfig()
{
    const auto fn = tracy::GetSavePath( "tracy.ini" );
    auto ini = ini_load( fn );
    if( !ini ) return;

    int v;
    double v1;
    const char* v2;

    if( ini_sget( ini, "core", "threadedRendering", "%d", &v ) ) s_config.threadedRendering = v;
    if( ini_sget( ini, "core", "focusLostLimit", "%d", &v ) ) s_config.focusLostLimit = v;
    if( ini_sget( ini, "timeline", "targetFps", "%d", &v ) && v >= 1 && v < 10000 ) s_config.targetFps = v;
    if( ini_sget( ini, "timeline", "dynamicColors", "%d", &v ) ) s_config.dynamicColors = v;
    if( ini_sget( ini, "timeline", "forceColors", "%d", &v ) ) s_config.forceColors = v;
    if( ini_sget( ini, "timeline", "shortenName", "%d", &v ) ) s_config.shortenName = v;
    if( ini_sget( ini, "timeline", "horizontalScrollMultiplier", "%lf", &v1 ) && v1 > 0.0 ) s_config.horizontalScrollMultiplier = v1;
    if( ini_sget( ini, "timeline", "verticalScrollMultiplier", "%lf", &v1 ) && v1 > 0.0 ) s_config.verticalScrollMultiplier = v1;
    if( ini_sget( ini, "memory", "limit", "%d", &v ) ) s_config.memoryLimit = v;
    if( ini_sget( ini, "memory", "percent", "%d", &v ) && v >= 1 && v < 1000 ) s_config.memoryLimitPercent = v;
    if( ini_sget( ini, "achievements", "enabled", "%d", &v ) ) s_config.achievements = v;
    if( ini_sget( ini, "achievements", "asked", "%d", &v ) ) s_config.achievementsAsked = v;
    if( ini_sget( ini, "ui", "saveUserScale", "%d", &v ) ) s_config.saveUserScale = v;
    if( ini_sget( ini, "ui", "userScale", "%lf", &v1 ) && v1 > 0.0 && s_config.saveUserScale ) s_config.userScale = v1;
    if( ini_sget( ini, "llm", "enabled", "%d", &v ) ) s_config.llm = v;
    if( v2 = ini_get( ini, "llm", "address" ); v2 ) s_config.llmAddress = v2;
    if( v2 = ini_get( ini, "llm", "model" ); v2 ) s_config.llmModel = v2;
    if( v2 = ini_get( ini, "llm", "embeddings" ); v2 ) s_config.llmEmbeddingsModel = v2;
    if( v2 = ini_get( ini, "llm", "useragent" ); v2 ) s_config.llmUserAgent = v2;
    if( v2 = ini_get( ini, "llm", "searchIdentifier" ); v2 ) s_config.llmSearchIdentifier = v2;
    if( v2 = ini_get( ini, "llm", "searchApiKey" ); v2 ) s_config.llmSearchApiKey = v2;
    if (ini_sget(ini, "symbols", "attemptResolutionByServer", "%d", &v)) s_config.symbolsAttemptResolutionByServer = (bool)v;
    if (ini_sget(ini, "symbols", "preventResolutionByClient", "%d", &v)) s_config.symbolsPreventResolutionByClient = (bool)v;

    ini_free( ini );
}

bool SaveConfig()
{
    const auto fn = tracy::GetSavePath( "tracy.ini" );
    FILE* f = fopen( fn, "wb" );
    if( !f ) return false;

    fprintf( f, "[core]\n" );
    fprintf( f, "threadedRendering = %i\n", (int)s_config.threadedRendering );
    fprintf( f, "focusLostLimit = %i\n", (int)s_config.focusLostLimit );

    fprintf( f, "\n[timeline]\n" );
    fprintf( f, "targetFps = %i\n", s_config.targetFps );
    fprintf( f, "dynamicColors = %i\n", s_config.dynamicColors );
    fprintf( f, "forceColors = %i\n", (int)s_config.forceColors );
    fprintf( f, "shortenName = %i\n", s_config.shortenName );
    fprintf( f, "horizontalScrollMultiplier = %lf\n", s_config.horizontalScrollMultiplier );
    fprintf( f, "verticalScrollMultiplier = %lf\n", s_config.verticalScrollMultiplier );

    fprintf( f, "\n[memory]\n" );
    fprintf( f, "limit = %i\n", (int)s_config.memoryLimit );
    fprintf( f, "percent = %i\n", s_config.memoryLimitPercent );

    fprintf( f, "\n[achievements]\n" );
    fprintf( f, "enabled = %i\n", (int)s_config.achievements );
    fprintf( f, "asked = %i\n", (int)s_config.achievementsAsked );

    fprintf( f, "\n[ui]\n" );
    fprintf( f, "saveUserScale = %i\n", (int)s_config.saveUserScale );
    fprintf( f, "userScale = %lf\n", s_config.userScale );

    fprintf( f, "\n[llm]\n" );
    fprintf( f, "enabled = %i\n", (int)s_config.llm );
    fprintf( f, "address = %s\n", s_config.llmAddress.c_str() );
    fprintf( f, "model = %s\n", s_config.llmModel.c_str() );
    fprintf( f, "embeddings = %s\n", s_config.llmEmbeddingsModel.c_str() );
    fprintf( f, "useragent = %s\n", s_config.llmUserAgent.c_str() );
    fprintf( f, "searchIdentifier = %s\n", s_config.llmSearchIdentifier.c_str() );
    fprintf( f, "searchApiKey = %s\n", s_config.llmSearchApiKey.c_str() );

    fprintf( f, "\n[symbols]\n" );
    fprintf( f, "attemptResolutionByServer = %i\n", (int)s_config.symbolsAttemptResolutionByServer);
    fprintf( f, "preventResolutionByClient = %i\n", (int)s_config.symbolsPreventResolutionByClient);

    fclose( f );
    return true;
}

}
