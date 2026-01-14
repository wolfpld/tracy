#include <imgui.h>
#include <math.h>
#include <backends/imgui_impl_opengl3.h>
#include <misc/freetype/imgui_freetype.h>

#include "Fonts.hpp"
#include "profiler/IconsFontAwesome6.h"
#include "profiler/TracyEmbed.hpp"

#include "data/FontFixed.hpp"
#include "data/FontIcons.hpp"
#include "data/FontNormal.hpp"
#include "data/FontBold.hpp"
#include "data/FontBoldItalic.hpp"
#include "data/FontItalic.hpp"
#include "data/FontEmoji.hpp"

FontData g_fonts;

float FontNormal, FontSmall, FontBig;

void LoadFonts( float scale )
{
    ImGuiIO& io = ImGui::GetIO();

    ImFontConfig configBasic;
    configBasic.FontLoaderFlags = ImGuiFreeTypeLoaderFlags_LightHinting;
    configBasic.FontDataOwnedByAtlas = false;
    ImFontConfig configMerge;
    configMerge.MergeMode = true;
    configMerge.FontLoaderFlags = ImGuiFreeTypeLoaderFlags_LightHinting;
    configMerge.FontDataOwnedByAtlas = false;
    ImFontConfig configFixed;
    configFixed.FontLoaderFlags = ImGuiFreeTypeLoaderFlags_LightHinting;
    configFixed.GlyphExtraAdvanceX = -1;
    configFixed.FontDataOwnedByAtlas = false;

    auto fontFixed = Unembed( FontFixed );
    auto fontIcons = Unembed( FontIcons );
    auto fontNormal = Unembed( FontNormal );
    auto fontBold = Unembed( FontBold );
    auto fontBoldItalic = Unembed( FontBoldItalic );
    auto fontItalic = Unembed( FontItalic );
    auto fontEmoji = Unembed( FontEmoji );

    io.Fonts->Clear();

    g_fonts.normal = io.Fonts->AddFontFromMemoryTTF( (void*)fontNormal->data(), fontNormal->size(), round( 15.0f * scale ), &configBasic );
    io.Fonts->AddFontFromMemoryTTF( (void*)fontIcons->data(), fontIcons->size(), round( 14.0f * scale ), &configMerge );
    io.Fonts->AddFontFromMemoryTTF( (void*)fontEmoji->data(), fontEmoji->size(), round( 14.0f * scale ), &configMerge );

    g_fonts.mono = io.Fonts->AddFontFromMemoryTTF( (void*)fontFixed->data(), fontFixed->size(), round( 15.0f * scale ), &configFixed );
    io.Fonts->AddFontFromMemoryTTF( (void*)fontIcons->data(), fontIcons->size(), round( 14.0f * scale ), &configMerge );
    io.Fonts->AddFontFromMemoryTTF( (void*)fontEmoji->data(), fontEmoji->size(), round( 14.0f * scale ), &configMerge );

    g_fonts.bold = io.Fonts->AddFontFromMemoryTTF( (void*)fontBold->data(), fontBold->size(), round( 15.0f * scale ), &configBasic );
    io.Fonts->AddFontFromMemoryTTF( (void*)fontIcons->data(), fontIcons->size(), round( 14.0f * scale ), &configMerge );
    io.Fonts->AddFontFromMemoryTTF( (void*)fontEmoji->data(), fontEmoji->size(), round( 14.0f * scale ), &configMerge );

    g_fonts.boldItalic = io.Fonts->AddFontFromMemoryTTF( (void*)fontBoldItalic->data(), fontBoldItalic->size(), round( 15.0f * scale ), &configBasic );
    io.Fonts->AddFontFromMemoryTTF( (void*)fontIcons->data(), fontIcons->size(), round( 14.0f * scale ), &configMerge );
    io.Fonts->AddFontFromMemoryTTF( (void*)fontEmoji->data(), fontEmoji->size(), round( 14.0f * scale ), &configMerge );

    g_fonts.italic = io.Fonts->AddFontFromMemoryTTF( (void*)fontItalic->data(), fontItalic->size(), round( 15.0f * scale ), &configBasic );
    io.Fonts->AddFontFromMemoryTTF( (void*)fontIcons->data(), fontIcons->size(), round( 14.0f * scale ), &configMerge );
    io.Fonts->AddFontFromMemoryTTF( (void*)fontEmoji->data(), fontEmoji->size(), round( 14.0f * scale ), &configMerge );

    FontNormal = round( scale * 15.f );
    FontSmall = round( scale * 15 * 2.f / 3.f );
    FontBig = round( scale * 15 * 1.4f );
}
