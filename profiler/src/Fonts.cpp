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

FontData g_fonts;

void LoadFonts( float scale )
{
    static const ImWchar rangesText[] = {
        0x0020, 0xFFFF,
        0,
    };
    static const ImWchar rangesIcons[] = {
        ICON_MIN_FA, ICON_MAX_FA,
        0
    };

    ImGuiIO& io = ImGui::GetIO();

    ImFontConfig configBasic;
    configBasic.FontLoaderFlags = ImGuiFreeTypeBuilderFlags_LightHinting;
    configBasic.FontDataOwnedByAtlas = false;
    ImFontConfig configMerge;
    configMerge.MergeMode = true;
    configMerge.FontLoaderFlags = ImGuiFreeTypeBuilderFlags_LightHinting;
    configMerge.FontDataOwnedByAtlas = false;
    ImFontConfig configFixed;
    configFixed.FontLoaderFlags = ImGuiFreeTypeBuilderFlags_LightHinting;
    configFixed.GlyphExtraAdvanceX = -1;
    configFixed.FontDataOwnedByAtlas = false;

    auto fontFixed = Unembed( FontFixed );
    auto fontIcons = Unembed( FontIcons );
    auto fontNormal = Unembed( FontNormal );
    auto fontBold = Unembed( FontBold );
    auto fontBoldItalic = Unembed( FontBoldItalic );
    auto fontItalic = Unembed( FontItalic );

    io.Fonts->Clear();

    io.Fonts->AddFontFromMemoryTTF( (void*)fontNormal->data(), fontNormal->size(), round( 15.0f * scale ), &configBasic, rangesText );
    io.Fonts->AddFontFromMemoryTTF( (void*)fontIcons->data(), fontIcons->size(), round( 14.0f * scale ), &configMerge, rangesIcons );

    g_fonts.mono = io.Fonts->AddFontFromMemoryTTF( (void*)fontFixed->data(), fontFixed->size(), round( 15.0f * scale ), &configFixed, rangesText );

    g_fonts.big = io.Fonts->AddFontFromMemoryTTF( (void*)fontNormal->data(), fontNormal->size(), round( 21.0f * scale ), &configBasic, rangesText );
    io.Fonts->AddFontFromMemoryTTF( (void*)fontIcons->data(), fontIcons->size(), round( 20.0f * scale ), &configMerge, rangesIcons );

    g_fonts.small = io.Fonts->AddFontFromMemoryTTF( (void*)fontNormal->data(), fontNormal->size(), round( 10.0f * scale ), &configBasic, rangesText );

    g_fonts.bold = io.Fonts->AddFontFromMemoryTTF( (void*)fontBold->data(), fontBold->size(), round( 15.0f * scale ), &configBasic, rangesText );
    io.Fonts->AddFontFromMemoryTTF( (void*)fontIcons->data(), fontIcons->size(), round( 20.0f * scale ), &configMerge, rangesIcons );

    g_fonts.boldItalic = io.Fonts->AddFontFromMemoryTTF( (void*)fontBoldItalic->data(), fontBoldItalic->size(), round( 15.0f * scale ), &configBasic, rangesText );
    io.Fonts->AddFontFromMemoryTTF( (void*)fontIcons->data(), fontIcons->size(), round( 20.0f * scale ), &configMerge, rangesIcons );

    g_fonts.italic = io.Fonts->AddFontFromMemoryTTF( (void*)fontItalic->data(), fontItalic->size(), round( 15.0f * scale ), &configBasic, rangesText );
    io.Fonts->AddFontFromMemoryTTF( (void*)fontIcons->data(), fontIcons->size(), round( 20.0f * scale ), &configMerge, rangesIcons );
}
