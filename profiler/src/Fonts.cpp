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
    static const ImWchar rangesBasic[] = {
        0x0020, 0x024F, // Basic Latin + Latin Supplement + Latin Extended A + Latin Extended B
        0x03BC, 0x03BC, // micro
        0x03C3, 0x03C3, // small sigma
        0x2013, 0x2013, // en dash
        0x2026, 0x2026, // ellipsis
        0x2264, 0x2264, // less-than or equal to
        0,
    };
    static const ImWchar rangesIcons[] = {
        ICON_MIN_FA, ICON_MAX_FA,
        0
    };
    static const ImWchar rangesFixed[] = {
        0x0020, 0x024F, // Basic Latin + Latin Supplement + Latin Extended A + Latin Extended B
        0x2026, 0x2026, // ellipsis
        0
    };

    ImGuiIO& io = ImGui::GetIO();

    ImFontConfig configBasic;
    configBasic.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_LightHinting;
    configBasic.FontDataOwnedByAtlas = false;
    ImFontConfig configMerge;
    configMerge.MergeMode = true;
    configMerge.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_LightHinting;
    configMerge.FontDataOwnedByAtlas = false;
    ImFontConfig configFixed;
    configFixed.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_LightHinting;
    configFixed.GlyphExtraAdvanceX = -1;
    configFixed.FontDataOwnedByAtlas = false;

    auto fontFixed = Unembed( FontFixed );
    auto fontIcons = Unembed( FontIcons );
    auto fontNormal = Unembed( FontNormal );
    auto fontBold = Unembed( FontBold );
    auto fontBoldItalic = Unembed( FontBoldItalic );
    auto fontItalic = Unembed( FontItalic );

    io.Fonts->Clear();

    io.Fonts->AddFontFromMemoryTTF( (void*)fontNormal->data(), fontNormal->size(), round( 15.0f * scale ), &configBasic, rangesBasic );
    io.Fonts->AddFontFromMemoryTTF( (void*)fontIcons->data(), fontIcons->size(), round( 14.0f * scale ), &configMerge, rangesIcons );

    g_fonts.mono = io.Fonts->AddFontFromMemoryTTF( (void*)fontFixed->data(), fontFixed->size(), round( 15.0f * scale ), &configFixed, rangesFixed );

    g_fonts.big = io.Fonts->AddFontFromMemoryTTF( (void*)fontNormal->data(), fontNormal->size(), round( 21.0f * scale ), &configBasic, rangesBasic );
    io.Fonts->AddFontFromMemoryTTF( (void*)fontIcons->data(), fontIcons->size(), round( 20.0f * scale ), &configMerge, rangesIcons );

    g_fonts.small = io.Fonts->AddFontFromMemoryTTF( (void*)fontNormal->data(), fontNormal->size(), round( 10.0f * scale ), &configBasic );

    g_fonts.bold = io.Fonts->AddFontFromMemoryTTF( (void*)fontBold->data(), fontBold->size(), round( 15.0f * scale ), &configBasic );
    io.Fonts->AddFontFromMemoryTTF( (void*)fontIcons->data(), fontIcons->size(), round( 20.0f * scale ), &configMerge, rangesIcons );

    g_fonts.boldItalic = io.Fonts->AddFontFromMemoryTTF( (void*)fontBoldItalic->data(), fontBoldItalic->size(), round( 15.0f * scale ), &configBasic );
    io.Fonts->AddFontFromMemoryTTF( (void*)fontIcons->data(), fontIcons->size(), round( 20.0f * scale ), &configMerge, rangesIcons );

    g_fonts.italic = io.Fonts->AddFontFromMemoryTTF( (void*)fontItalic->data(), fontItalic->size(), round( 15.0f * scale ), &configBasic );
    io.Fonts->AddFontFromMemoryTTF( (void*)fontIcons->data(), fontIcons->size(), round( 20.0f * scale ), &configMerge, rangesIcons );

    ImGui_ImplOpenGL3_DestroyFontsTexture();
    ImGui_ImplOpenGL3_CreateFontsTexture();
}
