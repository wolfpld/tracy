#include <imgui.h>
#include <math.h>

#include "Fonts.hpp"
#include "misc/freetype/imgui_freetype.h"
#include "imgui/imgui_impl_opengl3.h"
#include "../../server/IconsFontAwesome6.h"

#include "font/DroidSans.hpp"
#include "font/FiraCodeRetina.hpp"
#include "font/FontAwesomeSolid.hpp"

ImFont* s_bigFont;
ImFont* s_smallFont;
ImFont* s_fixedWidth;

void LoadFonts( float scale, ImFont*& cb_fixedWidth, ImFont*& cb_bigFont, ImFont*& cb_smallFont )
{
    static const ImWchar rangesBasic[] = {
        0x0020, 0x00FF, // Basic Latin + Latin Supplement
        0x03BC, 0x03BC, // micro
        0x03C3, 0x03C3, // small sigma
        0x2013, 0x2013, // en dash
        0x2264, 0x2264, // less-than or equal to
        0,
    };
    static const ImWchar rangesIcons[] = {
        ICON_MIN_FA, ICON_MAX_FA,
        0
    };
    static const ImWchar rangesFixed[] = {
        0x0020, 0x00FF, // Basic Latin + Latin Supplement
        0x2026, 0x2026, // ellipsis
        0
    };

    ImGuiIO& io = ImGui::GetIO();

    ImFontConfig configBasic;
    configBasic.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_LightHinting;
    ImFontConfig configMerge;
    configMerge.MergeMode = true;
    configMerge.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_LightHinting;
    ImFontConfig configFixed;
    configFixed.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_LightHinting;
    configFixed.GlyphExtraSpacing.x = -1;

    io.Fonts->Clear();
    io.Fonts->AddFontFromMemoryCompressedTTF( tracy::DroidSans_compressed_data, tracy::DroidSans_compressed_size, round( 15.0f * scale ), &configBasic, rangesBasic );
    io.Fonts->AddFontFromMemoryCompressedTTF( tracy::FontAwesomeSolid_compressed_data, tracy::FontAwesomeSolid_compressed_size, round( 14.0f * scale ), &configMerge, rangesIcons );
    s_fixedWidth = cb_fixedWidth = io.Fonts->AddFontFromMemoryCompressedTTF( tracy::FiraCodeRetina_compressed_data, tracy::FiraCodeRetina_compressed_size, round( 15.0f * scale ), &configFixed, rangesFixed );
    s_bigFont = cb_bigFont = io.Fonts->AddFontFromMemoryCompressedTTF( tracy::DroidSans_compressed_data, tracy::DroidSans_compressed_size, round( 21.0f * scale ), &configBasic );
    io.Fonts->AddFontFromMemoryCompressedTTF( tracy::FontAwesomeSolid_compressed_data, tracy::FontAwesomeSolid_compressed_size, round( 20.0f * scale ), &configMerge, rangesIcons );
    s_smallFont = cb_smallFont = io.Fonts->AddFontFromMemoryCompressedTTF( tracy::DroidSans_compressed_data, tracy::DroidSans_compressed_size, round( 10.0f * scale ), &configBasic );

    ImGui_ImplOpenGL3_DestroyFontsTexture();
    ImGui_ImplOpenGL3_CreateFontsTexture();
}
