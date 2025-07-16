#ifndef __FONTS_HPP__
#define __FONTS_HPP__

struct ImFont;

struct FontData
{
    ImFont* normal;
    ImFont* mono;
    ImFont* bold;
    ImFont* boldItalic;
    ImFont* italic;
};

extern FontData g_fonts;
extern float FontNormal, FontSmall, FontBig;

void LoadFonts( float scale );

#endif
