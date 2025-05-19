#ifndef __FONTS_HPP__
#define __FONTS_HPP__

struct ImFont;

struct FontData
{
    ImFont* big;
    ImFont* small;
    ImFont* mono;
    ImFont* bold;
    ImFont* boldItalic;
    ImFont* italic;
};

extern FontData g_fonts;

void LoadFonts( float scale );

#endif
