#ifndef __FONTS_HPP__
#define __FONTS_HPP__

struct ImFont;

extern ImFont* s_bigFont;
extern ImFont* s_smallFont;
extern ImFont* s_fixedWidth;

void LoadFonts( float scale, ImFont*& cb_fixedWidth, ImFont*& cb_bigFont, ImFont*& cb_smallFont );

#endif
