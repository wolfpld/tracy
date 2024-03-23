#include "Memory.hpp"
#include "ScopedZone.hpp"
#include "tracy/TracyC.h"

namespace tracy {
#ifndef TRACY_ENABLE
enum class PlotFormatType : uint8_t { Number, Memory, Percentage };
#endif

constexpr static inline bool IsEnabled() {
#ifdef TRACY_ENABLE
  return true;
#else
  return false;
#endif
}
}  // namespace tracy

PYBIND11_MODULE(TracyClientBindings, m) {
  m.doc() = "Tracy Client Bindings";

  m.def("is_enabled", &tracy::IsEnabled);

  py::enum_<tracy::Color::ColorType>(m, "ColorType")
      .value("Snow", tracy::Color::Snow)
      .value("GhostWhite", tracy::Color::GhostWhite)
      .value("WhiteSmoke", tracy::Color::WhiteSmoke)
      .value("Gainsboro", tracy::Color::Gainsboro)
      .value("FloralWhite", tracy::Color::FloralWhite)
      .value("OldLace", tracy::Color::OldLace)
      .value("Linen", tracy::Color::Linen)
      .value("AntiqueWhite", tracy::Color::AntiqueWhite)
      .value("PapayaWhip", tracy::Color::PapayaWhip)
      .value("BlanchedAlmond", tracy::Color::BlanchedAlmond)
      .value("Bisque", tracy::Color::Bisque)
      .value("PeachPuff", tracy::Color::PeachPuff)
      .value("NavajoWhite", tracy::Color::NavajoWhite)
      .value("Moccasin", tracy::Color::Moccasin)
      .value("Cornsilk", tracy::Color::Cornsilk)
      .value("Ivory", tracy::Color::Ivory)
      .value("LemonChiffon", tracy::Color::LemonChiffon)
      .value("Seashell", tracy::Color::Seashell)
      .value("Honeydew", tracy::Color::Honeydew)
      .value("MintCream", tracy::Color::MintCream)
      .value("Azure", tracy::Color::Azure)
      .value("AliceBlue", tracy::Color::AliceBlue)
      .value("Lavender", tracy::Color::Lavender)
      .value("LavenderBlush", tracy::Color::LavenderBlush)
      .value("MistyRose", tracy::Color::MistyRose)
      .value("White", tracy::Color::White)
      .value("Black", tracy::Color::Black)
      .value("DarkSlateGray", tracy::Color::DarkSlateGray)
      .value("DarkSlateGrey", tracy::Color::DarkSlateGrey)
      .value("DimGray", tracy::Color::DimGray)
      .value("DimGrey", tracy::Color::DimGrey)
      .value("SlateGray", tracy::Color::SlateGray)
      .value("SlateGrey", tracy::Color::SlateGrey)
      .value("LightSlateGray", tracy::Color::LightSlateGray)
      .value("LightSlateGrey", tracy::Color::LightSlateGrey)
      .value("Gray", tracy::Color::Gray)
      .value("Grey", tracy::Color::Grey)
      .value("X11Gray", tracy::Color::X11Gray)
      .value("X11Grey", tracy::Color::X11Grey)
      .value("WebGray", tracy::Color::WebGray)
      .value("WebGrey", tracy::Color::WebGrey)
      .value("LightGrey", tracy::Color::LightGrey)
      .value("LightGray", tracy::Color::LightGray)
      .value("MidnightBlue", tracy::Color::MidnightBlue)
      .value("Navy", tracy::Color::Navy)
      .value("NavyBlue", tracy::Color::NavyBlue)
      .value("CornflowerBlue", tracy::Color::CornflowerBlue)
      .value("DarkSlateBlue", tracy::Color::DarkSlateBlue)
      .value("SlateBlue", tracy::Color::SlateBlue)
      .value("MediumSlateBlue", tracy::Color::MediumSlateBlue)
      .value("LightSlateBlue", tracy::Color::LightSlateBlue)
      .value("MediumBlue", tracy::Color::MediumBlue)
      .value("RoyalBlue", tracy::Color::RoyalBlue)
      .value("Blue", tracy::Color::Blue)
      .value("DodgerBlue", tracy::Color::DodgerBlue)
      .value("DeepSkyBlue", tracy::Color::DeepSkyBlue)
      .value("SkyBlue", tracy::Color::SkyBlue)
      .value("LightSkyBlue", tracy::Color::LightSkyBlue)
      .value("SteelBlue", tracy::Color::SteelBlue)
      .value("LightSteelBlue", tracy::Color::LightSteelBlue)
      .value("LightBlue", tracy::Color::LightBlue)
      .value("PowderBlue", tracy::Color::PowderBlue)
      .value("PaleTurquoise", tracy::Color::PaleTurquoise)
      .value("DarkTurquoise", tracy::Color::DarkTurquoise)
      .value("MediumTurquoise", tracy::Color::MediumTurquoise)
      .value("Turquoise", tracy::Color::Turquoise)
      .value("Cyan", tracy::Color::Cyan)
      .value("Aqua", tracy::Color::Aqua)
      .value("LightCyan", tracy::Color::LightCyan)
      .value("CadetBlue", tracy::Color::CadetBlue)
      .value("MediumAquamarine", tracy::Color::MediumAquamarine)
      .value("Aquamarine", tracy::Color::Aquamarine)
      .value("DarkGreen", tracy::Color::DarkGreen)
      .value("DarkOliveGreen", tracy::Color::DarkOliveGreen)
      .value("DarkSeaGreen", tracy::Color::DarkSeaGreen)
      .value("SeaGreen", tracy::Color::SeaGreen)
      .value("MediumSeaGreen", tracy::Color::MediumSeaGreen)
      .value("LightSeaGreen", tracy::Color::LightSeaGreen)
      .value("PaleGreen", tracy::Color::PaleGreen)
      .value("SpringGreen", tracy::Color::SpringGreen)
      .value("LawnGreen", tracy::Color::LawnGreen)
      .value("Green", tracy::Color::Green)
      .value("Lime", tracy::Color::Lime)
      .value("X11Green", tracy::Color::X11Green)
      .value("WebGreen", tracy::Color::WebGreen)
      .value("Chartreuse", tracy::Color::Chartreuse)
      .value("MediumSpringGreen", tracy::Color::MediumSpringGreen)
      .value("GreenYellow", tracy::Color::GreenYellow)
      .value("LimeGreen", tracy::Color::LimeGreen)
      .value("YellowGreen", tracy::Color::YellowGreen)
      .value("ForestGreen", tracy::Color::ForestGreen)
      .value("OliveDrab", tracy::Color::OliveDrab)
      .value("DarkKhaki", tracy::Color::DarkKhaki)
      .value("Khaki", tracy::Color::Khaki)
      .value("PaleGoldenrod", tracy::Color::PaleGoldenrod)
      .value("LightGoldenrodYellow", tracy::Color::LightGoldenrodYellow)
      .value("LightYellow", tracy::Color::LightYellow)
      .value("Yellow", tracy::Color::Yellow)
      .value("Gold", tracy::Color::Gold)
      .value("LightGoldenrod", tracy::Color::LightGoldenrod)
      .value("Goldenrod", tracy::Color::Goldenrod)
      .value("DarkGoldenrod", tracy::Color::DarkGoldenrod)
      .value("RosyBrown", tracy::Color::RosyBrown)
      .value("IndianRed", tracy::Color::IndianRed)
      .value("SaddleBrown", tracy::Color::SaddleBrown)
      .value("Sienna", tracy::Color::Sienna)
      .value("Peru", tracy::Color::Peru)
      .value("Burlywood", tracy::Color::Burlywood)
      .value("Beige", tracy::Color::Beige)
      .value("Wheat", tracy::Color::Wheat)
      .value("SandyBrown", tracy::Color::SandyBrown)
      .value("Tan", tracy::Color::Tan)
      .value("Chocolate", tracy::Color::Chocolate)
      .value("Firebrick", tracy::Color::Firebrick)
      .value("Brown", tracy::Color::Brown)
      .value("DarkSalmon", tracy::Color::DarkSalmon)
      .value("Salmon", tracy::Color::Salmon)
      .value("LightSalmon", tracy::Color::LightSalmon)
      .value("Orange", tracy::Color::Orange)
      .value("DarkOrange", tracy::Color::DarkOrange)
      .value("Coral", tracy::Color::Coral)
      .value("LightCoral", tracy::Color::LightCoral)
      .value("Tomato", tracy::Color::Tomato)
      .value("OrangeRed", tracy::Color::OrangeRed)
      .value("Red", tracy::Color::Red)
      .value("HotPink", tracy::Color::HotPink)
      .value("DeepPink", tracy::Color::DeepPink)
      .value("Pink", tracy::Color::Pink)
      .value("LightPink", tracy::Color::LightPink)
      .value("PaleVioletRed", tracy::Color::PaleVioletRed)
      .value("Maroon", tracy::Color::Maroon)
      .value("X11Maroon", tracy::Color::X11Maroon)
      .value("WebMaroon", tracy::Color::WebMaroon)
      .value("MediumVioletRed", tracy::Color::MediumVioletRed)
      .value("VioletRed", tracy::Color::VioletRed)
      .value("Magenta", tracy::Color::Magenta)
      .value("Fuchsia", tracy::Color::Fuchsia)
      .value("Violet", tracy::Color::Violet)
      .value("Plum", tracy::Color::Plum)
      .value("Orchid", tracy::Color::Orchid)
      .value("MediumOrchid", tracy::Color::MediumOrchid)
      .value("DarkOrchid", tracy::Color::DarkOrchid)
      .value("DarkViolet", tracy::Color::DarkViolet)
      .value("BlueViolet", tracy::Color::BlueViolet)
      .value("Purple", tracy::Color::Purple)
      .value("X11Purple", tracy::Color::X11Purple)
      .value("WebPurple", tracy::Color::WebPurple)
      .value("MediumPurple", tracy::Color::MediumPurple)
      .value("Thistle", tracy::Color::Thistle)
      .value("Snow1", tracy::Color::Snow1)
      .value("Snow2", tracy::Color::Snow2)
      .value("Snow3", tracy::Color::Snow3)
      .value("Snow4", tracy::Color::Snow4)
      .value("Seashell1", tracy::Color::Seashell1)
      .value("Seashell2", tracy::Color::Seashell2)
      .value("Seashell3", tracy::Color::Seashell3)
      .value("Seashell4", tracy::Color::Seashell4)
      .value("AntiqueWhite1", tracy::Color::AntiqueWhite1)
      .value("AntiqueWhite2", tracy::Color::AntiqueWhite2)
      .value("AntiqueWhite3", tracy::Color::AntiqueWhite3)
      .value("AntiqueWhite4", tracy::Color::AntiqueWhite4)
      .value("Bisque1", tracy::Color::Bisque1)
      .value("Bisque2", tracy::Color::Bisque2)
      .value("Bisque3", tracy::Color::Bisque3)
      .value("Bisque4", tracy::Color::Bisque4)
      .value("PeachPuff1", tracy::Color::PeachPuff1)
      .value("PeachPuff2", tracy::Color::PeachPuff2)
      .value("PeachPuff3", tracy::Color::PeachPuff3)
      .value("PeachPuff4", tracy::Color::PeachPuff4)
      .value("NavajoWhite1", tracy::Color::NavajoWhite1)
      .value("NavajoWhite2", tracy::Color::NavajoWhite2)
      .value("NavajoWhite3", tracy::Color::NavajoWhite3)
      .value("NavajoWhite4", tracy::Color::NavajoWhite4)
      .value("LemonChiffon1", tracy::Color::LemonChiffon1)
      .value("LemonChiffon2", tracy::Color::LemonChiffon2)
      .value("LemonChiffon3", tracy::Color::LemonChiffon3)
      .value("LemonChiffon4", tracy::Color::LemonChiffon4)
      .value("Cornsilk1", tracy::Color::Cornsilk1)
      .value("Cornsilk2", tracy::Color::Cornsilk2)
      .value("Cornsilk3", tracy::Color::Cornsilk3)
      .value("Cornsilk4", tracy::Color::Cornsilk4)
      .value("Ivory1", tracy::Color::Ivory1)
      .value("Ivory2", tracy::Color::Ivory2)
      .value("Ivory3", tracy::Color::Ivory3)
      .value("Ivory4", tracy::Color::Ivory4)
      .value("Honeydew1", tracy::Color::Honeydew1)
      .value("Honeydew2", tracy::Color::Honeydew2)
      .value("Honeydew3", tracy::Color::Honeydew3)
      .value("Honeydew4", tracy::Color::Honeydew4)
      .value("LavenderBlush1", tracy::Color::LavenderBlush1)
      .value("LavenderBlush2", tracy::Color::LavenderBlush2)
      .value("LavenderBlush3", tracy::Color::LavenderBlush3)
      .value("LavenderBlush4", tracy::Color::LavenderBlush4)
      .value("MistyRose1", tracy::Color::MistyRose1)
      .value("MistyRose2", tracy::Color::MistyRose2)
      .value("MistyRose3", tracy::Color::MistyRose3)
      .value("MistyRose4", tracy::Color::MistyRose4)
      .value("Azure1", tracy::Color::Azure1)
      .value("Azure2", tracy::Color::Azure2)
      .value("Azure3", tracy::Color::Azure3)
      .value("Azure4", tracy::Color::Azure4)
      .value("SlateBlue1", tracy::Color::SlateBlue1)
      .value("SlateBlue2", tracy::Color::SlateBlue2)
      .value("SlateBlue3", tracy::Color::SlateBlue3)
      .value("SlateBlue4", tracy::Color::SlateBlue4)
      .value("RoyalBlue1", tracy::Color::RoyalBlue1)
      .value("RoyalBlue2", tracy::Color::RoyalBlue2)
      .value("RoyalBlue3", tracy::Color::RoyalBlue3)
      .value("RoyalBlue4", tracy::Color::RoyalBlue4)
      .value("Blue1", tracy::Color::Blue1)
      .value("Blue2", tracy::Color::Blue2)
      .value("Blue3", tracy::Color::Blue3)
      .value("Blue4", tracy::Color::Blue4)
      .value("DodgerBlue1", tracy::Color::DodgerBlue1)
      .value("DodgerBlue2", tracy::Color::DodgerBlue2)
      .value("DodgerBlue3", tracy::Color::DodgerBlue3)
      .value("DodgerBlue4", tracy::Color::DodgerBlue4)
      .value("SteelBlue1", tracy::Color::SteelBlue1)
      .value("SteelBlue2", tracy::Color::SteelBlue2)
      .value("SteelBlue3", tracy::Color::SteelBlue3)
      .value("SteelBlue4", tracy::Color::SteelBlue4)
      .value("DeepSkyBlue1", tracy::Color::DeepSkyBlue1)
      .value("DeepSkyBlue2", tracy::Color::DeepSkyBlue2)
      .value("DeepSkyBlue3", tracy::Color::DeepSkyBlue3)
      .value("DeepSkyBlue4", tracy::Color::DeepSkyBlue4)
      .value("SkyBlue1", tracy::Color::SkyBlue1)
      .value("SkyBlue2", tracy::Color::SkyBlue2)
      .value("SkyBlue3", tracy::Color::SkyBlue3)
      .value("SkyBlue4", tracy::Color::SkyBlue4)
      .value("LightSkyBlue1", tracy::Color::LightSkyBlue1)
      .value("LightSkyBlue2", tracy::Color::LightSkyBlue2)
      .value("LightSkyBlue3", tracy::Color::LightSkyBlue3)
      .value("LightSkyBlue4", tracy::Color::LightSkyBlue4)
      .value("SlateGray1", tracy::Color::SlateGray1)
      .value("SlateGray2", tracy::Color::SlateGray2)
      .value("SlateGray3", tracy::Color::SlateGray3)
      .value("SlateGray4", tracy::Color::SlateGray4)
      .value("LightSteelBlue1", tracy::Color::LightSteelBlue1)
      .value("LightSteelBlue2", tracy::Color::LightSteelBlue2)
      .value("LightSteelBlue3", tracy::Color::LightSteelBlue3)
      .value("LightSteelBlue4", tracy::Color::LightSteelBlue4)
      .value("LightBlue1", tracy::Color::LightBlue1)
      .value("LightBlue2", tracy::Color::LightBlue2)
      .value("LightBlue3", tracy::Color::LightBlue3)
      .value("LightBlue4", tracy::Color::LightBlue4)
      .value("LightCyan1", tracy::Color::LightCyan1)
      .value("LightCyan2", tracy::Color::LightCyan2)
      .value("LightCyan3", tracy::Color::LightCyan3)
      .value("LightCyan4", tracy::Color::LightCyan4)
      .value("PaleTurquoise1", tracy::Color::PaleTurquoise1)
      .value("PaleTurquoise2", tracy::Color::PaleTurquoise2)
      .value("PaleTurquoise3", tracy::Color::PaleTurquoise3)
      .value("PaleTurquoise4", tracy::Color::PaleTurquoise4)
      .value("CadetBlue1", tracy::Color::CadetBlue1)
      .value("CadetBlue2", tracy::Color::CadetBlue2)
      .value("CadetBlue3", tracy::Color::CadetBlue3)
      .value("CadetBlue4", tracy::Color::CadetBlue4)
      .value("Turquoise1", tracy::Color::Turquoise1)
      .value("Turquoise2", tracy::Color::Turquoise2)
      .value("Turquoise3", tracy::Color::Turquoise3)
      .value("Turquoise4", tracy::Color::Turquoise4)
      .value("Cyan1", tracy::Color::Cyan1)
      .value("Cyan2", tracy::Color::Cyan2)
      .value("Cyan3", tracy::Color::Cyan3)
      .value("Cyan4", tracy::Color::Cyan4)
      .value("DarkSlateGray1", tracy::Color::DarkSlateGray1)
      .value("DarkSlateGray2", tracy::Color::DarkSlateGray2)
      .value("DarkSlateGray3", tracy::Color::DarkSlateGray3)
      .value("DarkSlateGray4", tracy::Color::DarkSlateGray4)
      .value("Aquamarine1", tracy::Color::Aquamarine1)
      .value("Aquamarine2", tracy::Color::Aquamarine2)
      .value("Aquamarine3", tracy::Color::Aquamarine3)
      .value("Aquamarine4", tracy::Color::Aquamarine4)
      .value("DarkSeaGreen1", tracy::Color::DarkSeaGreen1)
      .value("DarkSeaGreen2", tracy::Color::DarkSeaGreen2)
      .value("DarkSeaGreen3", tracy::Color::DarkSeaGreen3)
      .value("DarkSeaGreen4", tracy::Color::DarkSeaGreen4)
      .value("SeaGreen1", tracy::Color::SeaGreen1)
      .value("SeaGreen2", tracy::Color::SeaGreen2)
      .value("SeaGreen3", tracy::Color::SeaGreen3)
      .value("SeaGreen4", tracy::Color::SeaGreen4)
      .value("PaleGreen1", tracy::Color::PaleGreen1)
      .value("PaleGreen2", tracy::Color::PaleGreen2)
      .value("PaleGreen3", tracy::Color::PaleGreen3)
      .value("PaleGreen4", tracy::Color::PaleGreen4)
      .value("SpringGreen1", tracy::Color::SpringGreen1)
      .value("SpringGreen2", tracy::Color::SpringGreen2)
      .value("SpringGreen3", tracy::Color::SpringGreen3)
      .value("SpringGreen4", tracy::Color::SpringGreen4)
      .value("Green1", tracy::Color::Green1)
      .value("Green2", tracy::Color::Green2)
      .value("Green3", tracy::Color::Green3)
      .value("Green4", tracy::Color::Green4)
      .value("Chartreuse1", tracy::Color::Chartreuse1)
      .value("Chartreuse2", tracy::Color::Chartreuse2)
      .value("Chartreuse3", tracy::Color::Chartreuse3)
      .value("Chartreuse4", tracy::Color::Chartreuse4)
      .value("OliveDrab1", tracy::Color::OliveDrab1)
      .value("OliveDrab2", tracy::Color::OliveDrab2)
      .value("OliveDrab3", tracy::Color::OliveDrab3)
      .value("OliveDrab4", tracy::Color::OliveDrab4)
      .value("DarkOliveGreen1", tracy::Color::DarkOliveGreen1)
      .value("DarkOliveGreen2", tracy::Color::DarkOliveGreen2)
      .value("DarkOliveGreen3", tracy::Color::DarkOliveGreen3)
      .value("DarkOliveGreen4", tracy::Color::DarkOliveGreen4)
      .value("Khaki1", tracy::Color::Khaki1)
      .value("Khaki2", tracy::Color::Khaki2)
      .value("Khaki3", tracy::Color::Khaki3)
      .value("Khaki4", tracy::Color::Khaki4)
      .value("LightGoldenrod1", tracy::Color::LightGoldenrod1)
      .value("LightGoldenrod2", tracy::Color::LightGoldenrod2)
      .value("LightGoldenrod3", tracy::Color::LightGoldenrod3)
      .value("LightGoldenrod4", tracy::Color::LightGoldenrod4)
      .value("LightYellow1", tracy::Color::LightYellow1)
      .value("LightYellow2", tracy::Color::LightYellow2)
      .value("LightYellow3", tracy::Color::LightYellow3)
      .value("LightYellow4", tracy::Color::LightYellow4)
      .value("Yellow1", tracy::Color::Yellow1)
      .value("Yellow2", tracy::Color::Yellow2)
      .value("Yellow3", tracy::Color::Yellow3)
      .value("Yellow4", tracy::Color::Yellow4)
      .value("Gold1", tracy::Color::Gold1)
      .value("Gold2", tracy::Color::Gold2)
      .value("Gold3", tracy::Color::Gold3)
      .value("Gold4", tracy::Color::Gold4)
      .value("Goldenrod1", tracy::Color::Goldenrod1)
      .value("Goldenrod2", tracy::Color::Goldenrod2)
      .value("Goldenrod3", tracy::Color::Goldenrod3)
      .value("Goldenrod4", tracy::Color::Goldenrod4)
      .value("DarkGoldenrod1", tracy::Color::DarkGoldenrod1)
      .value("DarkGoldenrod2", tracy::Color::DarkGoldenrod2)
      .value("DarkGoldenrod3", tracy::Color::DarkGoldenrod3)
      .value("DarkGoldenrod4", tracy::Color::DarkGoldenrod4)
      .value("RosyBrown1", tracy::Color::RosyBrown1)
      .value("RosyBrown2", tracy::Color::RosyBrown2)
      .value("RosyBrown3", tracy::Color::RosyBrown3)
      .value("RosyBrown4", tracy::Color::RosyBrown4)
      .value("IndianRed1", tracy::Color::IndianRed1)
      .value("IndianRed2", tracy::Color::IndianRed2)
      .value("IndianRed3", tracy::Color::IndianRed3)
      .value("IndianRed4", tracy::Color::IndianRed4)
      .value("Sienna1", tracy::Color::Sienna1)
      .value("Sienna2", tracy::Color::Sienna2)
      .value("Sienna3", tracy::Color::Sienna3)
      .value("Sienna4", tracy::Color::Sienna4)
      .value("Burlywood1", tracy::Color::Burlywood1)
      .value("Burlywood2", tracy::Color::Burlywood2)
      .value("Burlywood3", tracy::Color::Burlywood3)
      .value("Burlywood4", tracy::Color::Burlywood4)
      .value("Wheat1", tracy::Color::Wheat1)
      .value("Wheat2", tracy::Color::Wheat2)
      .value("Wheat3", tracy::Color::Wheat3)
      .value("Wheat4", tracy::Color::Wheat4)
      .value("Tan1", tracy::Color::Tan1)
      .value("Tan2", tracy::Color::Tan2)
      .value("Tan3", tracy::Color::Tan3)
      .value("Tan4", tracy::Color::Tan4)
      .value("Chocolate1", tracy::Color::Chocolate1)
      .value("Chocolate2", tracy::Color::Chocolate2)
      .value("Chocolate3", tracy::Color::Chocolate3)
      .value("Chocolate4", tracy::Color::Chocolate4)
      .value("Firebrick1", tracy::Color::Firebrick1)
      .value("Firebrick2", tracy::Color::Firebrick2)
      .value("Firebrick3", tracy::Color::Firebrick3)
      .value("Firebrick4", tracy::Color::Firebrick4)
      .value("Brown1", tracy::Color::Brown1)
      .value("Brown2", tracy::Color::Brown2)
      .value("Brown3", tracy::Color::Brown3)
      .value("Brown4", tracy::Color::Brown4)
      .value("Salmon1", tracy::Color::Salmon1)
      .value("Salmon2", tracy::Color::Salmon2)
      .value("Salmon3", tracy::Color::Salmon3)
      .value("Salmon4", tracy::Color::Salmon4)
      .value("LightSalmon1", tracy::Color::LightSalmon1)
      .value("LightSalmon2", tracy::Color::LightSalmon2)
      .value("LightSalmon3", tracy::Color::LightSalmon3)
      .value("LightSalmon4", tracy::Color::LightSalmon4)
      .value("Orange1", tracy::Color::Orange1)
      .value("Orange2", tracy::Color::Orange2)
      .value("Orange3", tracy::Color::Orange3)
      .value("Orange4", tracy::Color::Orange4)
      .value("DarkOrange1", tracy::Color::DarkOrange1)
      .value("DarkOrange2", tracy::Color::DarkOrange2)
      .value("DarkOrange3", tracy::Color::DarkOrange3)
      .value("DarkOrange4", tracy::Color::DarkOrange4)
      .value("Coral1", tracy::Color::Coral1)
      .value("Coral2", tracy::Color::Coral2)
      .value("Coral3", tracy::Color::Coral3)
      .value("Coral4", tracy::Color::Coral4)
      .value("Tomato1", tracy::Color::Tomato1)
      .value("Tomato2", tracy::Color::Tomato2)
      .value("Tomato3", tracy::Color::Tomato3)
      .value("Tomato4", tracy::Color::Tomato4)
      .value("OrangeRed1", tracy::Color::OrangeRed1)
      .value("OrangeRed2", tracy::Color::OrangeRed2)
      .value("OrangeRed3", tracy::Color::OrangeRed3)
      .value("OrangeRed4", tracy::Color::OrangeRed4)
      .value("Red1", tracy::Color::Red1)
      .value("Red2", tracy::Color::Red2)
      .value("Red3", tracy::Color::Red3)
      .value("Red4", tracy::Color::Red4)
      .value("DeepPink1", tracy::Color::DeepPink1)
      .value("DeepPink2", tracy::Color::DeepPink2)
      .value("DeepPink3", tracy::Color::DeepPink3)
      .value("DeepPink4", tracy::Color::DeepPink4)
      .value("HotPink1", tracy::Color::HotPink1)
      .value("HotPink2", tracy::Color::HotPink2)
      .value("HotPink3", tracy::Color::HotPink3)
      .value("HotPink4", tracy::Color::HotPink4)
      .value("Pink1", tracy::Color::Pink1)
      .value("Pink2", tracy::Color::Pink2)
      .value("Pink3", tracy::Color::Pink3)
      .value("Pink4", tracy::Color::Pink4)
      .value("LightPink1", tracy::Color::LightPink1)
      .value("LightPink2", tracy::Color::LightPink2)
      .value("LightPink3", tracy::Color::LightPink3)
      .value("LightPink4", tracy::Color::LightPink4)
      .value("PaleVioletRed1", tracy::Color::PaleVioletRed1)
      .value("PaleVioletRed2", tracy::Color::PaleVioletRed2)
      .value("PaleVioletRed3", tracy::Color::PaleVioletRed3)
      .value("PaleVioletRed4", tracy::Color::PaleVioletRed4)
      .value("Maroon1", tracy::Color::Maroon1)
      .value("Maroon2", tracy::Color::Maroon2)
      .value("Maroon3", tracy::Color::Maroon3)
      .value("Maroon4", tracy::Color::Maroon4)
      .value("VioletRed1", tracy::Color::VioletRed1)
      .value("VioletRed2", tracy::Color::VioletRed2)
      .value("VioletRed3", tracy::Color::VioletRed3)
      .value("VioletRed4", tracy::Color::VioletRed4)
      .value("Magenta1", tracy::Color::Magenta1)
      .value("Magenta2", tracy::Color::Magenta2)
      .value("Magenta3", tracy::Color::Magenta3)
      .value("Magenta4", tracy::Color::Magenta4)
      .value("Orchid1", tracy::Color::Orchid1)
      .value("Orchid2", tracy::Color::Orchid2)
      .value("Orchid3", tracy::Color::Orchid3)
      .value("Orchid4", tracy::Color::Orchid4)
      .value("Plum1", tracy::Color::Plum1)
      .value("Plum2", tracy::Color::Plum2)
      .value("Plum3", tracy::Color::Plum3)
      .value("Plum4", tracy::Color::Plum4)
      .value("MediumOrchid1", tracy::Color::MediumOrchid1)
      .value("MediumOrchid2", tracy::Color::MediumOrchid2)
      .value("MediumOrchid3", tracy::Color::MediumOrchid3)
      .value("MediumOrchid4", tracy::Color::MediumOrchid4)
      .value("DarkOrchid1", tracy::Color::DarkOrchid1)
      .value("DarkOrchid2", tracy::Color::DarkOrchid2)
      .value("DarkOrchid3", tracy::Color::DarkOrchid3)
      .value("DarkOrchid4", tracy::Color::DarkOrchid4)
      .value("Purple1", tracy::Color::Purple1)
      .value("Purple2", tracy::Color::Purple2)
      .value("Purple3", tracy::Color::Purple3)
      .value("Purple4", tracy::Color::Purple4)
      .value("MediumPurple1", tracy::Color::MediumPurple1)
      .value("MediumPurple2", tracy::Color::MediumPurple2)
      .value("MediumPurple3", tracy::Color::MediumPurple3)
      .value("MediumPurple4", tracy::Color::MediumPurple4)
      .value("Thistle1", tracy::Color::Thistle1)
      .value("Thistle2", tracy::Color::Thistle2)
      .value("Thistle3", tracy::Color::Thistle3)
      .value("Thistle4", tracy::Color::Thistle4)
      .value("Gray0", tracy::Color::Gray0)
      .value("Grey0", tracy::Color::Grey0)
      .value("Gray1", tracy::Color::Gray1)
      .value("Grey1", tracy::Color::Grey1)
      .value("Gray2", tracy::Color::Gray2)
      .value("Grey2", tracy::Color::Grey2)
      .value("Gray3", tracy::Color::Gray3)
      .value("Grey3", tracy::Color::Grey3)
      .value("Gray4", tracy::Color::Gray4)
      .value("Grey4", tracy::Color::Grey4)
      .value("Gray5", tracy::Color::Gray5)
      .value("Grey5", tracy::Color::Grey5)
      .value("Gray6", tracy::Color::Gray6)
      .value("Grey6", tracy::Color::Grey6)
      .value("Gray7", tracy::Color::Gray7)
      .value("Grey7", tracy::Color::Grey7)
      .value("Gray8", tracy::Color::Gray8)
      .value("Grey8", tracy::Color::Grey8)
      .value("Gray9", tracy::Color::Gray9)
      .value("Grey9", tracy::Color::Grey9)
      .value("Gray10", tracy::Color::Gray10)
      .value("Grey10", tracy::Color::Grey10)
      .value("Gray11", tracy::Color::Gray11)
      .value("Grey11", tracy::Color::Grey11)
      .value("Gray12", tracy::Color::Gray12)
      .value("Grey12", tracy::Color::Grey12)
      .value("Gray13", tracy::Color::Gray13)
      .value("Grey13", tracy::Color::Grey13)
      .value("Gray14", tracy::Color::Gray14)
      .value("Grey14", tracy::Color::Grey14)
      .value("Gray15", tracy::Color::Gray15)
      .value("Grey15", tracy::Color::Grey15)
      .value("Gray16", tracy::Color::Gray16)
      .value("Grey16", tracy::Color::Grey16)
      .value("Gray17", tracy::Color::Gray17)
      .value("Grey17", tracy::Color::Grey17)
      .value("Gray18", tracy::Color::Gray18)
      .value("Grey18", tracy::Color::Grey18)
      .value("Gray19", tracy::Color::Gray19)
      .value("Grey19", tracy::Color::Grey19)
      .value("Gray20", tracy::Color::Gray20)
      .value("Grey20", tracy::Color::Grey20)
      .value("Gray21", tracy::Color::Gray21)
      .value("Grey21", tracy::Color::Grey21)
      .value("Gray22", tracy::Color::Gray22)
      .value("Grey22", tracy::Color::Grey22)
      .value("Gray23", tracy::Color::Gray23)
      .value("Grey23", tracy::Color::Grey23)
      .value("Gray24", tracy::Color::Gray24)
      .value("Grey24", tracy::Color::Grey24)
      .value("Gray25", tracy::Color::Gray25)
      .value("Grey25", tracy::Color::Grey25)
      .value("Gray26", tracy::Color::Gray26)
      .value("Grey26", tracy::Color::Grey26)
      .value("Gray27", tracy::Color::Gray27)
      .value("Grey27", tracy::Color::Grey27)
      .value("Gray28", tracy::Color::Gray28)
      .value("Grey28", tracy::Color::Grey28)
      .value("Gray29", tracy::Color::Gray29)
      .value("Grey29", tracy::Color::Grey29)
      .value("Gray30", tracy::Color::Gray30)
      .value("Grey30", tracy::Color::Grey30)
      .value("Gray31", tracy::Color::Gray31)
      .value("Grey31", tracy::Color::Grey31)
      .value("Gray32", tracy::Color::Gray32)
      .value("Grey32", tracy::Color::Grey32)
      .value("Gray33", tracy::Color::Gray33)
      .value("Grey33", tracy::Color::Grey33)
      .value("Gray34", tracy::Color::Gray34)
      .value("Grey34", tracy::Color::Grey34)
      .value("Gray35", tracy::Color::Gray35)
      .value("Grey35", tracy::Color::Grey35)
      .value("Gray36", tracy::Color::Gray36)
      .value("Grey36", tracy::Color::Grey36)
      .value("Gray37", tracy::Color::Gray37)
      .value("Grey37", tracy::Color::Grey37)
      .value("Gray38", tracy::Color::Gray38)
      .value("Grey38", tracy::Color::Grey38)
      .value("Gray39", tracy::Color::Gray39)
      .value("Grey39", tracy::Color::Grey39)
      .value("Gray40", tracy::Color::Gray40)
      .value("Grey40", tracy::Color::Grey40)
      .value("Gray41", tracy::Color::Gray41)
      .value("Grey41", tracy::Color::Grey41)
      .value("Gray42", tracy::Color::Gray42)
      .value("Grey42", tracy::Color::Grey42)
      .value("Gray43", tracy::Color::Gray43)
      .value("Grey43", tracy::Color::Grey43)
      .value("Gray44", tracy::Color::Gray44)
      .value("Grey44", tracy::Color::Grey44)
      .value("Gray45", tracy::Color::Gray45)
      .value("Grey45", tracy::Color::Grey45)
      .value("Gray46", tracy::Color::Gray46)
      .value("Grey46", tracy::Color::Grey46)
      .value("Gray47", tracy::Color::Gray47)
      .value("Grey47", tracy::Color::Grey47)
      .value("Gray48", tracy::Color::Gray48)
      .value("Grey48", tracy::Color::Grey48)
      .value("Gray49", tracy::Color::Gray49)
      .value("Grey49", tracy::Color::Grey49)
      .value("Gray50", tracy::Color::Gray50)
      .value("Grey50", tracy::Color::Grey50)
      .value("Gray51", tracy::Color::Gray51)
      .value("Grey51", tracy::Color::Grey51)
      .value("Gray52", tracy::Color::Gray52)
      .value("Grey52", tracy::Color::Grey52)
      .value("Gray53", tracy::Color::Gray53)
      .value("Grey53", tracy::Color::Grey53)
      .value("Gray54", tracy::Color::Gray54)
      .value("Grey54", tracy::Color::Grey54)
      .value("Gray55", tracy::Color::Gray55)
      .value("Grey55", tracy::Color::Grey55)
      .value("Gray56", tracy::Color::Gray56)
      .value("Grey56", tracy::Color::Grey56)
      .value("Gray57", tracy::Color::Gray57)
      .value("Grey57", tracy::Color::Grey57)
      .value("Gray58", tracy::Color::Gray58)
      .value("Grey58", tracy::Color::Grey58)
      .value("Gray59", tracy::Color::Gray59)
      .value("Grey59", tracy::Color::Grey59)
      .value("Gray60", tracy::Color::Gray60)
      .value("Grey60", tracy::Color::Grey60)
      .value("Gray61", tracy::Color::Gray61)
      .value("Grey61", tracy::Color::Grey61)
      .value("Gray62", tracy::Color::Gray62)
      .value("Grey62", tracy::Color::Grey62)
      .value("Gray63", tracy::Color::Gray63)
      .value("Grey63", tracy::Color::Grey63)
      .value("Gray64", tracy::Color::Gray64)
      .value("Grey64", tracy::Color::Grey64)
      .value("Gray65", tracy::Color::Gray65)
      .value("Grey65", tracy::Color::Grey65)
      .value("Gray66", tracy::Color::Gray66)
      .value("Grey66", tracy::Color::Grey66)
      .value("Gray67", tracy::Color::Gray67)
      .value("Grey67", tracy::Color::Grey67)
      .value("Gray68", tracy::Color::Gray68)
      .value("Grey68", tracy::Color::Grey68)
      .value("Gray69", tracy::Color::Gray69)
      .value("Grey69", tracy::Color::Grey69)
      .value("Gray70", tracy::Color::Gray70)
      .value("Grey70", tracy::Color::Grey70)
      .value("Gray71", tracy::Color::Gray71)
      .value("Grey71", tracy::Color::Grey71)
      .value("Gray72", tracy::Color::Gray72)
      .value("Grey72", tracy::Color::Grey72)
      .value("Gray73", tracy::Color::Gray73)
      .value("Grey73", tracy::Color::Grey73)
      .value("Gray74", tracy::Color::Gray74)
      .value("Grey74", tracy::Color::Grey74)
      .value("Gray75", tracy::Color::Gray75)
      .value("Grey75", tracy::Color::Grey75)
      .value("Gray76", tracy::Color::Gray76)
      .value("Grey76", tracy::Color::Grey76)
      .value("Gray77", tracy::Color::Gray77)
      .value("Grey77", tracy::Color::Grey77)
      .value("Gray78", tracy::Color::Gray78)
      .value("Grey78", tracy::Color::Grey78)
      .value("Gray79", tracy::Color::Gray79)
      .value("Grey79", tracy::Color::Grey79)
      .value("Gray80", tracy::Color::Gray80)
      .value("Grey80", tracy::Color::Grey80)
      .value("Gray81", tracy::Color::Gray81)
      .value("Grey81", tracy::Color::Grey81)
      .value("Gray82", tracy::Color::Gray82)
      .value("Grey82", tracy::Color::Grey82)
      .value("Gray83", tracy::Color::Gray83)
      .value("Grey83", tracy::Color::Grey83)
      .value("Gray84", tracy::Color::Gray84)
      .value("Grey84", tracy::Color::Grey84)
      .value("Gray85", tracy::Color::Gray85)
      .value("Grey85", tracy::Color::Grey85)
      .value("Gray86", tracy::Color::Gray86)
      .value("Grey86", tracy::Color::Grey86)
      .value("Gray87", tracy::Color::Gray87)
      .value("Grey87", tracy::Color::Grey87)
      .value("Gray88", tracy::Color::Gray88)
      .value("Grey88", tracy::Color::Grey88)
      .value("Gray89", tracy::Color::Gray89)
      .value("Grey89", tracy::Color::Grey89)
      .value("Gray90", tracy::Color::Gray90)
      .value("Grey90", tracy::Color::Grey90)
      .value("Gray91", tracy::Color::Gray91)
      .value("Grey91", tracy::Color::Grey91)
      .value("Gray92", tracy::Color::Gray92)
      .value("Grey92", tracy::Color::Grey92)
      .value("Gray93", tracy::Color::Gray93)
      .value("Grey93", tracy::Color::Grey93)
      .value("Gray94", tracy::Color::Gray94)
      .value("Grey94", tracy::Color::Grey94)
      .value("Gray95", tracy::Color::Gray95)
      .value("Grey95", tracy::Color::Grey95)
      .value("Gray96", tracy::Color::Gray96)
      .value("Grey96", tracy::Color::Grey96)
      .value("Gray97", tracy::Color::Gray97)
      .value("Grey97", tracy::Color::Grey97)
      .value("Gray98", tracy::Color::Gray98)
      .value("Grey98", tracy::Color::Grey98)
      .value("Gray99", tracy::Color::Gray99)
      .value("Grey99", tracy::Color::Grey99)
      .value("Gray100", tracy::Color::Gray100)
      .value("Grey100", tracy::Color::Grey100)
      .value("DarkGrey", tracy::Color::DarkGrey)
      .value("DarkGray", tracy::Color::DarkGray)
      .value("DarkBlue", tracy::Color::DarkBlue)
      .value("DarkCyan", tracy::Color::DarkCyan)
      .value("DarkMagenta", tracy::Color::DarkMagenta)
      .value("DarkRed", tracy::Color::DarkRed)
      .value("LightGreen", tracy::Color::LightGreen)
      .value("Crimson", tracy::Color::Crimson)
      .value("Indigo", tracy::Color::Indigo)
      .value("Olive", tracy::Color::Olive)
      .value("RebeccaPurple", tracy::Color::RebeccaPurple)
      .value("Silver", tracy::Color::Silver)
      .value("Teal", tracy::Color::Teal)
      .export_values();

  m.def(
      "program_name",
      [](const std::string &name) {
        if (!tracy::IsEnabled()) return true;
        auto entry = NameBuffer::Add(name);
        if (!entry.first) return false;
        TracySetProgramName(entry.second);
        return true;
      },
      "name"_a.none(false));

  m.def(
      "thread_name",
      [](const std::string &name) {
        if (!tracy::IsEnabled()) return;
        tracy::SetThreadName(name.c_str());
      },
      "name"_a.none(false));

  m.def(
      "app_info",
      [](const std::string &text) {
        if (!tracy::IsEnabled()) return true;
        if (text.size() >= std::numeric_limits<uint16_t>::max()) return false;
        TracyAppInfo(text.c_str(), text.size());
        return true;
      },
      "text"_a.none(false));

  m.def(
      "message",
      [](const std::string &message) {
        if (!tracy::IsEnabled()) return true;
        if (message.size() >= std::numeric_limits<uint16_t>::max())
          return false;
        TracyMessage(message.c_str(), message.size());
        return true;
      },
      "message"_a.none(false));

  m.def(
      "message",
      [](const std::string &message, uint32_t pColor) {
        if (!tracy::IsEnabled()) return true;
        if (message.size() >= std::numeric_limits<uint16_t>::max())
          return false;
        TracyMessageC(message.c_str(), message.size(), pColor);
        return true;
      },
      "message"_a.none(false), "color"_a.none(false));

  m.def("frame_mark", []() { FrameMark; });

  m.def(
      "frame_mark_start",
      [](const std::string &name) {
        if (!tracy::IsEnabled()) return static_cast<OptionalNumber>(0ul);
        auto entry = NameBuffer::Add(name);
        if (!entry.first) return static_cast<OptionalNumber>(std::nullopt);
        FrameMarkStart(entry.second);
        return entry.first;
      },
      "name"_a.none(false));

  m.def(
      "frame_mark_end",
      [](std::size_t id) {
        if (!tracy::IsEnabled()) return true;
        auto ptr = NameBuffer::Get(id);
        if (!ptr) return false;
        FrameMarkEnd(ptr);
        return true;
      },
      "name"_a.none(false));

  m.def(
      "frame_image",
      [](const py::bytes &image, uint16_t width, uint16_t height,
         uint8_t offset = 0, bool flip = false) {
        if (!tracy::IsEnabled()) return true;
        if (width % 4 != 0 || height % 4 != 0) return false;
        TracyCFrameImage(std::string(image).data(), width, height, offset,
                         flip);
        return true;
      },
      "data"_a.none(false), "width"_a.none(false), "height"_a.none(false),
      "offset"_a.none(false) = 0, "flip"_a.none(false) = false);

  py::class_<PyScopedZone, std::shared_ptr<PyScopedZone>>(m, "_ScopedZone")
      .def(py::init<const OptionalString &, uint32_t, OptionalInt, bool,
                    const std::string &, const std::string &, uint32_t>(),
           "name"_a, "color"_a.none(false), "depth"_a, "active"_a.none(false),
           "function"_a.none(false), "file"_a.none(false), "line"_a.none(false))
      .def_property_readonly("is_active", &PyScopedZone::IsActive)
      .def("text", &PyScopedZone::Text<std::string>, "text"_a.none(false))
      .def("text", &PyScopedZone::Text<py::object>, "text"_a.none(false))
      .def("name", &PyScopedZone::Name, "name"_a.none(false))
      .def("_color", &PyScopedZone::Color, "color"_a.none(false))
      .def("enter", &PyScopedZone::Enter)
      .def("exit", &PyScopedZone::Exit);

  m.def("alloc", &MemoryAllocate<>, "ptr"_a.none(false), "size"_a.none(false),
        "name"_a = static_cast<OptionalString>(std::nullopt),
        "id"_a = static_cast<OptionalNumber>(std::nullopt),
        "depth"_a = static_cast<OptionalInt>(std::nullopt));
  m.def("alloc", &MemoryAllocate<py::object>, "object"_a.none(false),
        "size"_a.none(false),
        "name"_a = static_cast<OptionalString>(std::nullopt),
        "id"_a = static_cast<OptionalNumber>(std::nullopt),
        "depth"_a = static_cast<OptionalInt>(std::nullopt));

  m.def("free", &MemoryFree<>, "ptr"_a.none(false),
        "id"_a = static_cast<OptionalNumber>(std::nullopt),
        "depth"_a = static_cast<OptionalInt>(std::nullopt));
  m.def("free", &MemoryFree<py::object>, "object"_a.none(false),
        "id"_a = static_cast<OptionalNumber>(std::nullopt),
        "depth"_a = static_cast<OptionalInt>(std::nullopt));

  m.def(
      "_plot_config",
      [](const std::string &name, int type, bool step, bool fill,
         uint32_t color = 0) {
        if (!tracy::IsEnabled()) return static_cast<OptionalNumber>(0ul);
        auto entry = NameBuffer::Add(name);
        if (!entry.first) return static_cast<OptionalNumber>(std::nullopt);
        TracyCPlotConfig(entry.second, type, step, fill, color);
        return entry.first;
      },
      "name"_a.none(false), "type"_a.none(false), "step"_a.none(false),
      "fill"_a.none(false), "color"_a.none(false));

  py::enum_<tracy::PlotFormatType>(m, "PlotFormatType")
      .value("Number", tracy::PlotFormatType::Number)
      .value("Memory", tracy::PlotFormatType::Memory)
      .value("Percentage", tracy::PlotFormatType::Percentage)
      .export_values();

  m.def(
      "plot",
      [](std::size_t id, double value) {
        if (!tracy::IsEnabled()) return true;
        auto ptr = NameBuffer::Get(id);
        if (!ptr) return false;
        TracyCPlot(ptr, value);
        return true;
      },
      "id"_a.none(false), "value"_a.none(false));
  m.def(
      "plot",
      [](std::size_t id, float value) {
        if (!tracy::IsEnabled()) return true;
        auto ptr = NameBuffer::Get(id);
        if (!ptr) return false;
        TracyCPlotF(ptr, value);
        return true;
      },
      "id"_a.none(false), "value"_a.none(false));
  m.def(
      "plot",
      [](std::size_t id, int64_t value) {
        if (!tracy::IsEnabled()) return true;
        auto ptr = NameBuffer::Get(id);
        if (!ptr) return false;
        TracyCPlotI(ptr, value);
        return true;
      },
      "id"_a.none(false), "value"_a.none(false));
}
