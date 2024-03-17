"""Tracy Client Bindings"""
from __future__ import annotations
import tracy_client.TracyClientBindings
import typing

__all__ = [
    "AliceBlue",
    "AntiqueWhite",
    "AntiqueWhite1",
    "AntiqueWhite2",
    "AntiqueWhite3",
    "AntiqueWhite4",
    "Aqua",
    "Aquamarine",
    "Aquamarine1",
    "Aquamarine2",
    "Aquamarine3",
    "Aquamarine4",
    "Azure",
    "Azure1",
    "Azure2",
    "Azure3",
    "Azure4",
    "Beige",
    "Bisque",
    "Bisque1",
    "Bisque2",
    "Bisque3",
    "Bisque4",
    "Black",
    "BlanchedAlmond",
    "Blue",
    "Blue1",
    "Blue2",
    "Blue3",
    "Blue4",
    "BlueViolet",
    "Brown",
    "Brown1",
    "Brown2",
    "Brown3",
    "Brown4",
    "Burlywood",
    "Burlywood1",
    "Burlywood2",
    "Burlywood3",
    "Burlywood4",
    "CadetBlue",
    "CadetBlue1",
    "CadetBlue2",
    "CadetBlue3",
    "CadetBlue4",
    "Chartreuse",
    "Chartreuse1",
    "Chartreuse2",
    "Chartreuse3",
    "Chartreuse4",
    "Chocolate",
    "Chocolate1",
    "Chocolate2",
    "Chocolate3",
    "Chocolate4",
    "ColorType",
    "Coral",
    "Coral1",
    "Coral2",
    "Coral3",
    "Coral4",
    "CornflowerBlue",
    "Cornsilk",
    "Cornsilk1",
    "Cornsilk2",
    "Cornsilk3",
    "Cornsilk4",
    "Crimson",
    "Cyan",
    "Cyan1",
    "Cyan2",
    "Cyan3",
    "Cyan4",
    "DarkBlue",
    "DarkCyan",
    "DarkGoldenrod",
    "DarkGoldenrod1",
    "DarkGoldenrod2",
    "DarkGoldenrod3",
    "DarkGoldenrod4",
    "DarkGray",
    "DarkGreen",
    "DarkGrey",
    "DarkKhaki",
    "DarkMagenta",
    "DarkOliveGreen",
    "DarkOliveGreen1",
    "DarkOliveGreen2",
    "DarkOliveGreen3",
    "DarkOliveGreen4",
    "DarkOrange",
    "DarkOrange1",
    "DarkOrange2",
    "DarkOrange3",
    "DarkOrange4",
    "DarkOrchid",
    "DarkOrchid1",
    "DarkOrchid2",
    "DarkOrchid3",
    "DarkOrchid4",
    "DarkRed",
    "DarkSalmon",
    "DarkSeaGreen",
    "DarkSeaGreen1",
    "DarkSeaGreen2",
    "DarkSeaGreen3",
    "DarkSeaGreen4",
    "DarkSlateBlue",
    "DarkSlateGray",
    "DarkSlateGray1",
    "DarkSlateGray2",
    "DarkSlateGray3",
    "DarkSlateGray4",
    "DarkSlateGrey",
    "DarkTurquoise",
    "DarkViolet",
    "DeepPink",
    "DeepPink1",
    "DeepPink2",
    "DeepPink3",
    "DeepPink4",
    "DeepSkyBlue",
    "DeepSkyBlue1",
    "DeepSkyBlue2",
    "DeepSkyBlue3",
    "DeepSkyBlue4",
    "DimGray",
    "DimGrey",
    "DodgerBlue",
    "DodgerBlue1",
    "DodgerBlue2",
    "DodgerBlue3",
    "DodgerBlue4",
    "Firebrick",
    "Firebrick1",
    "Firebrick2",
    "Firebrick3",
    "Firebrick4",
    "FloralWhite",
    "ForestGreen",
    "Fuchsia",
    "Gainsboro",
    "GhostWhite",
    "Gold",
    "Gold1",
    "Gold2",
    "Gold3",
    "Gold4",
    "Goldenrod",
    "Goldenrod1",
    "Goldenrod2",
    "Goldenrod3",
    "Goldenrod4",
    "Gray",
    "Gray0",
    "Gray1",
    "Gray10",
    "Gray100",
    "Gray11",
    "Gray12",
    "Gray13",
    "Gray14",
    "Gray15",
    "Gray16",
    "Gray17",
    "Gray18",
    "Gray19",
    "Gray2",
    "Gray20",
    "Gray21",
    "Gray22",
    "Gray23",
    "Gray24",
    "Gray25",
    "Gray26",
    "Gray27",
    "Gray28",
    "Gray29",
    "Gray3",
    "Gray30",
    "Gray31",
    "Gray32",
    "Gray33",
    "Gray34",
    "Gray35",
    "Gray36",
    "Gray37",
    "Gray38",
    "Gray39",
    "Gray4",
    "Gray40",
    "Gray41",
    "Gray42",
    "Gray43",
    "Gray44",
    "Gray45",
    "Gray46",
    "Gray47",
    "Gray48",
    "Gray49",
    "Gray5",
    "Gray50",
    "Gray51",
    "Gray52",
    "Gray53",
    "Gray54",
    "Gray55",
    "Gray56",
    "Gray57",
    "Gray58",
    "Gray59",
    "Gray6",
    "Gray60",
    "Gray61",
    "Gray62",
    "Gray63",
    "Gray64",
    "Gray65",
    "Gray66",
    "Gray67",
    "Gray68",
    "Gray69",
    "Gray7",
    "Gray70",
    "Gray71",
    "Gray72",
    "Gray73",
    "Gray74",
    "Gray75",
    "Gray76",
    "Gray77",
    "Gray78",
    "Gray79",
    "Gray8",
    "Gray80",
    "Gray81",
    "Gray82",
    "Gray83",
    "Gray84",
    "Gray85",
    "Gray86",
    "Gray87",
    "Gray88",
    "Gray89",
    "Gray9",
    "Gray90",
    "Gray91",
    "Gray92",
    "Gray93",
    "Gray94",
    "Gray95",
    "Gray96",
    "Gray97",
    "Gray98",
    "Gray99",
    "Green",
    "Green1",
    "Green2",
    "Green3",
    "Green4",
    "GreenYellow",
    "Grey",
    "Grey0",
    "Grey1",
    "Grey10",
    "Grey100",
    "Grey11",
    "Grey12",
    "Grey13",
    "Grey14",
    "Grey15",
    "Grey16",
    "Grey17",
    "Grey18",
    "Grey19",
    "Grey2",
    "Grey20",
    "Grey21",
    "Grey22",
    "Grey23",
    "Grey24",
    "Grey25",
    "Grey26",
    "Grey27",
    "Grey28",
    "Grey29",
    "Grey3",
    "Grey30",
    "Grey31",
    "Grey32",
    "Grey33",
    "Grey34",
    "Grey35",
    "Grey36",
    "Grey37",
    "Grey38",
    "Grey39",
    "Grey4",
    "Grey40",
    "Grey41",
    "Grey42",
    "Grey43",
    "Grey44",
    "Grey45",
    "Grey46",
    "Grey47",
    "Grey48",
    "Grey49",
    "Grey5",
    "Grey50",
    "Grey51",
    "Grey52",
    "Grey53",
    "Grey54",
    "Grey55",
    "Grey56",
    "Grey57",
    "Grey58",
    "Grey59",
    "Grey6",
    "Grey60",
    "Grey61",
    "Grey62",
    "Grey63",
    "Grey64",
    "Grey65",
    "Grey66",
    "Grey67",
    "Grey68",
    "Grey69",
    "Grey7",
    "Grey70",
    "Grey71",
    "Grey72",
    "Grey73",
    "Grey74",
    "Grey75",
    "Grey76",
    "Grey77",
    "Grey78",
    "Grey79",
    "Grey8",
    "Grey80",
    "Grey81",
    "Grey82",
    "Grey83",
    "Grey84",
    "Grey85",
    "Grey86",
    "Grey87",
    "Grey88",
    "Grey89",
    "Grey9",
    "Grey90",
    "Grey91",
    "Grey92",
    "Grey93",
    "Grey94",
    "Grey95",
    "Grey96",
    "Grey97",
    "Grey98",
    "Grey99",
    "Honeydew",
    "Honeydew1",
    "Honeydew2",
    "Honeydew3",
    "Honeydew4",
    "HotPink",
    "HotPink1",
    "HotPink2",
    "HotPink3",
    "HotPink4",
    "IndianRed",
    "IndianRed1",
    "IndianRed2",
    "IndianRed3",
    "IndianRed4",
    "Indigo",
    "Ivory",
    "Ivory1",
    "Ivory2",
    "Ivory3",
    "Ivory4",
    "Khaki",
    "Khaki1",
    "Khaki2",
    "Khaki3",
    "Khaki4",
    "Lavender",
    "LavenderBlush",
    "LavenderBlush1",
    "LavenderBlush2",
    "LavenderBlush3",
    "LavenderBlush4",
    "LawnGreen",
    "LemonChiffon",
    "LemonChiffon1",
    "LemonChiffon2",
    "LemonChiffon3",
    "LemonChiffon4",
    "LightBlue",
    "LightBlue1",
    "LightBlue2",
    "LightBlue3",
    "LightBlue4",
    "LightCoral",
    "LightCyan",
    "LightCyan1",
    "LightCyan2",
    "LightCyan3",
    "LightCyan4",
    "LightGoldenrod",
    "LightGoldenrod1",
    "LightGoldenrod2",
    "LightGoldenrod3",
    "LightGoldenrod4",
    "LightGoldenrodYellow",
    "LightGray",
    "LightGreen",
    "LightGrey",
    "LightPink",
    "LightPink1",
    "LightPink2",
    "LightPink3",
    "LightPink4",
    "LightSalmon",
    "LightSalmon1",
    "LightSalmon2",
    "LightSalmon3",
    "LightSalmon4",
    "LightSeaGreen",
    "LightSkyBlue",
    "LightSkyBlue1",
    "LightSkyBlue2",
    "LightSkyBlue3",
    "LightSkyBlue4",
    "LightSlateBlue",
    "LightSlateGray",
    "LightSlateGrey",
    "LightSteelBlue",
    "LightSteelBlue1",
    "LightSteelBlue2",
    "LightSteelBlue3",
    "LightSteelBlue4",
    "LightYellow",
    "LightYellow1",
    "LightYellow2",
    "LightYellow3",
    "LightYellow4",
    "Lime",
    "LimeGreen",
    "Linen",
    "Magenta",
    "Magenta1",
    "Magenta2",
    "Magenta3",
    "Magenta4",
    "Maroon",
    "Maroon1",
    "Maroon2",
    "Maroon3",
    "Maroon4",
    "MediumAquamarine",
    "MediumBlue",
    "MediumOrchid",
    "MediumOrchid1",
    "MediumOrchid2",
    "MediumOrchid3",
    "MediumOrchid4",
    "MediumPurple",
    "MediumPurple1",
    "MediumPurple2",
    "MediumPurple3",
    "MediumPurple4",
    "MediumSeaGreen",
    "MediumSlateBlue",
    "MediumSpringGreen",
    "MediumTurquoise",
    "MediumVioletRed",
    "Memory",
    "MidnightBlue",
    "MintCream",
    "MistyRose",
    "MistyRose1",
    "MistyRose2",
    "MistyRose3",
    "MistyRose4",
    "Moccasin",
    "NavajoWhite",
    "NavajoWhite1",
    "NavajoWhite2",
    "NavajoWhite3",
    "NavajoWhite4",
    "Navy",
    "NavyBlue",
    "Number",
    "OldLace",
    "Olive",
    "OliveDrab",
    "OliveDrab1",
    "OliveDrab2",
    "OliveDrab3",
    "OliveDrab4",
    "Orange",
    "Orange1",
    "Orange2",
    "Orange3",
    "Orange4",
    "OrangeRed",
    "OrangeRed1",
    "OrangeRed2",
    "OrangeRed3",
    "OrangeRed4",
    "Orchid",
    "Orchid1",
    "Orchid2",
    "Orchid3",
    "Orchid4",
    "PaleGoldenrod",
    "PaleGreen",
    "PaleGreen1",
    "PaleGreen2",
    "PaleGreen3",
    "PaleGreen4",
    "PaleTurquoise",
    "PaleTurquoise1",
    "PaleTurquoise2",
    "PaleTurquoise3",
    "PaleTurquoise4",
    "PaleVioletRed",
    "PaleVioletRed1",
    "PaleVioletRed2",
    "PaleVioletRed3",
    "PaleVioletRed4",
    "PapayaWhip",
    "PeachPuff",
    "PeachPuff1",
    "PeachPuff2",
    "PeachPuff3",
    "PeachPuff4",
    "Percentage",
    "Peru",
    "Pink",
    "Pink1",
    "Pink2",
    "Pink3",
    "Pink4",
    "PlotFormatType",
    "Plum",
    "Plum1",
    "Plum2",
    "Plum3",
    "Plum4",
    "PowderBlue",
    "Purple",
    "Purple1",
    "Purple2",
    "Purple3",
    "Purple4",
    "RebeccaPurple",
    "Red",
    "Red1",
    "Red2",
    "Red3",
    "Red4",
    "RosyBrown",
    "RosyBrown1",
    "RosyBrown2",
    "RosyBrown3",
    "RosyBrown4",
    "RoyalBlue",
    "RoyalBlue1",
    "RoyalBlue2",
    "RoyalBlue3",
    "RoyalBlue4",
    "SaddleBrown",
    "Salmon",
    "Salmon1",
    "Salmon2",
    "Salmon3",
    "Salmon4",
    "SandyBrown",
    "SeaGreen",
    "SeaGreen1",
    "SeaGreen2",
    "SeaGreen3",
    "SeaGreen4",
    "Seashell",
    "Seashell1",
    "Seashell2",
    "Seashell3",
    "Seashell4",
    "Sienna",
    "Sienna1",
    "Sienna2",
    "Sienna3",
    "Sienna4",
    "Silver",
    "SkyBlue",
    "SkyBlue1",
    "SkyBlue2",
    "SkyBlue3",
    "SkyBlue4",
    "SlateBlue",
    "SlateBlue1",
    "SlateBlue2",
    "SlateBlue3",
    "SlateBlue4",
    "SlateGray",
    "SlateGray1",
    "SlateGray2",
    "SlateGray3",
    "SlateGray4",
    "SlateGrey",
    "Snow",
    "Snow1",
    "Snow2",
    "Snow3",
    "Snow4",
    "SpringGreen",
    "SpringGreen1",
    "SpringGreen2",
    "SpringGreen3",
    "SpringGreen4",
    "SteelBlue",
    "SteelBlue1",
    "SteelBlue2",
    "SteelBlue3",
    "SteelBlue4",
    "Tan",
    "Tan1",
    "Tan2",
    "Tan3",
    "Tan4",
    "Teal",
    "Thistle",
    "Thistle1",
    "Thistle2",
    "Thistle3",
    "Thistle4",
    "Tomato",
    "Tomato1",
    "Tomato2",
    "Tomato3",
    "Tomato4",
    "Turquoise",
    "Turquoise1",
    "Turquoise2",
    "Turquoise3",
    "Turquoise4",
    "Violet",
    "VioletRed",
    "VioletRed1",
    "VioletRed2",
    "VioletRed3",
    "VioletRed4",
    "WebGray",
    "WebGreen",
    "WebGrey",
    "WebMaroon",
    "WebPurple",
    "Wheat",
    "Wheat1",
    "Wheat2",
    "Wheat3",
    "Wheat4",
    "White",
    "WhiteSmoke",
    "X11Gray",
    "X11Green",
    "X11Grey",
    "X11Maroon",
    "X11Purple",
    "Yellow",
    "Yellow1",
    "Yellow2",
    "Yellow3",
    "Yellow4",
    "YellowGreen",
    "alloc",
    "app_info",
    "frame_image",
    "frame_mark",
    "frame_mark_end",
    "frame_mark_start",
    "free",
    "is_enabled",
    "message",
    "plot",
    "program_name",
    "thread_name"
]


class ColorType():
    """
    Members:

      Snow

      GhostWhite

      WhiteSmoke

      Gainsboro

      FloralWhite

      OldLace

      Linen

      AntiqueWhite

      PapayaWhip

      BlanchedAlmond

      Bisque

      PeachPuff

      NavajoWhite

      Moccasin

      Cornsilk

      Ivory

      LemonChiffon

      Seashell

      Honeydew

      MintCream

      Azure

      AliceBlue

      Lavender

      LavenderBlush

      MistyRose

      White

      Black

      DarkSlateGray

      DarkSlateGrey

      DimGray

      DimGrey

      SlateGray

      SlateGrey

      LightSlateGray

      LightSlateGrey

      Gray

      Grey

      X11Gray

      X11Grey

      WebGray

      WebGrey

      LightGrey

      LightGray

      MidnightBlue

      Navy

      NavyBlue

      CornflowerBlue

      DarkSlateBlue

      SlateBlue

      MediumSlateBlue

      LightSlateBlue

      MediumBlue

      RoyalBlue

      Blue

      DodgerBlue

      DeepSkyBlue

      SkyBlue

      LightSkyBlue

      SteelBlue

      LightSteelBlue

      LightBlue

      PowderBlue

      PaleTurquoise

      DarkTurquoise

      MediumTurquoise

      Turquoise

      Cyan

      Aqua

      LightCyan

      CadetBlue

      MediumAquamarine

      Aquamarine

      DarkGreen

      DarkOliveGreen

      DarkSeaGreen

      SeaGreen

      MediumSeaGreen

      LightSeaGreen

      PaleGreen

      SpringGreen

      LawnGreen

      Green

      Lime

      X11Green

      WebGreen

      Chartreuse

      MediumSpringGreen

      GreenYellow

      LimeGreen

      YellowGreen

      ForestGreen

      OliveDrab

      DarkKhaki

      Khaki

      PaleGoldenrod

      LightGoldenrodYellow

      LightYellow

      Yellow

      Gold

      LightGoldenrod

      Goldenrod

      DarkGoldenrod

      RosyBrown

      IndianRed

      SaddleBrown

      Sienna

      Peru

      Burlywood

      Beige

      Wheat

      SandyBrown

      Tan

      Chocolate

      Firebrick

      Brown

      DarkSalmon

      Salmon

      LightSalmon

      Orange

      DarkOrange

      Coral

      LightCoral

      Tomato

      OrangeRed

      Red

      HotPink

      DeepPink

      Pink

      LightPink

      PaleVioletRed

      Maroon

      X11Maroon

      WebMaroon

      MediumVioletRed

      VioletRed

      Magenta

      Fuchsia

      Violet

      Plum

      Orchid

      MediumOrchid

      DarkOrchid

      DarkViolet

      BlueViolet

      Purple

      X11Purple

      WebPurple

      MediumPurple

      Thistle

      Snow1

      Snow2

      Snow3

      Snow4

      Seashell1

      Seashell2

      Seashell3

      Seashell4

      AntiqueWhite1

      AntiqueWhite2

      AntiqueWhite3

      AntiqueWhite4

      Bisque1

      Bisque2

      Bisque3

      Bisque4

      PeachPuff1

      PeachPuff2

      PeachPuff3

      PeachPuff4

      NavajoWhite1

      NavajoWhite2

      NavajoWhite3

      NavajoWhite4

      LemonChiffon1

      LemonChiffon2

      LemonChiffon3

      LemonChiffon4

      Cornsilk1

      Cornsilk2

      Cornsilk3

      Cornsilk4

      Ivory1

      Ivory2

      Ivory3

      Ivory4

      Honeydew1

      Honeydew2

      Honeydew3

      Honeydew4

      LavenderBlush1

      LavenderBlush2

      LavenderBlush3

      LavenderBlush4

      MistyRose1

      MistyRose2

      MistyRose3

      MistyRose4

      Azure1

      Azure2

      Azure3

      Azure4

      SlateBlue1

      SlateBlue2

      SlateBlue3

      SlateBlue4

      RoyalBlue1

      RoyalBlue2

      RoyalBlue3

      RoyalBlue4

      Blue1

      Blue2

      Blue3

      Blue4

      DodgerBlue1

      DodgerBlue2

      DodgerBlue3

      DodgerBlue4

      SteelBlue1

      SteelBlue2

      SteelBlue3

      SteelBlue4

      DeepSkyBlue1

      DeepSkyBlue2

      DeepSkyBlue3

      DeepSkyBlue4

      SkyBlue1

      SkyBlue2

      SkyBlue3

      SkyBlue4

      LightSkyBlue1

      LightSkyBlue2

      LightSkyBlue3

      LightSkyBlue4

      SlateGray1

      SlateGray2

      SlateGray3

      SlateGray4

      LightSteelBlue1

      LightSteelBlue2

      LightSteelBlue3

      LightSteelBlue4

      LightBlue1

      LightBlue2

      LightBlue3

      LightBlue4

      LightCyan1

      LightCyan2

      LightCyan3

      LightCyan4

      PaleTurquoise1

      PaleTurquoise2

      PaleTurquoise3

      PaleTurquoise4

      CadetBlue1

      CadetBlue2

      CadetBlue3

      CadetBlue4

      Turquoise1

      Turquoise2

      Turquoise3

      Turquoise4

      Cyan1

      Cyan2

      Cyan3

      Cyan4

      DarkSlateGray1

      DarkSlateGray2

      DarkSlateGray3

      DarkSlateGray4

      Aquamarine1

      Aquamarine2

      Aquamarine3

      Aquamarine4

      DarkSeaGreen1

      DarkSeaGreen2

      DarkSeaGreen3

      DarkSeaGreen4

      SeaGreen1

      SeaGreen2

      SeaGreen3

      SeaGreen4

      PaleGreen1

      PaleGreen2

      PaleGreen3

      PaleGreen4

      SpringGreen1

      SpringGreen2

      SpringGreen3

      SpringGreen4

      Green1

      Green2

      Green3

      Green4

      Chartreuse1

      Chartreuse2

      Chartreuse3

      Chartreuse4

      OliveDrab1

      OliveDrab2

      OliveDrab3

      OliveDrab4

      DarkOliveGreen1

      DarkOliveGreen2

      DarkOliveGreen3

      DarkOliveGreen4

      Khaki1

      Khaki2

      Khaki3

      Khaki4

      LightGoldenrod1

      LightGoldenrod2

      LightGoldenrod3

      LightGoldenrod4

      LightYellow1

      LightYellow2

      LightYellow3

      LightYellow4

      Yellow1

      Yellow2

      Yellow3

      Yellow4

      Gold1

      Gold2

      Gold3

      Gold4

      Goldenrod1

      Goldenrod2

      Goldenrod3

      Goldenrod4

      DarkGoldenrod1

      DarkGoldenrod2

      DarkGoldenrod3

      DarkGoldenrod4

      RosyBrown1

      RosyBrown2

      RosyBrown3

      RosyBrown4

      IndianRed1

      IndianRed2

      IndianRed3

      IndianRed4

      Sienna1

      Sienna2

      Sienna3

      Sienna4

      Burlywood1

      Burlywood2

      Burlywood3

      Burlywood4

      Wheat1

      Wheat2

      Wheat3

      Wheat4

      Tan1

      Tan2

      Tan3

      Tan4

      Chocolate1

      Chocolate2

      Chocolate3

      Chocolate4

      Firebrick1

      Firebrick2

      Firebrick3

      Firebrick4

      Brown1

      Brown2

      Brown3

      Brown4

      Salmon1

      Salmon2

      Salmon3

      Salmon4

      LightSalmon1

      LightSalmon2

      LightSalmon3

      LightSalmon4

      Orange1

      Orange2

      Orange3

      Orange4

      DarkOrange1

      DarkOrange2

      DarkOrange3

      DarkOrange4

      Coral1

      Coral2

      Coral3

      Coral4

      Tomato1

      Tomato2

      Tomato3

      Tomato4

      OrangeRed1

      OrangeRed2

      OrangeRed3

      OrangeRed4

      Red1

      Red2

      Red3

      Red4

      DeepPink1

      DeepPink2

      DeepPink3

      DeepPink4

      HotPink1

      HotPink2

      HotPink3

      HotPink4

      Pink1

      Pink2

      Pink3

      Pink4

      LightPink1

      LightPink2

      LightPink3

      LightPink4

      PaleVioletRed1

      PaleVioletRed2

      PaleVioletRed3

      PaleVioletRed4

      Maroon1

      Maroon2

      Maroon3

      Maroon4

      VioletRed1

      VioletRed2

      VioletRed3

      VioletRed4

      Magenta1

      Magenta2

      Magenta3

      Magenta4

      Orchid1

      Orchid2

      Orchid3

      Orchid4

      Plum1

      Plum2

      Plum3

      Plum4

      MediumOrchid1

      MediumOrchid2

      MediumOrchid3

      MediumOrchid4

      DarkOrchid1

      DarkOrchid2

      DarkOrchid3

      DarkOrchid4

      Purple1

      Purple2

      Purple3

      Purple4

      MediumPurple1

      MediumPurple2

      MediumPurple3

      MediumPurple4

      Thistle1

      Thistle2

      Thistle3

      Thistle4

      Gray0

      Grey0

      Gray1

      Grey1

      Gray2

      Grey2

      Gray3

      Grey3

      Gray4

      Grey4

      Gray5

      Grey5

      Gray6

      Grey6

      Gray7

      Grey7

      Gray8

      Grey8

      Gray9

      Grey9

      Gray10

      Grey10

      Gray11

      Grey11

      Gray12

      Grey12

      Gray13

      Grey13

      Gray14

      Grey14

      Gray15

      Grey15

      Gray16

      Grey16

      Gray17

      Grey17

      Gray18

      Grey18

      Gray19

      Grey19

      Gray20

      Grey20

      Gray21

      Grey21

      Gray22

      Grey22

      Gray23

      Grey23

      Gray24

      Grey24

      Gray25

      Grey25

      Gray26

      Grey26

      Gray27

      Grey27

      Gray28

      Grey28

      Gray29

      Grey29

      Gray30

      Grey30

      Gray31

      Grey31

      Gray32

      Grey32

      Gray33

      Grey33

      Gray34

      Grey34

      Gray35

      Grey35

      Gray36

      Grey36

      Gray37

      Grey37

      Gray38

      Grey38

      Gray39

      Grey39

      Gray40

      Grey40

      Gray41

      Grey41

      Gray42

      Grey42

      Gray43

      Grey43

      Gray44

      Grey44

      Gray45

      Grey45

      Gray46

      Grey46

      Gray47

      Grey47

      Gray48

      Grey48

      Gray49

      Grey49

      Gray50

      Grey50

      Gray51

      Grey51

      Gray52

      Grey52

      Gray53

      Grey53

      Gray54

      Grey54

      Gray55

      Grey55

      Gray56

      Grey56

      Gray57

      Grey57

      Gray58

      Grey58

      Gray59

      Grey59

      Gray60

      Grey60

      Gray61

      Grey61

      Gray62

      Grey62

      Gray63

      Grey63

      Gray64

      Grey64

      Gray65

      Grey65

      Gray66

      Grey66

      Gray67

      Grey67

      Gray68

      Grey68

      Gray69

      Grey69

      Gray70

      Grey70

      Gray71

      Grey71

      Gray72

      Grey72

      Gray73

      Grey73

      Gray74

      Grey74

      Gray75

      Grey75

      Gray76

      Grey76

      Gray77

      Grey77

      Gray78

      Grey78

      Gray79

      Grey79

      Gray80

      Grey80

      Gray81

      Grey81

      Gray82

      Grey82

      Gray83

      Grey83

      Gray84

      Grey84

      Gray85

      Grey85

      Gray86

      Grey86

      Gray87

      Grey87

      Gray88

      Grey88

      Gray89

      Grey89

      Gray90

      Grey90

      Gray91

      Grey91

      Gray92

      Grey92

      Gray93

      Grey93

      Gray94

      Grey94

      Gray95

      Grey95

      Gray96

      Grey96

      Gray97

      Grey97

      Gray98

      Grey98

      Gray99

      Grey99

      Gray100

      Grey100

      DarkGrey

      DarkGray

      DarkBlue

      DarkCyan

      DarkMagenta

      DarkRed

      LightGreen

      Crimson

      Indigo

      Olive

      RebeccaPurple

      Silver

      Teal
    """
    def __eq__(self, other: object) -> bool: ...
    def __getstate__(self) -> int: ...
    def __hash__(self) -> int: ...
    def __index__(self) -> int: ...
    def __init__(self, value: int) -> None: ...
    def __int__(self) -> int: ...
    def __ne__(self, other: object) -> bool: ...
    def __repr__(self) -> str: ...
    def __setstate__(self, state: int) -> None: ...
    @property
    def name(self) -> str:
        """
        :type: str
        """
    @property
    def value(self) -> int:
        """
        :type: int
        """
    AliceBlue: TracyClientBindings.ColorType # value = <ColorType.AliceBlue: 15792383>
    AntiqueWhite: TracyClientBindings.ColorType # value = <ColorType.AntiqueWhite: 16444375>
    AntiqueWhite1: TracyClientBindings.ColorType # value = <ColorType.AntiqueWhite1: 16773083>
    AntiqueWhite2: TracyClientBindings.ColorType # value = <ColorType.AntiqueWhite2: 15654860>
    AntiqueWhite3: TracyClientBindings.ColorType # value = <ColorType.AntiqueWhite3: 13484208>
    AntiqueWhite4: TracyClientBindings.ColorType # value = <ColorType.AntiqueWhite4: 9143160>
    Aqua: TracyClientBindings.ColorType # value = <ColorType.Cyan: 65535>
    Aquamarine: TracyClientBindings.ColorType # value = <ColorType.Aquamarine: 8388564>
    Aquamarine1: TracyClientBindings.ColorType # value = <ColorType.Aquamarine: 8388564>
    Aquamarine2: TracyClientBindings.ColorType # value = <ColorType.Aquamarine2: 7794374>
    Aquamarine3: TracyClientBindings.ColorType # value = <ColorType.MediumAquamarine: 6737322>
    Aquamarine4: TracyClientBindings.ColorType # value = <ColorType.Aquamarine4: 4557684>
    Azure: TracyClientBindings.ColorType # value = <ColorType.Azure: 15794175>
    Azure1: TracyClientBindings.ColorType # value = <ColorType.Azure: 15794175>
    Azure2: TracyClientBindings.ColorType # value = <ColorType.Azure2: 14741230>
    Azure3: TracyClientBindings.ColorType # value = <ColorType.Azure3: 12701133>
    Azure4: TracyClientBindings.ColorType # value = <ColorType.Azure4: 8620939>
    Beige: TracyClientBindings.ColorType # value = <ColorType.Beige: 16119260>
    Bisque: TracyClientBindings.ColorType # value = <ColorType.Bisque: 16770244>
    Bisque1: TracyClientBindings.ColorType # value = <ColorType.Bisque: 16770244>
    Bisque2: TracyClientBindings.ColorType # value = <ColorType.Bisque2: 15652279>
    Bisque3: TracyClientBindings.ColorType # value = <ColorType.Bisque3: 13481886>
    Bisque4: TracyClientBindings.ColorType # value = <ColorType.Bisque4: 9141611>
    Black: TracyClientBindings.ColorType # value = <ColorType.Black: 0>
    BlanchedAlmond: TracyClientBindings.ColorType # value = <ColorType.BlanchedAlmond: 16772045>
    Blue: TracyClientBindings.ColorType # value = <ColorType.Blue: 255>
    Blue1: TracyClientBindings.ColorType # value = <ColorType.Blue: 255>
    Blue2: TracyClientBindings.ColorType # value = <ColorType.Blue2: 238>
    Blue3: TracyClientBindings.ColorType # value = <ColorType.MediumBlue: 205>
    Blue4: TracyClientBindings.ColorType # value = <ColorType.Blue4: 139>
    BlueViolet: TracyClientBindings.ColorType # value = <ColorType.BlueViolet: 9055202>
    Brown: TracyClientBindings.ColorType # value = <ColorType.Brown: 10824234>
    Brown1: TracyClientBindings.ColorType # value = <ColorType.Brown1: 16728128>
    Brown2: TracyClientBindings.ColorType # value = <ColorType.Brown2: 15612731>
    Brown3: TracyClientBindings.ColorType # value = <ColorType.Brown3: 13447987>
    Brown4: TracyClientBindings.ColorType # value = <ColorType.Brown4: 9118499>
    Burlywood: TracyClientBindings.ColorType # value = <ColorType.Burlywood: 14596231>
    Burlywood1: TracyClientBindings.ColorType # value = <ColorType.Burlywood1: 16765851>
    Burlywood2: TracyClientBindings.ColorType # value = <ColorType.Burlywood2: 15648145>
    Burlywood3: TracyClientBindings.ColorType # value = <ColorType.Burlywood3: 13478525>
    Burlywood4: TracyClientBindings.ColorType # value = <ColorType.Burlywood4: 9139029>
    CadetBlue: TracyClientBindings.ColorType # value = <ColorType.CadetBlue: 6266528>
    CadetBlue1: TracyClientBindings.ColorType # value = <ColorType.CadetBlue1: 10024447>
    CadetBlue2: TracyClientBindings.ColorType # value = <ColorType.CadetBlue2: 9364974>
    CadetBlue3: TracyClientBindings.ColorType # value = <ColorType.CadetBlue3: 8046029>
    CadetBlue4: TracyClientBindings.ColorType # value = <ColorType.CadetBlue4: 5473931>
    Chartreuse: TracyClientBindings.ColorType # value = <ColorType.Chartreuse: 8388352>
    Chartreuse1: TracyClientBindings.ColorType # value = <ColorType.Chartreuse: 8388352>
    Chartreuse2: TracyClientBindings.ColorType # value = <ColorType.Chartreuse2: 7794176>
    Chartreuse3: TracyClientBindings.ColorType # value = <ColorType.Chartreuse3: 6737152>
    Chartreuse4: TracyClientBindings.ColorType # value = <ColorType.Chartreuse4: 4557568>
    Chocolate: TracyClientBindings.ColorType # value = <ColorType.Chocolate: 13789470>
    Chocolate1: TracyClientBindings.ColorType # value = <ColorType.Chocolate1: 16744228>
    Chocolate2: TracyClientBindings.ColorType # value = <ColorType.Chocolate2: 15627809>
    Chocolate3: TracyClientBindings.ColorType # value = <ColorType.Chocolate3: 13461021>
    Chocolate4: TracyClientBindings.ColorType # value = <ColorType.SaddleBrown: 9127187>
    Coral: TracyClientBindings.ColorType # value = <ColorType.Coral: 16744272>
    Coral1: TracyClientBindings.ColorType # value = <ColorType.Coral1: 16740950>
    Coral2: TracyClientBindings.ColorType # value = <ColorType.Coral2: 15624784>
    Coral3: TracyClientBindings.ColorType # value = <ColorType.Coral3: 13458245>
    Coral4: TracyClientBindings.ColorType # value = <ColorType.Coral4: 9125423>
    CornflowerBlue: TracyClientBindings.ColorType # value = <ColorType.CornflowerBlue: 6591981>
    Cornsilk: TracyClientBindings.ColorType # value = <ColorType.Cornsilk: 16775388>
    Cornsilk1: TracyClientBindings.ColorType # value = <ColorType.Cornsilk: 16775388>
    Cornsilk2: TracyClientBindings.ColorType # value = <ColorType.Cornsilk2: 15657165>
    Cornsilk3: TracyClientBindings.ColorType # value = <ColorType.Cornsilk3: 13486257>
    Cornsilk4: TracyClientBindings.ColorType # value = <ColorType.Cornsilk4: 9144440>
    Crimson: TracyClientBindings.ColorType # value = <ColorType.Crimson: 14423100>
    Cyan: TracyClientBindings.ColorType # value = <ColorType.Cyan: 65535>
    Cyan1: TracyClientBindings.ColorType # value = <ColorType.Cyan: 65535>
    Cyan2: TracyClientBindings.ColorType # value = <ColorType.Cyan2: 61166>
    Cyan3: TracyClientBindings.ColorType # value = <ColorType.Cyan3: 52685>
    Cyan4: TracyClientBindings.ColorType # value = <ColorType.Cyan4: 35723>
    DarkBlue: TracyClientBindings.ColorType # value = <ColorType.Blue4: 139>
    DarkCyan: TracyClientBindings.ColorType # value = <ColorType.Cyan4: 35723>
    DarkGoldenrod: TracyClientBindings.ColorType # value = <ColorType.DarkGoldenrod: 12092939>
    DarkGoldenrod1: TracyClientBindings.ColorType # value = <ColorType.DarkGoldenrod1: 16759055>
    DarkGoldenrod2: TracyClientBindings.ColorType # value = <ColorType.DarkGoldenrod2: 15641870>
    DarkGoldenrod3: TracyClientBindings.ColorType # value = <ColorType.DarkGoldenrod3: 13473036>
    DarkGoldenrod4: TracyClientBindings.ColorType # value = <ColorType.DarkGoldenrod4: 9135368>
    DarkGray: TracyClientBindings.ColorType # value = <ColorType.DarkGrey: 11119017>
    DarkGreen: TracyClientBindings.ColorType # value = <ColorType.DarkGreen: 25600>
    DarkGrey: TracyClientBindings.ColorType # value = <ColorType.DarkGrey: 11119017>
    DarkKhaki: TracyClientBindings.ColorType # value = <ColorType.DarkKhaki: 12433259>
    DarkMagenta: TracyClientBindings.ColorType # value = <ColorType.Magenta4: 9109643>
    DarkOliveGreen: TracyClientBindings.ColorType # value = <ColorType.DarkOliveGreen: 5597999>
    DarkOliveGreen1: TracyClientBindings.ColorType # value = <ColorType.DarkOliveGreen1: 13303664>
    DarkOliveGreen2: TracyClientBindings.ColorType # value = <ColorType.DarkOliveGreen2: 12381800>
    DarkOliveGreen3: TracyClientBindings.ColorType # value = <ColorType.DarkOliveGreen3: 10669402>
    DarkOliveGreen4: TracyClientBindings.ColorType # value = <ColorType.DarkOliveGreen4: 7244605>
    DarkOrange: TracyClientBindings.ColorType # value = <ColorType.DarkOrange: 16747520>
    DarkOrange1: TracyClientBindings.ColorType # value = <ColorType.DarkOrange1: 16744192>
    DarkOrange2: TracyClientBindings.ColorType # value = <ColorType.DarkOrange2: 15627776>
    DarkOrange3: TracyClientBindings.ColorType # value = <ColorType.DarkOrange3: 13460992>
    DarkOrange4: TracyClientBindings.ColorType # value = <ColorType.DarkOrange4: 9127168>
    DarkOrchid: TracyClientBindings.ColorType # value = <ColorType.DarkOrchid: 10040012>
    DarkOrchid1: TracyClientBindings.ColorType # value = <ColorType.DarkOrchid1: 12533503>
    DarkOrchid2: TracyClientBindings.ColorType # value = <ColorType.DarkOrchid2: 11680494>
    DarkOrchid3: TracyClientBindings.ColorType # value = <ColorType.DarkOrchid3: 10105549>
    DarkOrchid4: TracyClientBindings.ColorType # value = <ColorType.DarkOrchid4: 6824587>
    DarkRed: TracyClientBindings.ColorType # value = <ColorType.Red4: 9109504>
    DarkSalmon: TracyClientBindings.ColorType # value = <ColorType.DarkSalmon: 15308410>
    DarkSeaGreen: TracyClientBindings.ColorType # value = <ColorType.DarkSeaGreen: 9419919>
    DarkSeaGreen1: TracyClientBindings.ColorType # value = <ColorType.DarkSeaGreen1: 12713921>
    DarkSeaGreen2: TracyClientBindings.ColorType # value = <ColorType.DarkSeaGreen2: 11857588>
    DarkSeaGreen3: TracyClientBindings.ColorType # value = <ColorType.DarkSeaGreen3: 10210715>
    DarkSeaGreen4: TracyClientBindings.ColorType # value = <ColorType.DarkSeaGreen4: 6916969>
    DarkSlateBlue: TracyClientBindings.ColorType # value = <ColorType.DarkSlateBlue: 4734347>
    DarkSlateGray: TracyClientBindings.ColorType # value = <ColorType.DarkSlateGray: 3100495>
    DarkSlateGray1: TracyClientBindings.ColorType # value = <ColorType.DarkSlateGray1: 9961471>
    DarkSlateGray2: TracyClientBindings.ColorType # value = <ColorType.DarkSlateGray2: 9301742>
    DarkSlateGray3: TracyClientBindings.ColorType # value = <ColorType.DarkSlateGray3: 7982541>
    DarkSlateGray4: TracyClientBindings.ColorType # value = <ColorType.DarkSlateGray4: 5409675>
    DarkSlateGrey: TracyClientBindings.ColorType # value = <ColorType.DarkSlateGray: 3100495>
    DarkTurquoise: TracyClientBindings.ColorType # value = <ColorType.DarkTurquoise: 52945>
    DarkViolet: TracyClientBindings.ColorType # value = <ColorType.DarkViolet: 9699539>
    DeepPink: TracyClientBindings.ColorType # value = <ColorType.DeepPink: 16716947>
    DeepPink1: TracyClientBindings.ColorType # value = <ColorType.DeepPink: 16716947>
    DeepPink2: TracyClientBindings.ColorType # value = <ColorType.DeepPink2: 15602313>
    DeepPink3: TracyClientBindings.ColorType # value = <ColorType.DeepPink3: 13439094>
    DeepPink4: TracyClientBindings.ColorType # value = <ColorType.DeepPink4: 9112144>
    DeepSkyBlue: TracyClientBindings.ColorType # value = <ColorType.DeepSkyBlue: 49151>
    DeepSkyBlue1: TracyClientBindings.ColorType # value = <ColorType.DeepSkyBlue: 49151>
    DeepSkyBlue2: TracyClientBindings.ColorType # value = <ColorType.DeepSkyBlue2: 45806>
    DeepSkyBlue3: TracyClientBindings.ColorType # value = <ColorType.DeepSkyBlue3: 39629>
    DeepSkyBlue4: TracyClientBindings.ColorType # value = <ColorType.DeepSkyBlue4: 26763>
    DimGray: TracyClientBindings.ColorType # value = <ColorType.DimGray: 6908265>
    DimGrey: TracyClientBindings.ColorType # value = <ColorType.DimGray: 6908265>
    DodgerBlue: TracyClientBindings.ColorType # value = <ColorType.DodgerBlue: 2003199>
    DodgerBlue1: TracyClientBindings.ColorType # value = <ColorType.DodgerBlue: 2003199>
    DodgerBlue2: TracyClientBindings.ColorType # value = <ColorType.DodgerBlue2: 1869550>
    DodgerBlue3: TracyClientBindings.ColorType # value = <ColorType.DodgerBlue3: 1602765>
    DodgerBlue4: TracyClientBindings.ColorType # value = <ColorType.DodgerBlue4: 1068683>
    Firebrick: TracyClientBindings.ColorType # value = <ColorType.Firebrick: 11674146>
    Firebrick1: TracyClientBindings.ColorType # value = <ColorType.Firebrick1: 16724016>
    Firebrick2: TracyClientBindings.ColorType # value = <ColorType.Firebrick2: 15608876>
    Firebrick3: TracyClientBindings.ColorType # value = <ColorType.Firebrick3: 13444646>
    Firebrick4: TracyClientBindings.ColorType # value = <ColorType.Firebrick4: 9116186>
    FloralWhite: TracyClientBindings.ColorType # value = <ColorType.FloralWhite: 16775920>
    ForestGreen: TracyClientBindings.ColorType # value = <ColorType.ForestGreen: 2263842>
    Fuchsia: TracyClientBindings.ColorType # value = <ColorType.Magenta: 16711935>
    Gainsboro: TracyClientBindings.ColorType # value = <ColorType.Gainsboro: 14474460>
    GhostWhite: TracyClientBindings.ColorType # value = <ColorType.GhostWhite: 16316671>
    Gold: TracyClientBindings.ColorType # value = <ColorType.Gold: 16766720>
    Gold1: TracyClientBindings.ColorType # value = <ColorType.Gold: 16766720>
    Gold2: TracyClientBindings.ColorType # value = <ColorType.Gold2: 15649024>
    Gold3: TracyClientBindings.ColorType # value = <ColorType.Gold3: 13479168>
    Gold4: TracyClientBindings.ColorType # value = <ColorType.Gold4: 9139456>
    Goldenrod: TracyClientBindings.ColorType # value = <ColorType.Goldenrod: 14329120>
    Goldenrod1: TracyClientBindings.ColorType # value = <ColorType.Goldenrod1: 16761125>
    Goldenrod2: TracyClientBindings.ColorType # value = <ColorType.Goldenrod2: 15643682>
    Goldenrod3: TracyClientBindings.ColorType # value = <ColorType.Goldenrod3: 13474589>
    Goldenrod4: TracyClientBindings.ColorType # value = <ColorType.Goldenrod4: 9136404>
    Gray: TracyClientBindings.ColorType # value = <ColorType.Gray: 12500670>
    Gray0: TracyClientBindings.ColorType # value = <ColorType.Black: 0>
    Gray1: TracyClientBindings.ColorType # value = <ColorType.Gray1: 197379>
    Gray10: TracyClientBindings.ColorType # value = <ColorType.Gray10: 1710618>
    Gray100: TracyClientBindings.ColorType # value = <ColorType.White: 16777215>
    Gray11: TracyClientBindings.ColorType # value = <ColorType.Gray11: 1842204>
    Gray12: TracyClientBindings.ColorType # value = <ColorType.Gray12: 2039583>
    Gray13: TracyClientBindings.ColorType # value = <ColorType.Gray13: 2171169>
    Gray14: TracyClientBindings.ColorType # value = <ColorType.Gray14: 2368548>
    Gray15: TracyClientBindings.ColorType # value = <ColorType.Gray15: 2500134>
    Gray16: TracyClientBindings.ColorType # value = <ColorType.Gray16: 2697513>
    Gray17: TracyClientBindings.ColorType # value = <ColorType.Gray17: 2829099>
    Gray18: TracyClientBindings.ColorType # value = <ColorType.Gray18: 3026478>
    Gray19: TracyClientBindings.ColorType # value = <ColorType.Gray19: 3158064>
    Gray2: TracyClientBindings.ColorType # value = <ColorType.Gray2: 328965>
    Gray20: TracyClientBindings.ColorType # value = <ColorType.Gray20: 3355443>
    Gray21: TracyClientBindings.ColorType # value = <ColorType.Gray21: 3552822>
    Gray22: TracyClientBindings.ColorType # value = <ColorType.Gray22: 3684408>
    Gray23: TracyClientBindings.ColorType # value = <ColorType.Gray23: 3881787>
    Gray24: TracyClientBindings.ColorType # value = <ColorType.Gray24: 4013373>
    Gray25: TracyClientBindings.ColorType # value = <ColorType.Gray25: 4210752>
    Gray26: TracyClientBindings.ColorType # value = <ColorType.Gray26: 4342338>
    Gray27: TracyClientBindings.ColorType # value = <ColorType.Gray27: 4539717>
    Gray28: TracyClientBindings.ColorType # value = <ColorType.Gray28: 4671303>
    Gray29: TracyClientBindings.ColorType # value = <ColorType.Gray29: 4868682>
    Gray3: TracyClientBindings.ColorType # value = <ColorType.Gray3: 526344>
    Gray30: TracyClientBindings.ColorType # value = <ColorType.Gray30: 5066061>
    Gray31: TracyClientBindings.ColorType # value = <ColorType.Gray31: 5197647>
    Gray32: TracyClientBindings.ColorType # value = <ColorType.Gray32: 5395026>
    Gray33: TracyClientBindings.ColorType # value = <ColorType.Gray33: 5526612>
    Gray34: TracyClientBindings.ColorType # value = <ColorType.Gray34: 5723991>
    Gray35: TracyClientBindings.ColorType # value = <ColorType.Gray35: 5855577>
    Gray36: TracyClientBindings.ColorType # value = <ColorType.Gray36: 6052956>
    Gray37: TracyClientBindings.ColorType # value = <ColorType.Gray37: 6184542>
    Gray38: TracyClientBindings.ColorType # value = <ColorType.Gray38: 6381921>
    Gray39: TracyClientBindings.ColorType # value = <ColorType.Gray39: 6513507>
    Gray4: TracyClientBindings.ColorType # value = <ColorType.Gray4: 657930>
    Gray40: TracyClientBindings.ColorType # value = <ColorType.Gray40: 6710886>
    Gray41: TracyClientBindings.ColorType # value = <ColorType.DimGray: 6908265>
    Gray42: TracyClientBindings.ColorType # value = <ColorType.Gray42: 7039851>
    Gray43: TracyClientBindings.ColorType # value = <ColorType.Gray43: 7237230>
    Gray44: TracyClientBindings.ColorType # value = <ColorType.Gray44: 7368816>
    Gray45: TracyClientBindings.ColorType # value = <ColorType.Gray45: 7566195>
    Gray46: TracyClientBindings.ColorType # value = <ColorType.Gray46: 7697781>
    Gray47: TracyClientBindings.ColorType # value = <ColorType.Gray47: 7895160>
    Gray48: TracyClientBindings.ColorType # value = <ColorType.Gray48: 8026746>
    Gray49: TracyClientBindings.ColorType # value = <ColorType.Gray49: 8224125>
    Gray5: TracyClientBindings.ColorType # value = <ColorType.Gray5: 855309>
    Gray50: TracyClientBindings.ColorType # value = <ColorType.Gray50: 8355711>
    Gray51: TracyClientBindings.ColorType # value = <ColorType.Gray51: 8553090>
    Gray52: TracyClientBindings.ColorType # value = <ColorType.Gray52: 8750469>
    Gray53: TracyClientBindings.ColorType # value = <ColorType.Gray53: 8882055>
    Gray54: TracyClientBindings.ColorType # value = <ColorType.Gray54: 9079434>
    Gray55: TracyClientBindings.ColorType # value = <ColorType.Gray55: 9211020>
    Gray56: TracyClientBindings.ColorType # value = <ColorType.Gray56: 9408399>
    Gray57: TracyClientBindings.ColorType # value = <ColorType.Gray57: 9539985>
    Gray58: TracyClientBindings.ColorType # value = <ColorType.Gray58: 9737364>
    Gray59: TracyClientBindings.ColorType # value = <ColorType.Gray59: 9868950>
    Gray6: TracyClientBindings.ColorType # value = <ColorType.Gray6: 986895>
    Gray60: TracyClientBindings.ColorType # value = <ColorType.Gray60: 10066329>
    Gray61: TracyClientBindings.ColorType # value = <ColorType.Gray61: 10263708>
    Gray62: TracyClientBindings.ColorType # value = <ColorType.Gray62: 10395294>
    Gray63: TracyClientBindings.ColorType # value = <ColorType.Gray63: 10592673>
    Gray64: TracyClientBindings.ColorType # value = <ColorType.Gray64: 10724259>
    Gray65: TracyClientBindings.ColorType # value = <ColorType.Gray65: 10921638>
    Gray66: TracyClientBindings.ColorType # value = <ColorType.Gray66: 11053224>
    Gray67: TracyClientBindings.ColorType # value = <ColorType.Gray67: 11250603>
    Gray68: TracyClientBindings.ColorType # value = <ColorType.Gray68: 11382189>
    Gray69: TracyClientBindings.ColorType # value = <ColorType.Gray69: 11579568>
    Gray7: TracyClientBindings.ColorType # value = <ColorType.Gray7: 1184274>
    Gray70: TracyClientBindings.ColorType # value = <ColorType.Gray70: 11776947>
    Gray71: TracyClientBindings.ColorType # value = <ColorType.Gray71: 11908533>
    Gray72: TracyClientBindings.ColorType # value = <ColorType.Gray72: 12105912>
    Gray73: TracyClientBindings.ColorType # value = <ColorType.Gray73: 12237498>
    Gray74: TracyClientBindings.ColorType # value = <ColorType.Gray74: 12434877>
    Gray75: TracyClientBindings.ColorType # value = <ColorType.Gray75: 12566463>
    Gray76: TracyClientBindings.ColorType # value = <ColorType.Gray76: 12763842>
    Gray77: TracyClientBindings.ColorType # value = <ColorType.Gray77: 12895428>
    Gray78: TracyClientBindings.ColorType # value = <ColorType.Gray78: 13092807>
    Gray79: TracyClientBindings.ColorType # value = <ColorType.Gray79: 13224393>
    Gray8: TracyClientBindings.ColorType # value = <ColorType.Gray8: 1315860>
    Gray80: TracyClientBindings.ColorType # value = <ColorType.Gray80: 13421772>
    Gray81: TracyClientBindings.ColorType # value = <ColorType.Gray81: 13619151>
    Gray82: TracyClientBindings.ColorType # value = <ColorType.Gray82: 13750737>
    Gray83: TracyClientBindings.ColorType # value = <ColorType.Gray83: 13948116>
    Gray84: TracyClientBindings.ColorType # value = <ColorType.Gray84: 14079702>
    Gray85: TracyClientBindings.ColorType # value = <ColorType.Gray85: 14277081>
    Gray86: TracyClientBindings.ColorType # value = <ColorType.Gray86: 14408667>
    Gray87: TracyClientBindings.ColorType # value = <ColorType.Gray87: 14606046>
    Gray88: TracyClientBindings.ColorType # value = <ColorType.Gray88: 14737632>
    Gray89: TracyClientBindings.ColorType # value = <ColorType.Gray89: 14935011>
    Gray9: TracyClientBindings.ColorType # value = <ColorType.Gray9: 1513239>
    Gray90: TracyClientBindings.ColorType # value = <ColorType.Gray90: 15066597>
    Gray91: TracyClientBindings.ColorType # value = <ColorType.Gray91: 15263976>
    Gray92: TracyClientBindings.ColorType # value = <ColorType.Gray92: 15461355>
    Gray93: TracyClientBindings.ColorType # value = <ColorType.Gray93: 15592941>
    Gray94: TracyClientBindings.ColorType # value = <ColorType.Gray94: 15790320>
    Gray95: TracyClientBindings.ColorType # value = <ColorType.Gray95: 15921906>
    Gray96: TracyClientBindings.ColorType # value = <ColorType.WhiteSmoke: 16119285>
    Gray97: TracyClientBindings.ColorType # value = <ColorType.Gray97: 16250871>
    Gray98: TracyClientBindings.ColorType # value = <ColorType.Gray98: 16448250>
    Gray99: TracyClientBindings.ColorType # value = <ColorType.Gray99: 16579836>
    Green: TracyClientBindings.ColorType # value = <ColorType.Green: 65280>
    Green1: TracyClientBindings.ColorType # value = <ColorType.Green: 65280>
    Green2: TracyClientBindings.ColorType # value = <ColorType.Green2: 60928>
    Green3: TracyClientBindings.ColorType # value = <ColorType.Green3: 52480>
    Green4: TracyClientBindings.ColorType # value = <ColorType.Green4: 35584>
    GreenYellow: TracyClientBindings.ColorType # value = <ColorType.GreenYellow: 11403055>
    Grey: TracyClientBindings.ColorType # value = <ColorType.Gray: 12500670>
    Grey0: TracyClientBindings.ColorType # value = <ColorType.Black: 0>
    Grey1: TracyClientBindings.ColorType # value = <ColorType.Gray1: 197379>
    Grey10: TracyClientBindings.ColorType # value = <ColorType.Gray10: 1710618>
    Grey100: TracyClientBindings.ColorType # value = <ColorType.White: 16777215>
    Grey11: TracyClientBindings.ColorType # value = <ColorType.Gray11: 1842204>
    Grey12: TracyClientBindings.ColorType # value = <ColorType.Gray12: 2039583>
    Grey13: TracyClientBindings.ColorType # value = <ColorType.Gray13: 2171169>
    Grey14: TracyClientBindings.ColorType # value = <ColorType.Gray14: 2368548>
    Grey15: TracyClientBindings.ColorType # value = <ColorType.Gray15: 2500134>
    Grey16: TracyClientBindings.ColorType # value = <ColorType.Gray16: 2697513>
    Grey17: TracyClientBindings.ColorType # value = <ColorType.Gray17: 2829099>
    Grey18: TracyClientBindings.ColorType # value = <ColorType.Gray18: 3026478>
    Grey19: TracyClientBindings.ColorType # value = <ColorType.Gray19: 3158064>
    Grey2: TracyClientBindings.ColorType # value = <ColorType.Gray2: 328965>
    Grey20: TracyClientBindings.ColorType # value = <ColorType.Gray20: 3355443>
    Grey21: TracyClientBindings.ColorType # value = <ColorType.Gray21: 3552822>
    Grey22: TracyClientBindings.ColorType # value = <ColorType.Gray22: 3684408>
    Grey23: TracyClientBindings.ColorType # value = <ColorType.Gray23: 3881787>
    Grey24: TracyClientBindings.ColorType # value = <ColorType.Gray24: 4013373>
    Grey25: TracyClientBindings.ColorType # value = <ColorType.Gray25: 4210752>
    Grey26: TracyClientBindings.ColorType # value = <ColorType.Gray26: 4342338>
    Grey27: TracyClientBindings.ColorType # value = <ColorType.Gray27: 4539717>
    Grey28: TracyClientBindings.ColorType # value = <ColorType.Gray28: 4671303>
    Grey29: TracyClientBindings.ColorType # value = <ColorType.Gray29: 4868682>
    Grey3: TracyClientBindings.ColorType # value = <ColorType.Gray3: 526344>
    Grey30: TracyClientBindings.ColorType # value = <ColorType.Gray30: 5066061>
    Grey31: TracyClientBindings.ColorType # value = <ColorType.Gray31: 5197647>
    Grey32: TracyClientBindings.ColorType # value = <ColorType.Gray32: 5395026>
    Grey33: TracyClientBindings.ColorType # value = <ColorType.Gray33: 5526612>
    Grey34: TracyClientBindings.ColorType # value = <ColorType.Gray34: 5723991>
    Grey35: TracyClientBindings.ColorType # value = <ColorType.Gray35: 5855577>
    Grey36: TracyClientBindings.ColorType # value = <ColorType.Gray36: 6052956>
    Grey37: TracyClientBindings.ColorType # value = <ColorType.Gray37: 6184542>
    Grey38: TracyClientBindings.ColorType # value = <ColorType.Gray38: 6381921>
    Grey39: TracyClientBindings.ColorType # value = <ColorType.Gray39: 6513507>
    Grey4: TracyClientBindings.ColorType # value = <ColorType.Gray4: 657930>
    Grey40: TracyClientBindings.ColorType # value = <ColorType.Gray40: 6710886>
    Grey41: TracyClientBindings.ColorType # value = <ColorType.DimGray: 6908265>
    Grey42: TracyClientBindings.ColorType # value = <ColorType.Gray42: 7039851>
    Grey43: TracyClientBindings.ColorType # value = <ColorType.Gray43: 7237230>
    Grey44: TracyClientBindings.ColorType # value = <ColorType.Gray44: 7368816>
    Grey45: TracyClientBindings.ColorType # value = <ColorType.Gray45: 7566195>
    Grey46: TracyClientBindings.ColorType # value = <ColorType.Gray46: 7697781>
    Grey47: TracyClientBindings.ColorType # value = <ColorType.Gray47: 7895160>
    Grey48: TracyClientBindings.ColorType # value = <ColorType.Gray48: 8026746>
    Grey49: TracyClientBindings.ColorType # value = <ColorType.Gray49: 8224125>
    Grey5: TracyClientBindings.ColorType # value = <ColorType.Gray5: 855309>
    Grey50: TracyClientBindings.ColorType # value = <ColorType.Gray50: 8355711>
    Grey51: TracyClientBindings.ColorType # value = <ColorType.Gray51: 8553090>
    Grey52: TracyClientBindings.ColorType # value = <ColorType.Gray52: 8750469>
    Grey53: TracyClientBindings.ColorType # value = <ColorType.Gray53: 8882055>
    Grey54: TracyClientBindings.ColorType # value = <ColorType.Gray54: 9079434>
    Grey55: TracyClientBindings.ColorType # value = <ColorType.Gray55: 9211020>
    Grey56: TracyClientBindings.ColorType # value = <ColorType.Gray56: 9408399>
    Grey57: TracyClientBindings.ColorType # value = <ColorType.Gray57: 9539985>
    Grey58: TracyClientBindings.ColorType # value = <ColorType.Gray58: 9737364>
    Grey59: TracyClientBindings.ColorType # value = <ColorType.Gray59: 9868950>
    Grey6: TracyClientBindings.ColorType # value = <ColorType.Gray6: 986895>
    Grey60: TracyClientBindings.ColorType # value = <ColorType.Gray60: 10066329>
    Grey61: TracyClientBindings.ColorType # value = <ColorType.Gray61: 10263708>
    Grey62: TracyClientBindings.ColorType # value = <ColorType.Gray62: 10395294>
    Grey63: TracyClientBindings.ColorType # value = <ColorType.Gray63: 10592673>
    Grey64: TracyClientBindings.ColorType # value = <ColorType.Gray64: 10724259>
    Grey65: TracyClientBindings.ColorType # value = <ColorType.Gray65: 10921638>
    Grey66: TracyClientBindings.ColorType # value = <ColorType.Gray66: 11053224>
    Grey67: TracyClientBindings.ColorType # value = <ColorType.Gray67: 11250603>
    Grey68: TracyClientBindings.ColorType # value = <ColorType.Gray68: 11382189>
    Grey69: TracyClientBindings.ColorType # value = <ColorType.Gray69: 11579568>
    Grey7: TracyClientBindings.ColorType # value = <ColorType.Gray7: 1184274>
    Grey70: TracyClientBindings.ColorType # value = <ColorType.Gray70: 11776947>
    Grey71: TracyClientBindings.ColorType # value = <ColorType.Gray71: 11908533>
    Grey72: TracyClientBindings.ColorType # value = <ColorType.Gray72: 12105912>
    Grey73: TracyClientBindings.ColorType # value = <ColorType.Gray73: 12237498>
    Grey74: TracyClientBindings.ColorType # value = <ColorType.Gray74: 12434877>
    Grey75: TracyClientBindings.ColorType # value = <ColorType.Gray75: 12566463>
    Grey76: TracyClientBindings.ColorType # value = <ColorType.Gray76: 12763842>
    Grey77: TracyClientBindings.ColorType # value = <ColorType.Gray77: 12895428>
    Grey78: TracyClientBindings.ColorType # value = <ColorType.Gray78: 13092807>
    Grey79: TracyClientBindings.ColorType # value = <ColorType.Gray79: 13224393>
    Grey8: TracyClientBindings.ColorType # value = <ColorType.Gray8: 1315860>
    Grey80: TracyClientBindings.ColorType # value = <ColorType.Gray80: 13421772>
    Grey81: TracyClientBindings.ColorType # value = <ColorType.Gray81: 13619151>
    Grey82: TracyClientBindings.ColorType # value = <ColorType.Gray82: 13750737>
    Grey83: TracyClientBindings.ColorType # value = <ColorType.Gray83: 13948116>
    Grey84: TracyClientBindings.ColorType # value = <ColorType.Gray84: 14079702>
    Grey85: TracyClientBindings.ColorType # value = <ColorType.Gray85: 14277081>
    Grey86: TracyClientBindings.ColorType # value = <ColorType.Gray86: 14408667>
    Grey87: TracyClientBindings.ColorType # value = <ColorType.Gray87: 14606046>
    Grey88: TracyClientBindings.ColorType # value = <ColorType.Gray88: 14737632>
    Grey89: TracyClientBindings.ColorType # value = <ColorType.Gray89: 14935011>
    Grey9: TracyClientBindings.ColorType # value = <ColorType.Gray9: 1513239>
    Grey90: TracyClientBindings.ColorType # value = <ColorType.Gray90: 15066597>
    Grey91: TracyClientBindings.ColorType # value = <ColorType.Gray91: 15263976>
    Grey92: TracyClientBindings.ColorType # value = <ColorType.Gray92: 15461355>
    Grey93: TracyClientBindings.ColorType # value = <ColorType.Gray93: 15592941>
    Grey94: TracyClientBindings.ColorType # value = <ColorType.Gray94: 15790320>
    Grey95: TracyClientBindings.ColorType # value = <ColorType.Gray95: 15921906>
    Grey96: TracyClientBindings.ColorType # value = <ColorType.WhiteSmoke: 16119285>
    Grey97: TracyClientBindings.ColorType # value = <ColorType.Gray97: 16250871>
    Grey98: TracyClientBindings.ColorType # value = <ColorType.Gray98: 16448250>
    Grey99: TracyClientBindings.ColorType # value = <ColorType.Gray99: 16579836>
    Honeydew: TracyClientBindings.ColorType # value = <ColorType.Honeydew: 15794160>
    Honeydew1: TracyClientBindings.ColorType # value = <ColorType.Honeydew: 15794160>
    Honeydew2: TracyClientBindings.ColorType # value = <ColorType.Honeydew2: 14741216>
    Honeydew3: TracyClientBindings.ColorType # value = <ColorType.Honeydew3: 12701121>
    Honeydew4: TracyClientBindings.ColorType # value = <ColorType.Honeydew4: 8620931>
    HotPink: TracyClientBindings.ColorType # value = <ColorType.HotPink: 16738740>
    HotPink1: TracyClientBindings.ColorType # value = <ColorType.HotPink1: 16740020>
    HotPink2: TracyClientBindings.ColorType # value = <ColorType.HotPink2: 15624871>
    HotPink3: TracyClientBindings.ColorType # value = <ColorType.HotPink3: 13459600>
    HotPink4: TracyClientBindings.ColorType # value = <ColorType.HotPink4: 9124450>
    IndianRed: TracyClientBindings.ColorType # value = <ColorType.IndianRed: 13458524>
    IndianRed1: TracyClientBindings.ColorType # value = <ColorType.IndianRed1: 16738922>
    IndianRed2: TracyClientBindings.ColorType # value = <ColorType.IndianRed2: 15623011>
    IndianRed3: TracyClientBindings.ColorType # value = <ColorType.IndianRed3: 13456725>
    IndianRed4: TracyClientBindings.ColorType # value = <ColorType.IndianRed4: 9124410>
    Indigo: TracyClientBindings.ColorType # value = <ColorType.Indigo: 4915330>
    Ivory: TracyClientBindings.ColorType # value = <ColorType.Ivory: 16777200>
    Ivory1: TracyClientBindings.ColorType # value = <ColorType.Ivory: 16777200>
    Ivory2: TracyClientBindings.ColorType # value = <ColorType.Ivory2: 15658720>
    Ivory3: TracyClientBindings.ColorType # value = <ColorType.Ivory3: 13487553>
    Ivory4: TracyClientBindings.ColorType # value = <ColorType.Ivory4: 9145219>
    Khaki: TracyClientBindings.ColorType # value = <ColorType.Khaki: 15787660>
    Khaki1: TracyClientBindings.ColorType # value = <ColorType.Khaki1: 16774799>
    Khaki2: TracyClientBindings.ColorType # value = <ColorType.Khaki2: 15656581>
    Khaki3: TracyClientBindings.ColorType # value = <ColorType.Khaki3: 13485683>
    Khaki4: TracyClientBindings.ColorType # value = <ColorType.Khaki4: 9143886>
    Lavender: TracyClientBindings.ColorType # value = <ColorType.Lavender: 15132410>
    LavenderBlush: TracyClientBindings.ColorType # value = <ColorType.LavenderBlush: 16773365>
    LavenderBlush1: TracyClientBindings.ColorType # value = <ColorType.LavenderBlush: 16773365>
    LavenderBlush2: TracyClientBindings.ColorType # value = <ColorType.LavenderBlush2: 15655141>
    LavenderBlush3: TracyClientBindings.ColorType # value = <ColorType.LavenderBlush3: 13484485>
    LavenderBlush4: TracyClientBindings.ColorType # value = <ColorType.LavenderBlush4: 9143174>
    LawnGreen: TracyClientBindings.ColorType # value = <ColorType.LawnGreen: 8190976>
    LemonChiffon: TracyClientBindings.ColorType # value = <ColorType.LemonChiffon: 16775885>
    LemonChiffon1: TracyClientBindings.ColorType # value = <ColorType.LemonChiffon: 16775885>
    LemonChiffon2: TracyClientBindings.ColorType # value = <ColorType.LemonChiffon2: 15657407>
    LemonChiffon3: TracyClientBindings.ColorType # value = <ColorType.LemonChiffon3: 13486501>
    LemonChiffon4: TracyClientBindings.ColorType # value = <ColorType.LemonChiffon4: 9144688>
    LightBlue: TracyClientBindings.ColorType # value = <ColorType.LightBlue: 11393254>
    LightBlue1: TracyClientBindings.ColorType # value = <ColorType.LightBlue1: 12578815>
    LightBlue2: TracyClientBindings.ColorType # value = <ColorType.LightBlue2: 11722734>
    LightBlue3: TracyClientBindings.ColorType # value = <ColorType.LightBlue3: 10141901>
    LightBlue4: TracyClientBindings.ColorType # value = <ColorType.LightBlue4: 6849419>
    LightCoral: TracyClientBindings.ColorType # value = <ColorType.LightCoral: 15761536>
    LightCyan: TracyClientBindings.ColorType # value = <ColorType.LightCyan: 14745599>
    LightCyan1: TracyClientBindings.ColorType # value = <ColorType.LightCyan: 14745599>
    LightCyan2: TracyClientBindings.ColorType # value = <ColorType.LightCyan2: 13758190>
    LightCyan3: TracyClientBindings.ColorType # value = <ColorType.LightCyan3: 11849165>
    LightCyan4: TracyClientBindings.ColorType # value = <ColorType.LightCyan4: 8031115>
    LightGoldenrod: TracyClientBindings.ColorType # value = <ColorType.LightGoldenrod: 15654274>
    LightGoldenrod1: TracyClientBindings.ColorType # value = <ColorType.LightGoldenrod1: 16772235>
    LightGoldenrod2: TracyClientBindings.ColorType # value = <ColorType.LightGoldenrod2: 15654018>
    LightGoldenrod3: TracyClientBindings.ColorType # value = <ColorType.LightGoldenrod3: 13483632>
    LightGoldenrod4: TracyClientBindings.ColorType # value = <ColorType.LightGoldenrod4: 9142604>
    LightGoldenrodYellow: TracyClientBindings.ColorType # value = <ColorType.LightGoldenrodYellow: 16448210>
    LightGray: TracyClientBindings.ColorType # value = <ColorType.LightGrey: 13882323>
    LightGreen: TracyClientBindings.ColorType # value = <ColorType.PaleGreen2: 9498256>
    LightGrey: TracyClientBindings.ColorType # value = <ColorType.LightGrey: 13882323>
    LightPink: TracyClientBindings.ColorType # value = <ColorType.LightPink: 16758465>
    LightPink1: TracyClientBindings.ColorType # value = <ColorType.LightPink1: 16756409>
    LightPink2: TracyClientBindings.ColorType # value = <ColorType.LightPink2: 15639213>
    LightPink3: TracyClientBindings.ColorType # value = <ColorType.LightPink3: 13470869>
    LightPink4: TracyClientBindings.ColorType # value = <ColorType.LightPink4: 9133925>
    LightSalmon: TracyClientBindings.ColorType # value = <ColorType.LightSalmon: 16752762>
    LightSalmon1: TracyClientBindings.ColorType # value = <ColorType.LightSalmon: 16752762>
    LightSalmon2: TracyClientBindings.ColorType # value = <ColorType.LightSalmon2: 15635826>
    LightSalmon3: TracyClientBindings.ColorType # value = <ColorType.LightSalmon3: 13468002>
    LightSalmon4: TracyClientBindings.ColorType # value = <ColorType.LightSalmon4: 9131842>
    LightSeaGreen: TracyClientBindings.ColorType # value = <ColorType.LightSeaGreen: 2142890>
    LightSkyBlue: TracyClientBindings.ColorType # value = <ColorType.LightSkyBlue: 8900346>
    LightSkyBlue1: TracyClientBindings.ColorType # value = <ColorType.LightSkyBlue1: 11592447>
    LightSkyBlue2: TracyClientBindings.ColorType # value = <ColorType.LightSkyBlue2: 10802158>
    LightSkyBlue3: TracyClientBindings.ColorType # value = <ColorType.LightSkyBlue3: 9287373>
    LightSkyBlue4: TracyClientBindings.ColorType # value = <ColorType.LightSkyBlue4: 6323083>
    LightSlateBlue: TracyClientBindings.ColorType # value = <ColorType.LightSlateBlue: 8679679>
    LightSlateGray: TracyClientBindings.ColorType # value = <ColorType.LightSlateGray: 7833753>
    LightSlateGrey: TracyClientBindings.ColorType # value = <ColorType.LightSlateGray: 7833753>
    LightSteelBlue: TracyClientBindings.ColorType # value = <ColorType.LightSteelBlue: 11584734>
    LightSteelBlue1: TracyClientBindings.ColorType # value = <ColorType.LightSteelBlue1: 13296127>
    LightSteelBlue2: TracyClientBindings.ColorType # value = <ColorType.LightSteelBlue2: 12374766>
    LightSteelBlue3: TracyClientBindings.ColorType # value = <ColorType.LightSteelBlue3: 10663373>
    LightSteelBlue4: TracyClientBindings.ColorType # value = <ColorType.LightSteelBlue4: 7240587>
    LightYellow: TracyClientBindings.ColorType # value = <ColorType.LightYellow: 16777184>
    LightYellow1: TracyClientBindings.ColorType # value = <ColorType.LightYellow: 16777184>
    LightYellow2: TracyClientBindings.ColorType # value = <ColorType.LightYellow2: 15658705>
    LightYellow3: TracyClientBindings.ColorType # value = <ColorType.LightYellow3: 13487540>
    LightYellow4: TracyClientBindings.ColorType # value = <ColorType.LightYellow4: 9145210>
    Lime: TracyClientBindings.ColorType # value = <ColorType.Green: 65280>
    LimeGreen: TracyClientBindings.ColorType # value = <ColorType.LimeGreen: 3329330>
    Linen: TracyClientBindings.ColorType # value = <ColorType.Linen: 16445670>
    Magenta: TracyClientBindings.ColorType # value = <ColorType.Magenta: 16711935>
    Magenta1: TracyClientBindings.ColorType # value = <ColorType.Magenta: 16711935>
    Magenta2: TracyClientBindings.ColorType # value = <ColorType.Magenta2: 15597806>
    Magenta3: TracyClientBindings.ColorType # value = <ColorType.Magenta3: 13435085>
    Magenta4: TracyClientBindings.ColorType # value = <ColorType.Magenta4: 9109643>
    Maroon: TracyClientBindings.ColorType # value = <ColorType.Maroon: 11546720>
    Maroon1: TracyClientBindings.ColorType # value = <ColorType.Maroon1: 16725171>
    Maroon2: TracyClientBindings.ColorType # value = <ColorType.Maroon2: 15610023>
    Maroon3: TracyClientBindings.ColorType # value = <ColorType.Maroon3: 13445520>
    Maroon4: TracyClientBindings.ColorType # value = <ColorType.Maroon4: 9116770>
    MediumAquamarine: TracyClientBindings.ColorType # value = <ColorType.MediumAquamarine: 6737322>
    MediumBlue: TracyClientBindings.ColorType # value = <ColorType.MediumBlue: 205>
    MediumOrchid: TracyClientBindings.ColorType # value = <ColorType.MediumOrchid: 12211667>
    MediumOrchid1: TracyClientBindings.ColorType # value = <ColorType.MediumOrchid1: 14706431>
    MediumOrchid2: TracyClientBindings.ColorType # value = <ColorType.MediumOrchid2: 13721582>
    MediumOrchid3: TracyClientBindings.ColorType # value = <ColorType.MediumOrchid3: 11817677>
    MediumOrchid4: TracyClientBindings.ColorType # value = <ColorType.MediumOrchid4: 8009611>
    MediumPurple: TracyClientBindings.ColorType # value = <ColorType.MediumPurple: 9662683>
    MediumPurple1: TracyClientBindings.ColorType # value = <ColorType.MediumPurple1: 11240191>
    MediumPurple2: TracyClientBindings.ColorType # value = <ColorType.MediumPurple2: 10451438>
    MediumPurple3: TracyClientBindings.ColorType # value = <ColorType.MediumPurple3: 9005261>
    MediumPurple4: TracyClientBindings.ColorType # value = <ColorType.MediumPurple4: 6113163>
    MediumSeaGreen: TracyClientBindings.ColorType # value = <ColorType.MediumSeaGreen: 3978097>
    MediumSlateBlue: TracyClientBindings.ColorType # value = <ColorType.MediumSlateBlue: 8087790>
    MediumSpringGreen: TracyClientBindings.ColorType # value = <ColorType.MediumSpringGreen: 64154>
    MediumTurquoise: TracyClientBindings.ColorType # value = <ColorType.MediumTurquoise: 4772300>
    MediumVioletRed: TracyClientBindings.ColorType # value = <ColorType.MediumVioletRed: 13047173>
    MidnightBlue: TracyClientBindings.ColorType # value = <ColorType.MidnightBlue: 1644912>
    MintCream: TracyClientBindings.ColorType # value = <ColorType.MintCream: 16121850>
    MistyRose: TracyClientBindings.ColorType # value = <ColorType.MistyRose: 16770273>
    MistyRose1: TracyClientBindings.ColorType # value = <ColorType.MistyRose: 16770273>
    MistyRose2: TracyClientBindings.ColorType # value = <ColorType.MistyRose2: 15652306>
    MistyRose3: TracyClientBindings.ColorType # value = <ColorType.MistyRose3: 13481909>
    MistyRose4: TracyClientBindings.ColorType # value = <ColorType.MistyRose4: 9141627>
    Moccasin: TracyClientBindings.ColorType # value = <ColorType.Moccasin: 16770229>
    NavajoWhite: TracyClientBindings.ColorType # value = <ColorType.NavajoWhite: 16768685>
    NavajoWhite1: TracyClientBindings.ColorType # value = <ColorType.NavajoWhite: 16768685>
    NavajoWhite2: TracyClientBindings.ColorType # value = <ColorType.NavajoWhite2: 15650721>
    NavajoWhite3: TracyClientBindings.ColorType # value = <ColorType.NavajoWhite3: 13480843>
    NavajoWhite4: TracyClientBindings.ColorType # value = <ColorType.NavajoWhite4: 9140574>
    Navy: TracyClientBindings.ColorType # value = <ColorType.Navy: 128>
    NavyBlue: TracyClientBindings.ColorType # value = <ColorType.Navy: 128>
    OldLace: TracyClientBindings.ColorType # value = <ColorType.OldLace: 16643558>
    Olive: TracyClientBindings.ColorType # value = <ColorType.Olive: 8421376>
    OliveDrab: TracyClientBindings.ColorType # value = <ColorType.OliveDrab: 7048739>
    OliveDrab1: TracyClientBindings.ColorType # value = <ColorType.OliveDrab1: 12648254>
    OliveDrab2: TracyClientBindings.ColorType # value = <ColorType.OliveDrab2: 11791930>
    OliveDrab3: TracyClientBindings.ColorType # value = <ColorType.YellowGreen: 10145074>
    OliveDrab4: TracyClientBindings.ColorType # value = <ColorType.OliveDrab4: 6916898>
    Orange: TracyClientBindings.ColorType # value = <ColorType.Orange: 16753920>
    Orange1: TracyClientBindings.ColorType # value = <ColorType.Orange: 16753920>
    Orange2: TracyClientBindings.ColorType # value = <ColorType.Orange2: 15636992>
    Orange3: TracyClientBindings.ColorType # value = <ColorType.Orange3: 13468928>
    Orange4: TracyClientBindings.ColorType # value = <ColorType.Orange4: 9132544>
    OrangeRed: TracyClientBindings.ColorType # value = <ColorType.OrangeRed: 16729344>
    OrangeRed1: TracyClientBindings.ColorType # value = <ColorType.OrangeRed: 16729344>
    OrangeRed2: TracyClientBindings.ColorType # value = <ColorType.OrangeRed2: 15613952>
    OrangeRed3: TracyClientBindings.ColorType # value = <ColorType.OrangeRed3: 13448960>
    OrangeRed4: TracyClientBindings.ColorType # value = <ColorType.OrangeRed4: 9118976>
    Orchid: TracyClientBindings.ColorType # value = <ColorType.Orchid: 14315734>
    Orchid1: TracyClientBindings.ColorType # value = <ColorType.Orchid1: 16745466>
    Orchid2: TracyClientBindings.ColorType # value = <ColorType.Orchid2: 15629033>
    Orchid3: TracyClientBindings.ColorType # value = <ColorType.Orchid3: 13461961>
    Orchid4: TracyClientBindings.ColorType # value = <ColorType.Orchid4: 9127817>
    PaleGoldenrod: TracyClientBindings.ColorType # value = <ColorType.PaleGoldenrod: 15657130>
    PaleGreen: TracyClientBindings.ColorType # value = <ColorType.PaleGreen: 10025880>
    PaleGreen1: TracyClientBindings.ColorType # value = <ColorType.PaleGreen1: 10157978>
    PaleGreen2: TracyClientBindings.ColorType # value = <ColorType.PaleGreen2: 9498256>
    PaleGreen3: TracyClientBindings.ColorType # value = <ColorType.PaleGreen3: 8179068>
    PaleGreen4: TracyClientBindings.ColorType # value = <ColorType.PaleGreen4: 5540692>
    PaleTurquoise: TracyClientBindings.ColorType # value = <ColorType.PaleTurquoise: 11529966>
    PaleTurquoise1: TracyClientBindings.ColorType # value = <ColorType.PaleTurquoise1: 12320767>
    PaleTurquoise2: TracyClientBindings.ColorType # value = <ColorType.PaleTurquoise2: 11464430>
    PaleTurquoise3: TracyClientBindings.ColorType # value = <ColorType.PaleTurquoise3: 9883085>
    PaleTurquoise4: TracyClientBindings.ColorType # value = <ColorType.PaleTurquoise4: 6720395>
    PaleVioletRed: TracyClientBindings.ColorType # value = <ColorType.PaleVioletRed: 14381203>
    PaleVioletRed1: TracyClientBindings.ColorType # value = <ColorType.PaleVioletRed1: 16745131>
    PaleVioletRed2: TracyClientBindings.ColorType # value = <ColorType.PaleVioletRed2: 15628703>
    PaleVioletRed3: TracyClientBindings.ColorType # value = <ColorType.PaleVioletRed3: 13461641>
    PaleVioletRed4: TracyClientBindings.ColorType # value = <ColorType.PaleVioletRed4: 9127773>
    PapayaWhip: TracyClientBindings.ColorType # value = <ColorType.PapayaWhip: 16773077>
    PeachPuff: TracyClientBindings.ColorType # value = <ColorType.PeachPuff: 16767673>
    PeachPuff1: TracyClientBindings.ColorType # value = <ColorType.PeachPuff: 16767673>
    PeachPuff2: TracyClientBindings.ColorType # value = <ColorType.PeachPuff2: 15649709>
    PeachPuff3: TracyClientBindings.ColorType # value = <ColorType.PeachPuff3: 13479829>
    PeachPuff4: TracyClientBindings.ColorType # value = <ColorType.PeachPuff4: 9140069>
    Peru: TracyClientBindings.ColorType # value = <ColorType.Peru: 13468991>
    Pink: TracyClientBindings.ColorType # value = <ColorType.Pink: 16761035>
    Pink1: TracyClientBindings.ColorType # value = <ColorType.Pink1: 16758213>
    Pink2: TracyClientBindings.ColorType # value = <ColorType.Pink2: 15641016>
    Pink3: TracyClientBindings.ColorType # value = <ColorType.Pink3: 13472158>
    Pink4: TracyClientBindings.ColorType # value = <ColorType.Pink4: 9134956>
    Plum: TracyClientBindings.ColorType # value = <ColorType.Plum: 14524637>
    Plum1: TracyClientBindings.ColorType # value = <ColorType.Plum1: 16759807>
    Plum2: TracyClientBindings.ColorType # value = <ColorType.Plum2: 15642350>
    Plum3: TracyClientBindings.ColorType # value = <ColorType.Plum3: 13473485>
    Plum4: TracyClientBindings.ColorType # value = <ColorType.Plum4: 9135755>
    PowderBlue: TracyClientBindings.ColorType # value = <ColorType.PowderBlue: 11591910>
    Purple: TracyClientBindings.ColorType # value = <ColorType.Purple: 10494192>
    Purple1: TracyClientBindings.ColorType # value = <ColorType.Purple1: 10170623>
    Purple2: TracyClientBindings.ColorType # value = <ColorType.Purple2: 9514222>
    Purple3: TracyClientBindings.ColorType # value = <ColorType.Purple3: 8201933>
    Purple4: TracyClientBindings.ColorType # value = <ColorType.Purple4: 5577355>
    RebeccaPurple: TracyClientBindings.ColorType # value = <ColorType.RebeccaPurple: 6697881>
    Red: TracyClientBindings.ColorType # value = <ColorType.Red: 16711680>
    Red1: TracyClientBindings.ColorType # value = <ColorType.Red: 16711680>
    Red2: TracyClientBindings.ColorType # value = <ColorType.Red2: 15597568>
    Red3: TracyClientBindings.ColorType # value = <ColorType.Red3: 13434880>
    Red4: TracyClientBindings.ColorType # value = <ColorType.Red4: 9109504>
    RosyBrown: TracyClientBindings.ColorType # value = <ColorType.RosyBrown: 12357519>
    RosyBrown1: TracyClientBindings.ColorType # value = <ColorType.RosyBrown1: 16761281>
    RosyBrown2: TracyClientBindings.ColorType # value = <ColorType.RosyBrown2: 15643828>
    RosyBrown3: TracyClientBindings.ColorType # value = <ColorType.RosyBrown3: 13474715>
    RosyBrown4: TracyClientBindings.ColorType # value = <ColorType.RosyBrown4: 9136489>
    RoyalBlue: TracyClientBindings.ColorType # value = <ColorType.RoyalBlue: 4286945>
    RoyalBlue1: TracyClientBindings.ColorType # value = <ColorType.RoyalBlue1: 4749055>
    RoyalBlue2: TracyClientBindings.ColorType # value = <ColorType.RoyalBlue2: 4419310>
    RoyalBlue3: TracyClientBindings.ColorType # value = <ColorType.RoyalBlue3: 3825613>
    RoyalBlue4: TracyClientBindings.ColorType # value = <ColorType.RoyalBlue4: 2572427>
    SaddleBrown: TracyClientBindings.ColorType # value = <ColorType.SaddleBrown: 9127187>
    Salmon: TracyClientBindings.ColorType # value = <ColorType.Salmon: 16416882>
    Salmon1: TracyClientBindings.ColorType # value = <ColorType.Salmon1: 16747625>
    Salmon2: TracyClientBindings.ColorType # value = <ColorType.Salmon2: 15630946>
    Salmon3: TracyClientBindings.ColorType # value = <ColorType.Salmon3: 13463636>
    Salmon4: TracyClientBindings.ColorType # value = <ColorType.Salmon4: 9129017>
    SandyBrown: TracyClientBindings.ColorType # value = <ColorType.SandyBrown: 16032864>
    SeaGreen: TracyClientBindings.ColorType # value = <ColorType.SeaGreen: 3050327>
    SeaGreen1: TracyClientBindings.ColorType # value = <ColorType.SeaGreen1: 5570463>
    SeaGreen2: TracyClientBindings.ColorType # value = <ColorType.SeaGreen2: 5172884>
    SeaGreen3: TracyClientBindings.ColorType # value = <ColorType.SeaGreen3: 4443520>
    SeaGreen4: TracyClientBindings.ColorType # value = <ColorType.SeaGreen: 3050327>
    Seashell: TracyClientBindings.ColorType # value = <ColorType.Seashell: 16774638>
    Seashell1: TracyClientBindings.ColorType # value = <ColorType.Seashell: 16774638>
    Seashell2: TracyClientBindings.ColorType # value = <ColorType.Seashell2: 15656414>
    Seashell3: TracyClientBindings.ColorType # value = <ColorType.Seashell3: 13485503>
    Seashell4: TracyClientBindings.ColorType # value = <ColorType.Seashell4: 9143938>
    Sienna: TracyClientBindings.ColorType # value = <ColorType.Sienna: 10506797>
    Sienna1: TracyClientBindings.ColorType # value = <ColorType.Sienna1: 16745031>
    Sienna2: TracyClientBindings.ColorType # value = <ColorType.Sienna2: 15628610>
    Sienna3: TracyClientBindings.ColorType # value = <ColorType.Sienna3: 13461561>
    Sienna4: TracyClientBindings.ColorType # value = <ColorType.Sienna4: 9127718>
    Silver: TracyClientBindings.ColorType # value = <ColorType.Silver: 12632256>
    SkyBlue: TracyClientBindings.ColorType # value = <ColorType.SkyBlue: 8900331>
    SkyBlue1: TracyClientBindings.ColorType # value = <ColorType.SkyBlue1: 8900351>
    SkyBlue2: TracyClientBindings.ColorType # value = <ColorType.SkyBlue2: 8306926>
    SkyBlue3: TracyClientBindings.ColorType # value = <ColorType.SkyBlue3: 7120589>
    SkyBlue4: TracyClientBindings.ColorType # value = <ColorType.SkyBlue4: 4878475>
    SlateBlue: TracyClientBindings.ColorType # value = <ColorType.SlateBlue: 6970061>
    SlateBlue1: TracyClientBindings.ColorType # value = <ColorType.SlateBlue1: 8613887>
    SlateBlue2: TracyClientBindings.ColorType # value = <ColorType.SlateBlue2: 8021998>
    SlateBlue3: TracyClientBindings.ColorType # value = <ColorType.SlateBlue3: 6904269>
    SlateBlue4: TracyClientBindings.ColorType # value = <ColorType.SlateBlue4: 4668555>
    SlateGray: TracyClientBindings.ColorType # value = <ColorType.SlateGray: 7372944>
    SlateGray1: TracyClientBindings.ColorType # value = <ColorType.SlateGray1: 13034239>
    SlateGray2: TracyClientBindings.ColorType # value = <ColorType.SlateGray2: 12178414>
    SlateGray3: TracyClientBindings.ColorType # value = <ColorType.SlateGray3: 10467021>
    SlateGray4: TracyClientBindings.ColorType # value = <ColorType.SlateGray4: 7109515>
    SlateGrey: TracyClientBindings.ColorType # value = <ColorType.SlateGray: 7372944>
    Snow: TracyClientBindings.ColorType # value = <ColorType.Snow: 16775930>
    Snow1: TracyClientBindings.ColorType # value = <ColorType.Snow: 16775930>
    Snow2: TracyClientBindings.ColorType # value = <ColorType.Snow2: 15657449>
    Snow3: TracyClientBindings.ColorType # value = <ColorType.Snow3: 13486537>
    Snow4: TracyClientBindings.ColorType # value = <ColorType.Snow4: 9144713>
    SpringGreen: TracyClientBindings.ColorType # value = <ColorType.SpringGreen: 65407>
    SpringGreen1: TracyClientBindings.ColorType # value = <ColorType.SpringGreen: 65407>
    SpringGreen2: TracyClientBindings.ColorType # value = <ColorType.SpringGreen2: 61046>
    SpringGreen3: TracyClientBindings.ColorType # value = <ColorType.SpringGreen3: 52582>
    SpringGreen4: TracyClientBindings.ColorType # value = <ColorType.SpringGreen4: 35653>
    SteelBlue: TracyClientBindings.ColorType # value = <ColorType.SteelBlue: 4620980>
    SteelBlue1: TracyClientBindings.ColorType # value = <ColorType.SteelBlue1: 6535423>
    SteelBlue2: TracyClientBindings.ColorType # value = <ColorType.SteelBlue2: 6073582>
    SteelBlue3: TracyClientBindings.ColorType # value = <ColorType.SteelBlue3: 5215437>
    SteelBlue4: TracyClientBindings.ColorType # value = <ColorType.SteelBlue4: 3564683>
    Tan: TracyClientBindings.ColorType # value = <ColorType.Tan: 13808780>
    Tan1: TracyClientBindings.ColorType # value = <ColorType.Tan1: 16753999>
    Tan2: TracyClientBindings.ColorType # value = <ColorType.Tan2: 15637065>
    Tan3: TracyClientBindings.ColorType # value = <ColorType.Peru: 13468991>
    Tan4: TracyClientBindings.ColorType # value = <ColorType.Tan4: 9132587>
    Teal: TracyClientBindings.ColorType # value = <ColorType.Teal: 32896>
    Thistle: TracyClientBindings.ColorType # value = <ColorType.Thistle: 14204888>
    Thistle1: TracyClientBindings.ColorType # value = <ColorType.Thistle1: 16769535>
    Thistle2: TracyClientBindings.ColorType # value = <ColorType.Thistle2: 15651566>
    Thistle3: TracyClientBindings.ColorType # value = <ColorType.Thistle3: 13481421>
    Thistle4: TracyClientBindings.ColorType # value = <ColorType.Thistle4: 9141131>
    Tomato: TracyClientBindings.ColorType # value = <ColorType.Tomato: 16737095>
    Tomato1: TracyClientBindings.ColorType # value = <ColorType.Tomato: 16737095>
    Tomato2: TracyClientBindings.ColorType # value = <ColorType.Tomato2: 15621186>
    Tomato3: TracyClientBindings.ColorType # value = <ColorType.Tomato3: 13455161>
    Tomato4: TracyClientBindings.ColorType # value = <ColorType.Tomato4: 9123366>
    Turquoise: TracyClientBindings.ColorType # value = <ColorType.Turquoise: 4251856>
    Turquoise1: TracyClientBindings.ColorType # value = <ColorType.Turquoise1: 62975>
    Turquoise2: TracyClientBindings.ColorType # value = <ColorType.Turquoise2: 58862>
    Turquoise3: TracyClientBindings.ColorType # value = <ColorType.Turquoise3: 50637>
    Turquoise4: TracyClientBindings.ColorType # value = <ColorType.Turquoise4: 34443>
    Violet: TracyClientBindings.ColorType # value = <ColorType.Violet: 15631086>
    VioletRed: TracyClientBindings.ColorType # value = <ColorType.VioletRed: 13639824>
    VioletRed1: TracyClientBindings.ColorType # value = <ColorType.VioletRed1: 16727702>
    VioletRed2: TracyClientBindings.ColorType # value = <ColorType.VioletRed2: 15612556>
    VioletRed3: TracyClientBindings.ColorType # value = <ColorType.VioletRed3: 13447800>
    VioletRed4: TracyClientBindings.ColorType # value = <ColorType.VioletRed4: 9118290>
    WebGray: TracyClientBindings.ColorType # value = <ColorType.WebGray: 8421504>
    WebGreen: TracyClientBindings.ColorType # value = <ColorType.WebGreen: 32768>
    WebGrey: TracyClientBindings.ColorType # value = <ColorType.WebGray: 8421504>
    WebMaroon: TracyClientBindings.ColorType # value = <ColorType.WebMaroon: 8388608>
    WebPurple: TracyClientBindings.ColorType # value = <ColorType.WebPurple: 8388736>
    Wheat: TracyClientBindings.ColorType # value = <ColorType.Wheat: 16113331>
    Wheat1: TracyClientBindings.ColorType # value = <ColorType.Wheat1: 16771002>
    Wheat2: TracyClientBindings.ColorType # value = <ColorType.Wheat2: 15653038>
    Wheat3: TracyClientBindings.ColorType # value = <ColorType.Wheat3: 13482646>
    Wheat4: TracyClientBindings.ColorType # value = <ColorType.Wheat4: 9141862>
    White: TracyClientBindings.ColorType # value = <ColorType.White: 16777215>
    WhiteSmoke: TracyClientBindings.ColorType # value = <ColorType.WhiteSmoke: 16119285>
    X11Gray: TracyClientBindings.ColorType # value = <ColorType.Gray: 12500670>
    X11Green: TracyClientBindings.ColorType # value = <ColorType.Green: 65280>
    X11Grey: TracyClientBindings.ColorType # value = <ColorType.Gray: 12500670>
    X11Maroon: TracyClientBindings.ColorType # value = <ColorType.Maroon: 11546720>
    X11Purple: TracyClientBindings.ColorType # value = <ColorType.Purple: 10494192>
    Yellow: TracyClientBindings.ColorType # value = <ColorType.Yellow: 16776960>
    Yellow1: TracyClientBindings.ColorType # value = <ColorType.Yellow: 16776960>
    Yellow2: TracyClientBindings.ColorType # value = <ColorType.Yellow2: 15658496>
    Yellow3: TracyClientBindings.ColorType # value = <ColorType.Yellow3: 13487360>
    Yellow4: TracyClientBindings.ColorType # value = <ColorType.Yellow4: 9145088>
    YellowGreen: TracyClientBindings.ColorType # value = <ColorType.YellowGreen: 10145074>
    __members__: dict # value = {'Snow': <ColorType.Snow: 16775930>, 'GhostWhite': <ColorType.GhostWhite: 16316671>, 'WhiteSmoke': <ColorType.WhiteSmoke: 16119285>, 'Gainsboro': <ColorType.Gainsboro: 14474460>, 'FloralWhite': <ColorType.FloralWhite: 16775920>, 'OldLace': <ColorType.OldLace: 16643558>, 'Linen': <ColorType.Linen: 16445670>, 'AntiqueWhite': <ColorType.AntiqueWhite: 16444375>, 'PapayaWhip': <ColorType.PapayaWhip: 16773077>, 'BlanchedAlmond': <ColorType.BlanchedAlmond: 16772045>, 'Bisque': <ColorType.Bisque: 16770244>, 'PeachPuff': <ColorType.PeachPuff: 16767673>, 'NavajoWhite': <ColorType.NavajoWhite: 16768685>, 'Moccasin': <ColorType.Moccasin: 16770229>, 'Cornsilk': <ColorType.Cornsilk: 16775388>, 'Ivory': <ColorType.Ivory: 16777200>, 'LemonChiffon': <ColorType.LemonChiffon: 16775885>, 'Seashell': <ColorType.Seashell: 16774638>, 'Honeydew': <ColorType.Honeydew: 15794160>, 'MintCream': <ColorType.MintCream: 16121850>, 'Azure': <ColorType.Azure: 15794175>, 'AliceBlue': <ColorType.AliceBlue: 15792383>, 'Lavender': <ColorType.Lavender: 15132410>, 'LavenderBlush': <ColorType.LavenderBlush: 16773365>, 'MistyRose': <ColorType.MistyRose: 16770273>, 'White': <ColorType.White: 16777215>, 'Black': <ColorType.Black: 0>, 'DarkSlateGray': <ColorType.DarkSlateGray: 3100495>, 'DarkSlateGrey': <ColorType.DarkSlateGray: 3100495>, 'DimGray': <ColorType.DimGray: 6908265>, 'DimGrey': <ColorType.DimGray: 6908265>, 'SlateGray': <ColorType.SlateGray: 7372944>, 'SlateGrey': <ColorType.SlateGray: 7372944>, 'LightSlateGray': <ColorType.LightSlateGray: 7833753>, 'LightSlateGrey': <ColorType.LightSlateGray: 7833753>, 'Gray': <ColorType.Gray: 12500670>, 'Grey': <ColorType.Gray: 12500670>, 'X11Gray': <ColorType.Gray: 12500670>, 'X11Grey': <ColorType.Gray: 12500670>, 'WebGray': <ColorType.WebGray: 8421504>, 'WebGrey': <ColorType.WebGray: 8421504>, 'LightGrey': <ColorType.LightGrey: 13882323>, 'LightGray': <ColorType.LightGrey: 13882323>, 'MidnightBlue': <ColorType.MidnightBlue: 1644912>, 'Navy': <ColorType.Navy: 128>, 'NavyBlue': <ColorType.Navy: 128>, 'CornflowerBlue': <ColorType.CornflowerBlue: 6591981>, 'DarkSlateBlue': <ColorType.DarkSlateBlue: 4734347>, 'SlateBlue': <ColorType.SlateBlue: 6970061>, 'MediumSlateBlue': <ColorType.MediumSlateBlue: 8087790>, 'LightSlateBlue': <ColorType.LightSlateBlue: 8679679>, 'MediumBlue': <ColorType.MediumBlue: 205>, 'RoyalBlue': <ColorType.RoyalBlue: 4286945>, 'Blue': <ColorType.Blue: 255>, 'DodgerBlue': <ColorType.DodgerBlue: 2003199>, 'DeepSkyBlue': <ColorType.DeepSkyBlue: 49151>, 'SkyBlue': <ColorType.SkyBlue: 8900331>, 'LightSkyBlue': <ColorType.LightSkyBlue: 8900346>, 'SteelBlue': <ColorType.SteelBlue: 4620980>, 'LightSteelBlue': <ColorType.LightSteelBlue: 11584734>, 'LightBlue': <ColorType.LightBlue: 11393254>, 'PowderBlue': <ColorType.PowderBlue: 11591910>, 'PaleTurquoise': <ColorType.PaleTurquoise: 11529966>, 'DarkTurquoise': <ColorType.DarkTurquoise: 52945>, 'MediumTurquoise': <ColorType.MediumTurquoise: 4772300>, 'Turquoise': <ColorType.Turquoise: 4251856>, 'Cyan': <ColorType.Cyan: 65535>, 'Aqua': <ColorType.Cyan: 65535>, 'LightCyan': <ColorType.LightCyan: 14745599>, 'CadetBlue': <ColorType.CadetBlue: 6266528>, 'MediumAquamarine': <ColorType.MediumAquamarine: 6737322>, 'Aquamarine': <ColorType.Aquamarine: 8388564>, 'DarkGreen': <ColorType.DarkGreen: 25600>, 'DarkOliveGreen': <ColorType.DarkOliveGreen: 5597999>, 'DarkSeaGreen': <ColorType.DarkSeaGreen: 9419919>, 'SeaGreen': <ColorType.SeaGreen: 3050327>, 'MediumSeaGreen': <ColorType.MediumSeaGreen: 3978097>, 'LightSeaGreen': <ColorType.LightSeaGreen: 2142890>, 'PaleGreen': <ColorType.PaleGreen: 10025880>, 'SpringGreen': <ColorType.SpringGreen: 65407>, 'LawnGreen': <ColorType.LawnGreen: 8190976>, 'Green': <ColorType.Green: 65280>, 'Lime': <ColorType.Green: 65280>, 'X11Green': <ColorType.Green: 65280>, 'WebGreen': <ColorType.WebGreen: 32768>, 'Chartreuse': <ColorType.Chartreuse: 8388352>, 'MediumSpringGreen': <ColorType.MediumSpringGreen: 64154>, 'GreenYellow': <ColorType.GreenYellow: 11403055>, 'LimeGreen': <ColorType.LimeGreen: 3329330>, 'YellowGreen': <ColorType.YellowGreen: 10145074>, 'ForestGreen': <ColorType.ForestGreen: 2263842>, 'OliveDrab': <ColorType.OliveDrab: 7048739>, 'DarkKhaki': <ColorType.DarkKhaki: 12433259>, 'Khaki': <ColorType.Khaki: 15787660>, 'PaleGoldenrod': <ColorType.PaleGoldenrod: 15657130>, 'LightGoldenrodYellow': <ColorType.LightGoldenrodYellow: 16448210>, 'LightYellow': <ColorType.LightYellow: 16777184>, 'Yellow': <ColorType.Yellow: 16776960>, 'Gold': <ColorType.Gold: 16766720>, 'LightGoldenrod': <ColorType.LightGoldenrod: 15654274>, 'Goldenrod': <ColorType.Goldenrod: 14329120>, 'DarkGoldenrod': <ColorType.DarkGoldenrod: 12092939>, 'RosyBrown': <ColorType.RosyBrown: 12357519>, 'IndianRed': <ColorType.IndianRed: 13458524>, 'SaddleBrown': <ColorType.SaddleBrown: 9127187>, 'Sienna': <ColorType.Sienna: 10506797>, 'Peru': <ColorType.Peru: 13468991>, 'Burlywood': <ColorType.Burlywood: 14596231>, 'Beige': <ColorType.Beige: 16119260>, 'Wheat': <ColorType.Wheat: 16113331>, 'SandyBrown': <ColorType.SandyBrown: 16032864>, 'Tan': <ColorType.Tan: 13808780>, 'Chocolate': <ColorType.Chocolate: 13789470>, 'Firebrick': <ColorType.Firebrick: 11674146>, 'Brown': <ColorType.Brown: 10824234>, 'DarkSalmon': <ColorType.DarkSalmon: 15308410>, 'Salmon': <ColorType.Salmon: 16416882>, 'LightSalmon': <ColorType.LightSalmon: 16752762>, 'Orange': <ColorType.Orange: 16753920>, 'DarkOrange': <ColorType.DarkOrange: 16747520>, 'Coral': <ColorType.Coral: 16744272>, 'LightCoral': <ColorType.LightCoral: 15761536>, 'Tomato': <ColorType.Tomato: 16737095>, 'OrangeRed': <ColorType.OrangeRed: 16729344>, 'Red': <ColorType.Red: 16711680>, 'HotPink': <ColorType.HotPink: 16738740>, 'DeepPink': <ColorType.DeepPink: 16716947>, 'Pink': <ColorType.Pink: 16761035>, 'LightPink': <ColorType.LightPink: 16758465>, 'PaleVioletRed': <ColorType.PaleVioletRed: 14381203>, 'Maroon': <ColorType.Maroon: 11546720>, 'X11Maroon': <ColorType.Maroon: 11546720>, 'WebMaroon': <ColorType.WebMaroon: 8388608>, 'MediumVioletRed': <ColorType.MediumVioletRed: 13047173>, 'VioletRed': <ColorType.VioletRed: 13639824>, 'Magenta': <ColorType.Magenta: 16711935>, 'Fuchsia': <ColorType.Magenta: 16711935>, 'Violet': <ColorType.Violet: 15631086>, 'Plum': <ColorType.Plum: 14524637>, 'Orchid': <ColorType.Orchid: 14315734>, 'MediumOrchid': <ColorType.MediumOrchid: 12211667>, 'DarkOrchid': <ColorType.DarkOrchid: 10040012>, 'DarkViolet': <ColorType.DarkViolet: 9699539>, 'BlueViolet': <ColorType.BlueViolet: 9055202>, 'Purple': <ColorType.Purple: 10494192>, 'X11Purple': <ColorType.Purple: 10494192>, 'WebPurple': <ColorType.WebPurple: 8388736>, 'MediumPurple': <ColorType.MediumPurple: 9662683>, 'Thistle': <ColorType.Thistle: 14204888>, 'Snow1': <ColorType.Snow: 16775930>, 'Snow2': <ColorType.Snow2: 15657449>, 'Snow3': <ColorType.Snow3: 13486537>, 'Snow4': <ColorType.Snow4: 9144713>, 'Seashell1': <ColorType.Seashell: 16774638>, 'Seashell2': <ColorType.Seashell2: 15656414>, 'Seashell3': <ColorType.Seashell3: 13485503>, 'Seashell4': <ColorType.Seashell4: 9143938>, 'AntiqueWhite1': <ColorType.AntiqueWhite1: 16773083>, 'AntiqueWhite2': <ColorType.AntiqueWhite2: 15654860>, 'AntiqueWhite3': <ColorType.AntiqueWhite3: 13484208>, 'AntiqueWhite4': <ColorType.AntiqueWhite4: 9143160>, 'Bisque1': <ColorType.Bisque: 16770244>, 'Bisque2': <ColorType.Bisque2: 15652279>, 'Bisque3': <ColorType.Bisque3: 13481886>, 'Bisque4': <ColorType.Bisque4: 9141611>, 'PeachPuff1': <ColorType.PeachPuff: 16767673>, 'PeachPuff2': <ColorType.PeachPuff2: 15649709>, 'PeachPuff3': <ColorType.PeachPuff3: 13479829>, 'PeachPuff4': <ColorType.PeachPuff4: 9140069>, 'NavajoWhite1': <ColorType.NavajoWhite: 16768685>, 'NavajoWhite2': <ColorType.NavajoWhite2: 15650721>, 'NavajoWhite3': <ColorType.NavajoWhite3: 13480843>, 'NavajoWhite4': <ColorType.NavajoWhite4: 9140574>, 'LemonChiffon1': <ColorType.LemonChiffon: 16775885>, 'LemonChiffon2': <ColorType.LemonChiffon2: 15657407>, 'LemonChiffon3': <ColorType.LemonChiffon3: 13486501>, 'LemonChiffon4': <ColorType.LemonChiffon4: 9144688>, 'Cornsilk1': <ColorType.Cornsilk: 16775388>, 'Cornsilk2': <ColorType.Cornsilk2: 15657165>, 'Cornsilk3': <ColorType.Cornsilk3: 13486257>, 'Cornsilk4': <ColorType.Cornsilk4: 9144440>, 'Ivory1': <ColorType.Ivory: 16777200>, 'Ivory2': <ColorType.Ivory2: 15658720>, 'Ivory3': <ColorType.Ivory3: 13487553>, 'Ivory4': <ColorType.Ivory4: 9145219>, 'Honeydew1': <ColorType.Honeydew: 15794160>, 'Honeydew2': <ColorType.Honeydew2: 14741216>, 'Honeydew3': <ColorType.Honeydew3: 12701121>, 'Honeydew4': <ColorType.Honeydew4: 8620931>, 'LavenderBlush1': <ColorType.LavenderBlush: 16773365>, 'LavenderBlush2': <ColorType.LavenderBlush2: 15655141>, 'LavenderBlush3': <ColorType.LavenderBlush3: 13484485>, 'LavenderBlush4': <ColorType.LavenderBlush4: 9143174>, 'MistyRose1': <ColorType.MistyRose: 16770273>, 'MistyRose2': <ColorType.MistyRose2: 15652306>, 'MistyRose3': <ColorType.MistyRose3: 13481909>, 'MistyRose4': <ColorType.MistyRose4: 9141627>, 'Azure1': <ColorType.Azure: 15794175>, 'Azure2': <ColorType.Azure2: 14741230>, 'Azure3': <ColorType.Azure3: 12701133>, 'Azure4': <ColorType.Azure4: 8620939>, 'SlateBlue1': <ColorType.SlateBlue1: 8613887>, 'SlateBlue2': <ColorType.SlateBlue2: 8021998>, 'SlateBlue3': <ColorType.SlateBlue3: 6904269>, 'SlateBlue4': <ColorType.SlateBlue4: 4668555>, 'RoyalBlue1': <ColorType.RoyalBlue1: 4749055>, 'RoyalBlue2': <ColorType.RoyalBlue2: 4419310>, 'RoyalBlue3': <ColorType.RoyalBlue3: 3825613>, 'RoyalBlue4': <ColorType.RoyalBlue4: 2572427>, 'Blue1': <ColorType.Blue: 255>, 'Blue2': <ColorType.Blue2: 238>, 'Blue3': <ColorType.MediumBlue: 205>, 'Blue4': <ColorType.Blue4: 139>, 'DodgerBlue1': <ColorType.DodgerBlue: 2003199>, 'DodgerBlue2': <ColorType.DodgerBlue2: 1869550>, 'DodgerBlue3': <ColorType.DodgerBlue3: 1602765>, 'DodgerBlue4': <ColorType.DodgerBlue4: 1068683>, 'SteelBlue1': <ColorType.SteelBlue1: 6535423>, 'SteelBlue2': <ColorType.SteelBlue2: 6073582>, 'SteelBlue3': <ColorType.SteelBlue3: 5215437>, 'SteelBlue4': <ColorType.SteelBlue4: 3564683>, 'DeepSkyBlue1': <ColorType.DeepSkyBlue: 49151>, 'DeepSkyBlue2': <ColorType.DeepSkyBlue2: 45806>, 'DeepSkyBlue3': <ColorType.DeepSkyBlue3: 39629>, 'DeepSkyBlue4': <ColorType.DeepSkyBlue4: 26763>, 'SkyBlue1': <ColorType.SkyBlue1: 8900351>, 'SkyBlue2': <ColorType.SkyBlue2: 8306926>, 'SkyBlue3': <ColorType.SkyBlue3: 7120589>, 'SkyBlue4': <ColorType.SkyBlue4: 4878475>, 'LightSkyBlue1': <ColorType.LightSkyBlue1: 11592447>, 'LightSkyBlue2': <ColorType.LightSkyBlue2: 10802158>, 'LightSkyBlue3': <ColorType.LightSkyBlue3: 9287373>, 'LightSkyBlue4': <ColorType.LightSkyBlue4: 6323083>, 'SlateGray1': <ColorType.SlateGray1: 13034239>, 'SlateGray2': <ColorType.SlateGray2: 12178414>, 'SlateGray3': <ColorType.SlateGray3: 10467021>, 'SlateGray4': <ColorType.SlateGray4: 7109515>, 'LightSteelBlue1': <ColorType.LightSteelBlue1: 13296127>, 'LightSteelBlue2': <ColorType.LightSteelBlue2: 12374766>, 'LightSteelBlue3': <ColorType.LightSteelBlue3: 10663373>, 'LightSteelBlue4': <ColorType.LightSteelBlue4: 7240587>, 'LightBlue1': <ColorType.LightBlue1: 12578815>, 'LightBlue2': <ColorType.LightBlue2: 11722734>, 'LightBlue3': <ColorType.LightBlue3: 10141901>, 'LightBlue4': <ColorType.LightBlue4: 6849419>, 'LightCyan1': <ColorType.LightCyan: 14745599>, 'LightCyan2': <ColorType.LightCyan2: 13758190>, 'LightCyan3': <ColorType.LightCyan3: 11849165>, 'LightCyan4': <ColorType.LightCyan4: 8031115>, 'PaleTurquoise1': <ColorType.PaleTurquoise1: 12320767>, 'PaleTurquoise2': <ColorType.PaleTurquoise2: 11464430>, 'PaleTurquoise3': <ColorType.PaleTurquoise3: 9883085>, 'PaleTurquoise4': <ColorType.PaleTurquoise4: 6720395>, 'CadetBlue1': <ColorType.CadetBlue1: 10024447>, 'CadetBlue2': <ColorType.CadetBlue2: 9364974>, 'CadetBlue3': <ColorType.CadetBlue3: 8046029>, 'CadetBlue4': <ColorType.CadetBlue4: 5473931>, 'Turquoise1': <ColorType.Turquoise1: 62975>, 'Turquoise2': <ColorType.Turquoise2: 58862>, 'Turquoise3': <ColorType.Turquoise3: 50637>, 'Turquoise4': <ColorType.Turquoise4: 34443>, 'Cyan1': <ColorType.Cyan: 65535>, 'Cyan2': <ColorType.Cyan2: 61166>, 'Cyan3': <ColorType.Cyan3: 52685>, 'Cyan4': <ColorType.Cyan4: 35723>, 'DarkSlateGray1': <ColorType.DarkSlateGray1: 9961471>, 'DarkSlateGray2': <ColorType.DarkSlateGray2: 9301742>, 'DarkSlateGray3': <ColorType.DarkSlateGray3: 7982541>, 'DarkSlateGray4': <ColorType.DarkSlateGray4: 5409675>, 'Aquamarine1': <ColorType.Aquamarine: 8388564>, 'Aquamarine2': <ColorType.Aquamarine2: 7794374>, 'Aquamarine3': <ColorType.MediumAquamarine: 6737322>, 'Aquamarine4': <ColorType.Aquamarine4: 4557684>, 'DarkSeaGreen1': <ColorType.DarkSeaGreen1: 12713921>, 'DarkSeaGreen2': <ColorType.DarkSeaGreen2: 11857588>, 'DarkSeaGreen3': <ColorType.DarkSeaGreen3: 10210715>, 'DarkSeaGreen4': <ColorType.DarkSeaGreen4: 6916969>, 'SeaGreen1': <ColorType.SeaGreen1: 5570463>, 'SeaGreen2': <ColorType.SeaGreen2: 5172884>, 'SeaGreen3': <ColorType.SeaGreen3: 4443520>, 'SeaGreen4': <ColorType.SeaGreen: 3050327>, 'PaleGreen1': <ColorType.PaleGreen1: 10157978>, 'PaleGreen2': <ColorType.PaleGreen2: 9498256>, 'PaleGreen3': <ColorType.PaleGreen3: 8179068>, 'PaleGreen4': <ColorType.PaleGreen4: 5540692>, 'SpringGreen1': <ColorType.SpringGreen: 65407>, 'SpringGreen2': <ColorType.SpringGreen2: 61046>, 'SpringGreen3': <ColorType.SpringGreen3: 52582>, 'SpringGreen4': <ColorType.SpringGreen4: 35653>, 'Green1': <ColorType.Green: 65280>, 'Green2': <ColorType.Green2: 60928>, 'Green3': <ColorType.Green3: 52480>, 'Green4': <ColorType.Green4: 35584>, 'Chartreuse1': <ColorType.Chartreuse: 8388352>, 'Chartreuse2': <ColorType.Chartreuse2: 7794176>, 'Chartreuse3': <ColorType.Chartreuse3: 6737152>, 'Chartreuse4': <ColorType.Chartreuse4: 4557568>, 'OliveDrab1': <ColorType.OliveDrab1: 12648254>, 'OliveDrab2': <ColorType.OliveDrab2: 11791930>, 'OliveDrab3': <ColorType.YellowGreen: 10145074>, 'OliveDrab4': <ColorType.OliveDrab4: 6916898>, 'DarkOliveGreen1': <ColorType.DarkOliveGreen1: 13303664>, 'DarkOliveGreen2': <ColorType.DarkOliveGreen2: 12381800>, 'DarkOliveGreen3': <ColorType.DarkOliveGreen3: 10669402>, 'DarkOliveGreen4': <ColorType.DarkOliveGreen4: 7244605>, 'Khaki1': <ColorType.Khaki1: 16774799>, 'Khaki2': <ColorType.Khaki2: 15656581>, 'Khaki3': <ColorType.Khaki3: 13485683>, 'Khaki4': <ColorType.Khaki4: 9143886>, 'LightGoldenrod1': <ColorType.LightGoldenrod1: 16772235>, 'LightGoldenrod2': <ColorType.LightGoldenrod2: 15654018>, 'LightGoldenrod3': <ColorType.LightGoldenrod3: 13483632>, 'LightGoldenrod4': <ColorType.LightGoldenrod4: 9142604>, 'LightYellow1': <ColorType.LightYellow: 16777184>, 'LightYellow2': <ColorType.LightYellow2: 15658705>, 'LightYellow3': <ColorType.LightYellow3: 13487540>, 'LightYellow4': <ColorType.LightYellow4: 9145210>, 'Yellow1': <ColorType.Yellow: 16776960>, 'Yellow2': <ColorType.Yellow2: 15658496>, 'Yellow3': <ColorType.Yellow3: 13487360>, 'Yellow4': <ColorType.Yellow4: 9145088>, 'Gold1': <ColorType.Gold: 16766720>, 'Gold2': <ColorType.Gold2: 15649024>, 'Gold3': <ColorType.Gold3: 13479168>, 'Gold4': <ColorType.Gold4: 9139456>, 'Goldenrod1': <ColorType.Goldenrod1: 16761125>, 'Goldenrod2': <ColorType.Goldenrod2: 15643682>, 'Goldenrod3': <ColorType.Goldenrod3: 13474589>, 'Goldenrod4': <ColorType.Goldenrod4: 9136404>, 'DarkGoldenrod1': <ColorType.DarkGoldenrod1: 16759055>, 'DarkGoldenrod2': <ColorType.DarkGoldenrod2: 15641870>, 'DarkGoldenrod3': <ColorType.DarkGoldenrod3: 13473036>, 'DarkGoldenrod4': <ColorType.DarkGoldenrod4: 9135368>, 'RosyBrown1': <ColorType.RosyBrown1: 16761281>, 'RosyBrown2': <ColorType.RosyBrown2: 15643828>, 'RosyBrown3': <ColorType.RosyBrown3: 13474715>, 'RosyBrown4': <ColorType.RosyBrown4: 9136489>, 'IndianRed1': <ColorType.IndianRed1: 16738922>, 'IndianRed2': <ColorType.IndianRed2: 15623011>, 'IndianRed3': <ColorType.IndianRed3: 13456725>, 'IndianRed4': <ColorType.IndianRed4: 9124410>, 'Sienna1': <ColorType.Sienna1: 16745031>, 'Sienna2': <ColorType.Sienna2: 15628610>, 'Sienna3': <ColorType.Sienna3: 13461561>, 'Sienna4': <ColorType.Sienna4: 9127718>, 'Burlywood1': <ColorType.Burlywood1: 16765851>, 'Burlywood2': <ColorType.Burlywood2: 15648145>, 'Burlywood3': <ColorType.Burlywood3: 13478525>, 'Burlywood4': <ColorType.Burlywood4: 9139029>, 'Wheat1': <ColorType.Wheat1: 16771002>, 'Wheat2': <ColorType.Wheat2: 15653038>, 'Wheat3': <ColorType.Wheat3: 13482646>, 'Wheat4': <ColorType.Wheat4: 9141862>, 'Tan1': <ColorType.Tan1: 16753999>, 'Tan2': <ColorType.Tan2: 15637065>, 'Tan3': <ColorType.Peru: 13468991>, 'Tan4': <ColorType.Tan4: 9132587>, 'Chocolate1': <ColorType.Chocolate1: 16744228>, 'Chocolate2': <ColorType.Chocolate2: 15627809>, 'Chocolate3': <ColorType.Chocolate3: 13461021>, 'Chocolate4': <ColorType.SaddleBrown: 9127187>, 'Firebrick1': <ColorType.Firebrick1: 16724016>, 'Firebrick2': <ColorType.Firebrick2: 15608876>, 'Firebrick3': <ColorType.Firebrick3: 13444646>, 'Firebrick4': <ColorType.Firebrick4: 9116186>, 'Brown1': <ColorType.Brown1: 16728128>, 'Brown2': <ColorType.Brown2: 15612731>, 'Brown3': <ColorType.Brown3: 13447987>, 'Brown4': <ColorType.Brown4: 9118499>, 'Salmon1': <ColorType.Salmon1: 16747625>, 'Salmon2': <ColorType.Salmon2: 15630946>, 'Salmon3': <ColorType.Salmon3: 13463636>, 'Salmon4': <ColorType.Salmon4: 9129017>, 'LightSalmon1': <ColorType.LightSalmon: 16752762>, 'LightSalmon2': <ColorType.LightSalmon2: 15635826>, 'LightSalmon3': <ColorType.LightSalmon3: 13468002>, 'LightSalmon4': <ColorType.LightSalmon4: 9131842>, 'Orange1': <ColorType.Orange: 16753920>, 'Orange2': <ColorType.Orange2: 15636992>, 'Orange3': <ColorType.Orange3: 13468928>, 'Orange4': <ColorType.Orange4: 9132544>, 'DarkOrange1': <ColorType.DarkOrange1: 16744192>, 'DarkOrange2': <ColorType.DarkOrange2: 15627776>, 'DarkOrange3': <ColorType.DarkOrange3: 13460992>, 'DarkOrange4': <ColorType.DarkOrange4: 9127168>, 'Coral1': <ColorType.Coral1: 16740950>, 'Coral2': <ColorType.Coral2: 15624784>, 'Coral3': <ColorType.Coral3: 13458245>, 'Coral4': <ColorType.Coral4: 9125423>, 'Tomato1': <ColorType.Tomato: 16737095>, 'Tomato2': <ColorType.Tomato2: 15621186>, 'Tomato3': <ColorType.Tomato3: 13455161>, 'Tomato4': <ColorType.Tomato4: 9123366>, 'OrangeRed1': <ColorType.OrangeRed: 16729344>, 'OrangeRed2': <ColorType.OrangeRed2: 15613952>, 'OrangeRed3': <ColorType.OrangeRed3: 13448960>, 'OrangeRed4': <ColorType.OrangeRed4: 9118976>, 'Red1': <ColorType.Red: 16711680>, 'Red2': <ColorType.Red2: 15597568>, 'Red3': <ColorType.Red3: 13434880>, 'Red4': <ColorType.Red4: 9109504>, 'DeepPink1': <ColorType.DeepPink: 16716947>, 'DeepPink2': <ColorType.DeepPink2: 15602313>, 'DeepPink3': <ColorType.DeepPink3: 13439094>, 'DeepPink4': <ColorType.DeepPink4: 9112144>, 'HotPink1': <ColorType.HotPink1: 16740020>, 'HotPink2': <ColorType.HotPink2: 15624871>, 'HotPink3': <ColorType.HotPink3: 13459600>, 'HotPink4': <ColorType.HotPink4: 9124450>, 'Pink1': <ColorType.Pink1: 16758213>, 'Pink2': <ColorType.Pink2: 15641016>, 'Pink3': <ColorType.Pink3: 13472158>, 'Pink4': <ColorType.Pink4: 9134956>, 'LightPink1': <ColorType.LightPink1: 16756409>, 'LightPink2': <ColorType.LightPink2: 15639213>, 'LightPink3': <ColorType.LightPink3: 13470869>, 'LightPink4': <ColorType.LightPink4: 9133925>, 'PaleVioletRed1': <ColorType.PaleVioletRed1: 16745131>, 'PaleVioletRed2': <ColorType.PaleVioletRed2: 15628703>, 'PaleVioletRed3': <ColorType.PaleVioletRed3: 13461641>, 'PaleVioletRed4': <ColorType.PaleVioletRed4: 9127773>, 'Maroon1': <ColorType.Maroon1: 16725171>, 'Maroon2': <ColorType.Maroon2: 15610023>, 'Maroon3': <ColorType.Maroon3: 13445520>, 'Maroon4': <ColorType.Maroon4: 9116770>, 'VioletRed1': <ColorType.VioletRed1: 16727702>, 'VioletRed2': <ColorType.VioletRed2: 15612556>, 'VioletRed3': <ColorType.VioletRed3: 13447800>, 'VioletRed4': <ColorType.VioletRed4: 9118290>, 'Magenta1': <ColorType.Magenta: 16711935>, 'Magenta2': <ColorType.Magenta2: 15597806>, 'Magenta3': <ColorType.Magenta3: 13435085>, 'Magenta4': <ColorType.Magenta4: 9109643>, 'Orchid1': <ColorType.Orchid1: 16745466>, 'Orchid2': <ColorType.Orchid2: 15629033>, 'Orchid3': <ColorType.Orchid3: 13461961>, 'Orchid4': <ColorType.Orchid4: 9127817>, 'Plum1': <ColorType.Plum1: 16759807>, 'Plum2': <ColorType.Plum2: 15642350>, 'Plum3': <ColorType.Plum3: 13473485>, 'Plum4': <ColorType.Plum4: 9135755>, 'MediumOrchid1': <ColorType.MediumOrchid1: 14706431>, 'MediumOrchid2': <ColorType.MediumOrchid2: 13721582>, 'MediumOrchid3': <ColorType.MediumOrchid3: 11817677>, 'MediumOrchid4': <ColorType.MediumOrchid4: 8009611>, 'DarkOrchid1': <ColorType.DarkOrchid1: 12533503>, 'DarkOrchid2': <ColorType.DarkOrchid2: 11680494>, 'DarkOrchid3': <ColorType.DarkOrchid3: 10105549>, 'DarkOrchid4': <ColorType.DarkOrchid4: 6824587>, 'Purple1': <ColorType.Purple1: 10170623>, 'Purple2': <ColorType.Purple2: 9514222>, 'Purple3': <ColorType.Purple3: 8201933>, 'Purple4': <ColorType.Purple4: 5577355>, 'MediumPurple1': <ColorType.MediumPurple1: 11240191>, 'MediumPurple2': <ColorType.MediumPurple2: 10451438>, 'MediumPurple3': <ColorType.MediumPurple3: 9005261>, 'MediumPurple4': <ColorType.MediumPurple4: 6113163>, 'Thistle1': <ColorType.Thistle1: 16769535>, 'Thistle2': <ColorType.Thistle2: 15651566>, 'Thistle3': <ColorType.Thistle3: 13481421>, 'Thistle4': <ColorType.Thistle4: 9141131>, 'Gray0': <ColorType.Black: 0>, 'Grey0': <ColorType.Black: 0>, 'Gray1': <ColorType.Gray1: 197379>, 'Grey1': <ColorType.Gray1: 197379>, 'Gray2': <ColorType.Gray2: 328965>, 'Grey2': <ColorType.Gray2: 328965>, 'Gray3': <ColorType.Gray3: 526344>, 'Grey3': <ColorType.Gray3: 526344>, 'Gray4': <ColorType.Gray4: 657930>, 'Grey4': <ColorType.Gray4: 657930>, 'Gray5': <ColorType.Gray5: 855309>, 'Grey5': <ColorType.Gray5: 855309>, 'Gray6': <ColorType.Gray6: 986895>, 'Grey6': <ColorType.Gray6: 986895>, 'Gray7': <ColorType.Gray7: 1184274>, 'Grey7': <ColorType.Gray7: 1184274>, 'Gray8': <ColorType.Gray8: 1315860>, 'Grey8': <ColorType.Gray8: 1315860>, 'Gray9': <ColorType.Gray9: 1513239>, 'Grey9': <ColorType.Gray9: 1513239>, 'Gray10': <ColorType.Gray10: 1710618>, 'Grey10': <ColorType.Gray10: 1710618>, 'Gray11': <ColorType.Gray11: 1842204>, 'Grey11': <ColorType.Gray11: 1842204>, 'Gray12': <ColorType.Gray12: 2039583>, 'Grey12': <ColorType.Gray12: 2039583>, 'Gray13': <ColorType.Gray13: 2171169>, 'Grey13': <ColorType.Gray13: 2171169>, 'Gray14': <ColorType.Gray14: 2368548>, 'Grey14': <ColorType.Gray14: 2368548>, 'Gray15': <ColorType.Gray15: 2500134>, 'Grey15': <ColorType.Gray15: 2500134>, 'Gray16': <ColorType.Gray16: 2697513>, 'Grey16': <ColorType.Gray16: 2697513>, 'Gray17': <ColorType.Gray17: 2829099>, 'Grey17': <ColorType.Gray17: 2829099>, 'Gray18': <ColorType.Gray18: 3026478>, 'Grey18': <ColorType.Gray18: 3026478>, 'Gray19': <ColorType.Gray19: 3158064>, 'Grey19': <ColorType.Gray19: 3158064>, 'Gray20': <ColorType.Gray20: 3355443>, 'Grey20': <ColorType.Gray20: 3355443>, 'Gray21': <ColorType.Gray21: 3552822>, 'Grey21': <ColorType.Gray21: 3552822>, 'Gray22': <ColorType.Gray22: 3684408>, 'Grey22': <ColorType.Gray22: 3684408>, 'Gray23': <ColorType.Gray23: 3881787>, 'Grey23': <ColorType.Gray23: 3881787>, 'Gray24': <ColorType.Gray24: 4013373>, 'Grey24': <ColorType.Gray24: 4013373>, 'Gray25': <ColorType.Gray25: 4210752>, 'Grey25': <ColorType.Gray25: 4210752>, 'Gray26': <ColorType.Gray26: 4342338>, 'Grey26': <ColorType.Gray26: 4342338>, 'Gray27': <ColorType.Gray27: 4539717>, 'Grey27': <ColorType.Gray27: 4539717>, 'Gray28': <ColorType.Gray28: 4671303>, 'Grey28': <ColorType.Gray28: 4671303>, 'Gray29': <ColorType.Gray29: 4868682>, 'Grey29': <ColorType.Gray29: 4868682>, 'Gray30': <ColorType.Gray30: 5066061>, 'Grey30': <ColorType.Gray30: 5066061>, 'Gray31': <ColorType.Gray31: 5197647>, 'Grey31': <ColorType.Gray31: 5197647>, 'Gray32': <ColorType.Gray32: 5395026>, 'Grey32': <ColorType.Gray32: 5395026>, 'Gray33': <ColorType.Gray33: 5526612>, 'Grey33': <ColorType.Gray33: 5526612>, 'Gray34': <ColorType.Gray34: 5723991>, 'Grey34': <ColorType.Gray34: 5723991>, 'Gray35': <ColorType.Gray35: 5855577>, 'Grey35': <ColorType.Gray35: 5855577>, 'Gray36': <ColorType.Gray36: 6052956>, 'Grey36': <ColorType.Gray36: 6052956>, 'Gray37': <ColorType.Gray37: 6184542>, 'Grey37': <ColorType.Gray37: 6184542>, 'Gray38': <ColorType.Gray38: 6381921>, 'Grey38': <ColorType.Gray38: 6381921>, 'Gray39': <ColorType.Gray39: 6513507>, 'Grey39': <ColorType.Gray39: 6513507>, 'Gray40': <ColorType.Gray40: 6710886>, 'Grey40': <ColorType.Gray40: 6710886>, 'Gray41': <ColorType.DimGray: 6908265>, 'Grey41': <ColorType.DimGray: 6908265>, 'Gray42': <ColorType.Gray42: 7039851>, 'Grey42': <ColorType.Gray42: 7039851>, 'Gray43': <ColorType.Gray43: 7237230>, 'Grey43': <ColorType.Gray43: 7237230>, 'Gray44': <ColorType.Gray44: 7368816>, 'Grey44': <ColorType.Gray44: 7368816>, 'Gray45': <ColorType.Gray45: 7566195>, 'Grey45': <ColorType.Gray45: 7566195>, 'Gray46': <ColorType.Gray46: 7697781>, 'Grey46': <ColorType.Gray46: 7697781>, 'Gray47': <ColorType.Gray47: 7895160>, 'Grey47': <ColorType.Gray47: 7895160>, 'Gray48': <ColorType.Gray48: 8026746>, 'Grey48': <ColorType.Gray48: 8026746>, 'Gray49': <ColorType.Gray49: 8224125>, 'Grey49': <ColorType.Gray49: 8224125>, 'Gray50': <ColorType.Gray50: 8355711>, 'Grey50': <ColorType.Gray50: 8355711>, 'Gray51': <ColorType.Gray51: 8553090>, 'Grey51': <ColorType.Gray51: 8553090>, 'Gray52': <ColorType.Gray52: 8750469>, 'Grey52': <ColorType.Gray52: 8750469>, 'Gray53': <ColorType.Gray53: 8882055>, 'Grey53': <ColorType.Gray53: 8882055>, 'Gray54': <ColorType.Gray54: 9079434>, 'Grey54': <ColorType.Gray54: 9079434>, 'Gray55': <ColorType.Gray55: 9211020>, 'Grey55': <ColorType.Gray55: 9211020>, 'Gray56': <ColorType.Gray56: 9408399>, 'Grey56': <ColorType.Gray56: 9408399>, 'Gray57': <ColorType.Gray57: 9539985>, 'Grey57': <ColorType.Gray57: 9539985>, 'Gray58': <ColorType.Gray58: 9737364>, 'Grey58': <ColorType.Gray58: 9737364>, 'Gray59': <ColorType.Gray59: 9868950>, 'Grey59': <ColorType.Gray59: 9868950>, 'Gray60': <ColorType.Gray60: 10066329>, 'Grey60': <ColorType.Gray60: 10066329>, 'Gray61': <ColorType.Gray61: 10263708>, 'Grey61': <ColorType.Gray61: 10263708>, 'Gray62': <ColorType.Gray62: 10395294>, 'Grey62': <ColorType.Gray62: 10395294>, 'Gray63': <ColorType.Gray63: 10592673>, 'Grey63': <ColorType.Gray63: 10592673>, 'Gray64': <ColorType.Gray64: 10724259>, 'Grey64': <ColorType.Gray64: 10724259>, 'Gray65': <ColorType.Gray65: 10921638>, 'Grey65': <ColorType.Gray65: 10921638>, 'Gray66': <ColorType.Gray66: 11053224>, 'Grey66': <ColorType.Gray66: 11053224>, 'Gray67': <ColorType.Gray67: 11250603>, 'Grey67': <ColorType.Gray67: 11250603>, 'Gray68': <ColorType.Gray68: 11382189>, 'Grey68': <ColorType.Gray68: 11382189>, 'Gray69': <ColorType.Gray69: 11579568>, 'Grey69': <ColorType.Gray69: 11579568>, 'Gray70': <ColorType.Gray70: 11776947>, 'Grey70': <ColorType.Gray70: 11776947>, 'Gray71': <ColorType.Gray71: 11908533>, 'Grey71': <ColorType.Gray71: 11908533>, 'Gray72': <ColorType.Gray72: 12105912>, 'Grey72': <ColorType.Gray72: 12105912>, 'Gray73': <ColorType.Gray73: 12237498>, 'Grey73': <ColorType.Gray73: 12237498>, 'Gray74': <ColorType.Gray74: 12434877>, 'Grey74': <ColorType.Gray74: 12434877>, 'Gray75': <ColorType.Gray75: 12566463>, 'Grey75': <ColorType.Gray75: 12566463>, 'Gray76': <ColorType.Gray76: 12763842>, 'Grey76': <ColorType.Gray76: 12763842>, 'Gray77': <ColorType.Gray77: 12895428>, 'Grey77': <ColorType.Gray77: 12895428>, 'Gray78': <ColorType.Gray78: 13092807>, 'Grey78': <ColorType.Gray78: 13092807>, 'Gray79': <ColorType.Gray79: 13224393>, 'Grey79': <ColorType.Gray79: 13224393>, 'Gray80': <ColorType.Gray80: 13421772>, 'Grey80': <ColorType.Gray80: 13421772>, 'Gray81': <ColorType.Gray81: 13619151>, 'Grey81': <ColorType.Gray81: 13619151>, 'Gray82': <ColorType.Gray82: 13750737>, 'Grey82': <ColorType.Gray82: 13750737>, 'Gray83': <ColorType.Gray83: 13948116>, 'Grey83': <ColorType.Gray83: 13948116>, 'Gray84': <ColorType.Gray84: 14079702>, 'Grey84': <ColorType.Gray84: 14079702>, 'Gray85': <ColorType.Gray85: 14277081>, 'Grey85': <ColorType.Gray85: 14277081>, 'Gray86': <ColorType.Gray86: 14408667>, 'Grey86': <ColorType.Gray86: 14408667>, 'Gray87': <ColorType.Gray87: 14606046>, 'Grey87': <ColorType.Gray87: 14606046>, 'Gray88': <ColorType.Gray88: 14737632>, 'Grey88': <ColorType.Gray88: 14737632>, 'Gray89': <ColorType.Gray89: 14935011>, 'Grey89': <ColorType.Gray89: 14935011>, 'Gray90': <ColorType.Gray90: 15066597>, 'Grey90': <ColorType.Gray90: 15066597>, 'Gray91': <ColorType.Gray91: 15263976>, 'Grey91': <ColorType.Gray91: 15263976>, 'Gray92': <ColorType.Gray92: 15461355>, 'Grey92': <ColorType.Gray92: 15461355>, 'Gray93': <ColorType.Gray93: 15592941>, 'Grey93': <ColorType.Gray93: 15592941>, 'Gray94': <ColorType.Gray94: 15790320>, 'Grey94': <ColorType.Gray94: 15790320>, 'Gray95': <ColorType.Gray95: 15921906>, 'Grey95': <ColorType.Gray95: 15921906>, 'Gray96': <ColorType.WhiteSmoke: 16119285>, 'Grey96': <ColorType.WhiteSmoke: 16119285>, 'Gray97': <ColorType.Gray97: 16250871>, 'Grey97': <ColorType.Gray97: 16250871>, 'Gray98': <ColorType.Gray98: 16448250>, 'Grey98': <ColorType.Gray98: 16448250>, 'Gray99': <ColorType.Gray99: 16579836>, 'Grey99': <ColorType.Gray99: 16579836>, 'Gray100': <ColorType.White: 16777215>, 'Grey100': <ColorType.White: 16777215>, 'DarkGrey': <ColorType.DarkGrey: 11119017>, 'DarkGray': <ColorType.DarkGrey: 11119017>, 'DarkBlue': <ColorType.Blue4: 139>, 'DarkCyan': <ColorType.Cyan4: 35723>, 'DarkMagenta': <ColorType.Magenta4: 9109643>, 'DarkRed': <ColorType.Red4: 9109504>, 'LightGreen': <ColorType.PaleGreen2: 9498256>, 'Crimson': <ColorType.Crimson: 14423100>, 'Indigo': <ColorType.Indigo: 4915330>, 'Olive': <ColorType.Olive: 8421376>, 'RebeccaPurple': <ColorType.RebeccaPurple: 6697881>, 'Silver': <ColorType.Silver: 12632256>, 'Teal': <ColorType.Teal: 32896>}
    pass
class PlotFormatType():
    """
    Members:

      Number

      Memory

      Percentage
    """
    def __eq__(self, other: object) -> bool: ...
    def __getstate__(self) -> int: ...
    def __hash__(self) -> int: ...
    def __index__(self) -> int: ...
    def __init__(self, value: int) -> None: ...
    def __int__(self) -> int: ...
    def __ne__(self, other: object) -> bool: ...
    def __repr__(self) -> str: ...
    def __setstate__(self, state: int) -> None: ...
    @property
    def name(self) -> str:
        """
        :type: str
        """
    @property
    def value(self) -> int:
        """
        :type: int
        """
    Memory: TracyClientBindings.PlotFormatType # value = <PlotFormatType.Memory: 1>
    Number: TracyClientBindings.PlotFormatType # value = <PlotFormatType.Number: 0>
    Percentage: TracyClientBindings.PlotFormatType # value = <PlotFormatType.Percentage: 2>
    __members__: dict # value = {'Number': <PlotFormatType.Number: 0>, 'Memory': <PlotFormatType.Memory: 1>, 'Percentage': <PlotFormatType.Percentage: 2>}
    pass
class _ScopedZone():
    def __init__(self, name: typing.Optional[str], color: int, depth: typing.Optional[int], active: bool, function: str, file: str, line: int) -> None: ...
    def _color(self, color: int) -> None: ...
    def enter(self) -> None: ...
    def exit(self) -> None: ...
    def name(self, name: str) -> bool: ...
    @typing.overload
    def text(self, text: str) -> bool: ...
    @typing.overload
    def text(self, text: object) -> bool: ...
    @property
    def is_active(self) -> bool:
        """
        :type: bool
        """
    pass
def _plot_config(name: str, type: int, step: bool, fill: bool, color: int) -> typing.Optional[int]:
    pass
@typing.overload
def alloc(ptr: int, size: int, name: typing.Optional[str] = None, id: typing.Optional[int] = None, depth: typing.Optional[int] = None) -> typing.Optional[int]:
    pass
@typing.overload
def alloc(object: object, size: int, name: typing.Optional[str] = None, id: typing.Optional[int] = None, depth: typing.Optional[int] = None) -> typing.Optional[int]:
    pass
def app_info(text: str) -> bool:
    pass
def frame_image(data: bytes, width: int, height: int, offset: int = 0, flip: bool = False) -> bool:
    pass
def frame_mark() -> None:
    pass
def frame_mark_end(name: int) -> bool:
    pass
def frame_mark_start(name: str) -> typing.Optional[int]:
    pass
@typing.overload
def free(ptr: int, id: typing.Optional[int] = None, depth: typing.Optional[int] = None) -> bool:
    pass
@typing.overload
def free(object: object, id: typing.Optional[int] = None, depth: typing.Optional[int] = None) -> bool:
    pass
def is_enabled() -> bool:
    pass
@typing.overload
def message(message: str) -> bool:
    pass
@typing.overload
def message(message: str, color: int) -> bool:
    pass
@typing.overload
def plot(id: int, value: float) -> bool:
    pass
@typing.overload
def plot(id: int, value: int) -> bool:
    pass
def program_name(name: str) -> bool:
    pass
def thread_name(name: str) -> None:
    pass
AliceBlue: TracyClientBindings.ColorType # value = <ColorType.AliceBlue: 15792383>
AntiqueWhite: TracyClientBindings.ColorType # value = <ColorType.AntiqueWhite: 16444375>
AntiqueWhite1: TracyClientBindings.ColorType # value = <ColorType.AntiqueWhite1: 16773083>
AntiqueWhite2: TracyClientBindings.ColorType # value = <ColorType.AntiqueWhite2: 15654860>
AntiqueWhite3: TracyClientBindings.ColorType # value = <ColorType.AntiqueWhite3: 13484208>
AntiqueWhite4: TracyClientBindings.ColorType # value = <ColorType.AntiqueWhite4: 9143160>
Aqua: TracyClientBindings.ColorType # value = <ColorType.Cyan: 65535>
Aquamarine: TracyClientBindings.ColorType # value = <ColorType.Aquamarine: 8388564>
Aquamarine1: TracyClientBindings.ColorType # value = <ColorType.Aquamarine: 8388564>
Aquamarine2: TracyClientBindings.ColorType # value = <ColorType.Aquamarine2: 7794374>
Aquamarine3: TracyClientBindings.ColorType # value = <ColorType.MediumAquamarine: 6737322>
Aquamarine4: TracyClientBindings.ColorType # value = <ColorType.Aquamarine4: 4557684>
Azure: TracyClientBindings.ColorType # value = <ColorType.Azure: 15794175>
Azure1: TracyClientBindings.ColorType # value = <ColorType.Azure: 15794175>
Azure2: TracyClientBindings.ColorType # value = <ColorType.Azure2: 14741230>
Azure3: TracyClientBindings.ColorType # value = <ColorType.Azure3: 12701133>
Azure4: TracyClientBindings.ColorType # value = <ColorType.Azure4: 8620939>
Beige: TracyClientBindings.ColorType # value = <ColorType.Beige: 16119260>
Bisque: TracyClientBindings.ColorType # value = <ColorType.Bisque: 16770244>
Bisque1: TracyClientBindings.ColorType # value = <ColorType.Bisque: 16770244>
Bisque2: TracyClientBindings.ColorType # value = <ColorType.Bisque2: 15652279>
Bisque3: TracyClientBindings.ColorType # value = <ColorType.Bisque3: 13481886>
Bisque4: TracyClientBindings.ColorType # value = <ColorType.Bisque4: 9141611>
Black: TracyClientBindings.ColorType # value = <ColorType.Black: 0>
BlanchedAlmond: TracyClientBindings.ColorType # value = <ColorType.BlanchedAlmond: 16772045>
Blue: TracyClientBindings.ColorType # value = <ColorType.Blue: 255>
Blue1: TracyClientBindings.ColorType # value = <ColorType.Blue: 255>
Blue2: TracyClientBindings.ColorType # value = <ColorType.Blue2: 238>
Blue3: TracyClientBindings.ColorType # value = <ColorType.MediumBlue: 205>
Blue4: TracyClientBindings.ColorType # value = <ColorType.Blue4: 139>
BlueViolet: TracyClientBindings.ColorType # value = <ColorType.BlueViolet: 9055202>
Brown: TracyClientBindings.ColorType # value = <ColorType.Brown: 10824234>
Brown1: TracyClientBindings.ColorType # value = <ColorType.Brown1: 16728128>
Brown2: TracyClientBindings.ColorType # value = <ColorType.Brown2: 15612731>
Brown3: TracyClientBindings.ColorType # value = <ColorType.Brown3: 13447987>
Brown4: TracyClientBindings.ColorType # value = <ColorType.Brown4: 9118499>
Burlywood: TracyClientBindings.ColorType # value = <ColorType.Burlywood: 14596231>
Burlywood1: TracyClientBindings.ColorType # value = <ColorType.Burlywood1: 16765851>
Burlywood2: TracyClientBindings.ColorType # value = <ColorType.Burlywood2: 15648145>
Burlywood3: TracyClientBindings.ColorType # value = <ColorType.Burlywood3: 13478525>
Burlywood4: TracyClientBindings.ColorType # value = <ColorType.Burlywood4: 9139029>
CadetBlue: TracyClientBindings.ColorType # value = <ColorType.CadetBlue: 6266528>
CadetBlue1: TracyClientBindings.ColorType # value = <ColorType.CadetBlue1: 10024447>
CadetBlue2: TracyClientBindings.ColorType # value = <ColorType.CadetBlue2: 9364974>
CadetBlue3: TracyClientBindings.ColorType # value = <ColorType.CadetBlue3: 8046029>
CadetBlue4: TracyClientBindings.ColorType # value = <ColorType.CadetBlue4: 5473931>
Chartreuse: TracyClientBindings.ColorType # value = <ColorType.Chartreuse: 8388352>
Chartreuse1: TracyClientBindings.ColorType # value = <ColorType.Chartreuse: 8388352>
Chartreuse2: TracyClientBindings.ColorType # value = <ColorType.Chartreuse2: 7794176>
Chartreuse3: TracyClientBindings.ColorType # value = <ColorType.Chartreuse3: 6737152>
Chartreuse4: TracyClientBindings.ColorType # value = <ColorType.Chartreuse4: 4557568>
Chocolate: TracyClientBindings.ColorType # value = <ColorType.Chocolate: 13789470>
Chocolate1: TracyClientBindings.ColorType # value = <ColorType.Chocolate1: 16744228>
Chocolate2: TracyClientBindings.ColorType # value = <ColorType.Chocolate2: 15627809>
Chocolate3: TracyClientBindings.ColorType # value = <ColorType.Chocolate3: 13461021>
Chocolate4: TracyClientBindings.ColorType # value = <ColorType.SaddleBrown: 9127187>
Coral: TracyClientBindings.ColorType # value = <ColorType.Coral: 16744272>
Coral1: TracyClientBindings.ColorType # value = <ColorType.Coral1: 16740950>
Coral2: TracyClientBindings.ColorType # value = <ColorType.Coral2: 15624784>
Coral3: TracyClientBindings.ColorType # value = <ColorType.Coral3: 13458245>
Coral4: TracyClientBindings.ColorType # value = <ColorType.Coral4: 9125423>
CornflowerBlue: TracyClientBindings.ColorType # value = <ColorType.CornflowerBlue: 6591981>
Cornsilk: TracyClientBindings.ColorType # value = <ColorType.Cornsilk: 16775388>
Cornsilk1: TracyClientBindings.ColorType # value = <ColorType.Cornsilk: 16775388>
Cornsilk2: TracyClientBindings.ColorType # value = <ColorType.Cornsilk2: 15657165>
Cornsilk3: TracyClientBindings.ColorType # value = <ColorType.Cornsilk3: 13486257>
Cornsilk4: TracyClientBindings.ColorType # value = <ColorType.Cornsilk4: 9144440>
Crimson: TracyClientBindings.ColorType # value = <ColorType.Crimson: 14423100>
Cyan: TracyClientBindings.ColorType # value = <ColorType.Cyan: 65535>
Cyan1: TracyClientBindings.ColorType # value = <ColorType.Cyan: 65535>
Cyan2: TracyClientBindings.ColorType # value = <ColorType.Cyan2: 61166>
Cyan3: TracyClientBindings.ColorType # value = <ColorType.Cyan3: 52685>
Cyan4: TracyClientBindings.ColorType # value = <ColorType.Cyan4: 35723>
DarkBlue: TracyClientBindings.ColorType # value = <ColorType.Blue4: 139>
DarkCyan: TracyClientBindings.ColorType # value = <ColorType.Cyan4: 35723>
DarkGoldenrod: TracyClientBindings.ColorType # value = <ColorType.DarkGoldenrod: 12092939>
DarkGoldenrod1: TracyClientBindings.ColorType # value = <ColorType.DarkGoldenrod1: 16759055>
DarkGoldenrod2: TracyClientBindings.ColorType # value = <ColorType.DarkGoldenrod2: 15641870>
DarkGoldenrod3: TracyClientBindings.ColorType # value = <ColorType.DarkGoldenrod3: 13473036>
DarkGoldenrod4: TracyClientBindings.ColorType # value = <ColorType.DarkGoldenrod4: 9135368>
DarkGray: TracyClientBindings.ColorType # value = <ColorType.DarkGrey: 11119017>
DarkGreen: TracyClientBindings.ColorType # value = <ColorType.DarkGreen: 25600>
DarkGrey: TracyClientBindings.ColorType # value = <ColorType.DarkGrey: 11119017>
DarkKhaki: TracyClientBindings.ColorType # value = <ColorType.DarkKhaki: 12433259>
DarkMagenta: TracyClientBindings.ColorType # value = <ColorType.Magenta4: 9109643>
DarkOliveGreen: TracyClientBindings.ColorType # value = <ColorType.DarkOliveGreen: 5597999>
DarkOliveGreen1: TracyClientBindings.ColorType # value = <ColorType.DarkOliveGreen1: 13303664>
DarkOliveGreen2: TracyClientBindings.ColorType # value = <ColorType.DarkOliveGreen2: 12381800>
DarkOliveGreen3: TracyClientBindings.ColorType # value = <ColorType.DarkOliveGreen3: 10669402>
DarkOliveGreen4: TracyClientBindings.ColorType # value = <ColorType.DarkOliveGreen4: 7244605>
DarkOrange: TracyClientBindings.ColorType # value = <ColorType.DarkOrange: 16747520>
DarkOrange1: TracyClientBindings.ColorType # value = <ColorType.DarkOrange1: 16744192>
DarkOrange2: TracyClientBindings.ColorType # value = <ColorType.DarkOrange2: 15627776>
DarkOrange3: TracyClientBindings.ColorType # value = <ColorType.DarkOrange3: 13460992>
DarkOrange4: TracyClientBindings.ColorType # value = <ColorType.DarkOrange4: 9127168>
DarkOrchid: TracyClientBindings.ColorType # value = <ColorType.DarkOrchid: 10040012>
DarkOrchid1: TracyClientBindings.ColorType # value = <ColorType.DarkOrchid1: 12533503>
DarkOrchid2: TracyClientBindings.ColorType # value = <ColorType.DarkOrchid2: 11680494>
DarkOrchid3: TracyClientBindings.ColorType # value = <ColorType.DarkOrchid3: 10105549>
DarkOrchid4: TracyClientBindings.ColorType # value = <ColorType.DarkOrchid4: 6824587>
DarkRed: TracyClientBindings.ColorType # value = <ColorType.Red4: 9109504>
DarkSalmon: TracyClientBindings.ColorType # value = <ColorType.DarkSalmon: 15308410>
DarkSeaGreen: TracyClientBindings.ColorType # value = <ColorType.DarkSeaGreen: 9419919>
DarkSeaGreen1: TracyClientBindings.ColorType # value = <ColorType.DarkSeaGreen1: 12713921>
DarkSeaGreen2: TracyClientBindings.ColorType # value = <ColorType.DarkSeaGreen2: 11857588>
DarkSeaGreen3: TracyClientBindings.ColorType # value = <ColorType.DarkSeaGreen3: 10210715>
DarkSeaGreen4: TracyClientBindings.ColorType # value = <ColorType.DarkSeaGreen4: 6916969>
DarkSlateBlue: TracyClientBindings.ColorType # value = <ColorType.DarkSlateBlue: 4734347>
DarkSlateGray: TracyClientBindings.ColorType # value = <ColorType.DarkSlateGray: 3100495>
DarkSlateGray1: TracyClientBindings.ColorType # value = <ColorType.DarkSlateGray1: 9961471>
DarkSlateGray2: TracyClientBindings.ColorType # value = <ColorType.DarkSlateGray2: 9301742>
DarkSlateGray3: TracyClientBindings.ColorType # value = <ColorType.DarkSlateGray3: 7982541>
DarkSlateGray4: TracyClientBindings.ColorType # value = <ColorType.DarkSlateGray4: 5409675>
DarkSlateGrey: TracyClientBindings.ColorType # value = <ColorType.DarkSlateGray: 3100495>
DarkTurquoise: TracyClientBindings.ColorType # value = <ColorType.DarkTurquoise: 52945>
DarkViolet: TracyClientBindings.ColorType # value = <ColorType.DarkViolet: 9699539>
DeepPink: TracyClientBindings.ColorType # value = <ColorType.DeepPink: 16716947>
DeepPink1: TracyClientBindings.ColorType # value = <ColorType.DeepPink: 16716947>
DeepPink2: TracyClientBindings.ColorType # value = <ColorType.DeepPink2: 15602313>
DeepPink3: TracyClientBindings.ColorType # value = <ColorType.DeepPink3: 13439094>
DeepPink4: TracyClientBindings.ColorType # value = <ColorType.DeepPink4: 9112144>
DeepSkyBlue: TracyClientBindings.ColorType # value = <ColorType.DeepSkyBlue: 49151>
DeepSkyBlue1: TracyClientBindings.ColorType # value = <ColorType.DeepSkyBlue: 49151>
DeepSkyBlue2: TracyClientBindings.ColorType # value = <ColorType.DeepSkyBlue2: 45806>
DeepSkyBlue3: TracyClientBindings.ColorType # value = <ColorType.DeepSkyBlue3: 39629>
DeepSkyBlue4: TracyClientBindings.ColorType # value = <ColorType.DeepSkyBlue4: 26763>
DimGray: TracyClientBindings.ColorType # value = <ColorType.DimGray: 6908265>
DimGrey: TracyClientBindings.ColorType # value = <ColorType.DimGray: 6908265>
DodgerBlue: TracyClientBindings.ColorType # value = <ColorType.DodgerBlue: 2003199>
DodgerBlue1: TracyClientBindings.ColorType # value = <ColorType.DodgerBlue: 2003199>
DodgerBlue2: TracyClientBindings.ColorType # value = <ColorType.DodgerBlue2: 1869550>
DodgerBlue3: TracyClientBindings.ColorType # value = <ColorType.DodgerBlue3: 1602765>
DodgerBlue4: TracyClientBindings.ColorType # value = <ColorType.DodgerBlue4: 1068683>
Firebrick: TracyClientBindings.ColorType # value = <ColorType.Firebrick: 11674146>
Firebrick1: TracyClientBindings.ColorType # value = <ColorType.Firebrick1: 16724016>
Firebrick2: TracyClientBindings.ColorType # value = <ColorType.Firebrick2: 15608876>
Firebrick3: TracyClientBindings.ColorType # value = <ColorType.Firebrick3: 13444646>
Firebrick4: TracyClientBindings.ColorType # value = <ColorType.Firebrick4: 9116186>
FloralWhite: TracyClientBindings.ColorType # value = <ColorType.FloralWhite: 16775920>
ForestGreen: TracyClientBindings.ColorType # value = <ColorType.ForestGreen: 2263842>
Fuchsia: TracyClientBindings.ColorType # value = <ColorType.Magenta: 16711935>
Gainsboro: TracyClientBindings.ColorType # value = <ColorType.Gainsboro: 14474460>
GhostWhite: TracyClientBindings.ColorType # value = <ColorType.GhostWhite: 16316671>
Gold: TracyClientBindings.ColorType # value = <ColorType.Gold: 16766720>
Gold1: TracyClientBindings.ColorType # value = <ColorType.Gold: 16766720>
Gold2: TracyClientBindings.ColorType # value = <ColorType.Gold2: 15649024>
Gold3: TracyClientBindings.ColorType # value = <ColorType.Gold3: 13479168>
Gold4: TracyClientBindings.ColorType # value = <ColorType.Gold4: 9139456>
Goldenrod: TracyClientBindings.ColorType # value = <ColorType.Goldenrod: 14329120>
Goldenrod1: TracyClientBindings.ColorType # value = <ColorType.Goldenrod1: 16761125>
Goldenrod2: TracyClientBindings.ColorType # value = <ColorType.Goldenrod2: 15643682>
Goldenrod3: TracyClientBindings.ColorType # value = <ColorType.Goldenrod3: 13474589>
Goldenrod4: TracyClientBindings.ColorType # value = <ColorType.Goldenrod4: 9136404>
Gray: TracyClientBindings.ColorType # value = <ColorType.Gray: 12500670>
Gray0: TracyClientBindings.ColorType # value = <ColorType.Black: 0>
Gray1: TracyClientBindings.ColorType # value = <ColorType.Gray1: 197379>
Gray10: TracyClientBindings.ColorType # value = <ColorType.Gray10: 1710618>
Gray100: TracyClientBindings.ColorType # value = <ColorType.White: 16777215>
Gray11: TracyClientBindings.ColorType # value = <ColorType.Gray11: 1842204>
Gray12: TracyClientBindings.ColorType # value = <ColorType.Gray12: 2039583>
Gray13: TracyClientBindings.ColorType # value = <ColorType.Gray13: 2171169>
Gray14: TracyClientBindings.ColorType # value = <ColorType.Gray14: 2368548>
Gray15: TracyClientBindings.ColorType # value = <ColorType.Gray15: 2500134>
Gray16: TracyClientBindings.ColorType # value = <ColorType.Gray16: 2697513>
Gray17: TracyClientBindings.ColorType # value = <ColorType.Gray17: 2829099>
Gray18: TracyClientBindings.ColorType # value = <ColorType.Gray18: 3026478>
Gray19: TracyClientBindings.ColorType # value = <ColorType.Gray19: 3158064>
Gray2: TracyClientBindings.ColorType # value = <ColorType.Gray2: 328965>
Gray20: TracyClientBindings.ColorType # value = <ColorType.Gray20: 3355443>
Gray21: TracyClientBindings.ColorType # value = <ColorType.Gray21: 3552822>
Gray22: TracyClientBindings.ColorType # value = <ColorType.Gray22: 3684408>
Gray23: TracyClientBindings.ColorType # value = <ColorType.Gray23: 3881787>
Gray24: TracyClientBindings.ColorType # value = <ColorType.Gray24: 4013373>
Gray25: TracyClientBindings.ColorType # value = <ColorType.Gray25: 4210752>
Gray26: TracyClientBindings.ColorType # value = <ColorType.Gray26: 4342338>
Gray27: TracyClientBindings.ColorType # value = <ColorType.Gray27: 4539717>
Gray28: TracyClientBindings.ColorType # value = <ColorType.Gray28: 4671303>
Gray29: TracyClientBindings.ColorType # value = <ColorType.Gray29: 4868682>
Gray3: TracyClientBindings.ColorType # value = <ColorType.Gray3: 526344>
Gray30: TracyClientBindings.ColorType # value = <ColorType.Gray30: 5066061>
Gray31: TracyClientBindings.ColorType # value = <ColorType.Gray31: 5197647>
Gray32: TracyClientBindings.ColorType # value = <ColorType.Gray32: 5395026>
Gray33: TracyClientBindings.ColorType # value = <ColorType.Gray33: 5526612>
Gray34: TracyClientBindings.ColorType # value = <ColorType.Gray34: 5723991>
Gray35: TracyClientBindings.ColorType # value = <ColorType.Gray35: 5855577>
Gray36: TracyClientBindings.ColorType # value = <ColorType.Gray36: 6052956>
Gray37: TracyClientBindings.ColorType # value = <ColorType.Gray37: 6184542>
Gray38: TracyClientBindings.ColorType # value = <ColorType.Gray38: 6381921>
Gray39: TracyClientBindings.ColorType # value = <ColorType.Gray39: 6513507>
Gray4: TracyClientBindings.ColorType # value = <ColorType.Gray4: 657930>
Gray40: TracyClientBindings.ColorType # value = <ColorType.Gray40: 6710886>
Gray41: TracyClientBindings.ColorType # value = <ColorType.DimGray: 6908265>
Gray42: TracyClientBindings.ColorType # value = <ColorType.Gray42: 7039851>
Gray43: TracyClientBindings.ColorType # value = <ColorType.Gray43: 7237230>
Gray44: TracyClientBindings.ColorType # value = <ColorType.Gray44: 7368816>
Gray45: TracyClientBindings.ColorType # value = <ColorType.Gray45: 7566195>
Gray46: TracyClientBindings.ColorType # value = <ColorType.Gray46: 7697781>
Gray47: TracyClientBindings.ColorType # value = <ColorType.Gray47: 7895160>
Gray48: TracyClientBindings.ColorType # value = <ColorType.Gray48: 8026746>
Gray49: TracyClientBindings.ColorType # value = <ColorType.Gray49: 8224125>
Gray5: TracyClientBindings.ColorType # value = <ColorType.Gray5: 855309>
Gray50: TracyClientBindings.ColorType # value = <ColorType.Gray50: 8355711>
Gray51: TracyClientBindings.ColorType # value = <ColorType.Gray51: 8553090>
Gray52: TracyClientBindings.ColorType # value = <ColorType.Gray52: 8750469>
Gray53: TracyClientBindings.ColorType # value = <ColorType.Gray53: 8882055>
Gray54: TracyClientBindings.ColorType # value = <ColorType.Gray54: 9079434>
Gray55: TracyClientBindings.ColorType # value = <ColorType.Gray55: 9211020>
Gray56: TracyClientBindings.ColorType # value = <ColorType.Gray56: 9408399>
Gray57: TracyClientBindings.ColorType # value = <ColorType.Gray57: 9539985>
Gray58: TracyClientBindings.ColorType # value = <ColorType.Gray58: 9737364>
Gray59: TracyClientBindings.ColorType # value = <ColorType.Gray59: 9868950>
Gray6: TracyClientBindings.ColorType # value = <ColorType.Gray6: 986895>
Gray60: TracyClientBindings.ColorType # value = <ColorType.Gray60: 10066329>
Gray61: TracyClientBindings.ColorType # value = <ColorType.Gray61: 10263708>
Gray62: TracyClientBindings.ColorType # value = <ColorType.Gray62: 10395294>
Gray63: TracyClientBindings.ColorType # value = <ColorType.Gray63: 10592673>
Gray64: TracyClientBindings.ColorType # value = <ColorType.Gray64: 10724259>
Gray65: TracyClientBindings.ColorType # value = <ColorType.Gray65: 10921638>
Gray66: TracyClientBindings.ColorType # value = <ColorType.Gray66: 11053224>
Gray67: TracyClientBindings.ColorType # value = <ColorType.Gray67: 11250603>
Gray68: TracyClientBindings.ColorType # value = <ColorType.Gray68: 11382189>
Gray69: TracyClientBindings.ColorType # value = <ColorType.Gray69: 11579568>
Gray7: TracyClientBindings.ColorType # value = <ColorType.Gray7: 1184274>
Gray70: TracyClientBindings.ColorType # value = <ColorType.Gray70: 11776947>
Gray71: TracyClientBindings.ColorType # value = <ColorType.Gray71: 11908533>
Gray72: TracyClientBindings.ColorType # value = <ColorType.Gray72: 12105912>
Gray73: TracyClientBindings.ColorType # value = <ColorType.Gray73: 12237498>
Gray74: TracyClientBindings.ColorType # value = <ColorType.Gray74: 12434877>
Gray75: TracyClientBindings.ColorType # value = <ColorType.Gray75: 12566463>
Gray76: TracyClientBindings.ColorType # value = <ColorType.Gray76: 12763842>
Gray77: TracyClientBindings.ColorType # value = <ColorType.Gray77: 12895428>
Gray78: TracyClientBindings.ColorType # value = <ColorType.Gray78: 13092807>
Gray79: TracyClientBindings.ColorType # value = <ColorType.Gray79: 13224393>
Gray8: TracyClientBindings.ColorType # value = <ColorType.Gray8: 1315860>
Gray80: TracyClientBindings.ColorType # value = <ColorType.Gray80: 13421772>
Gray81: TracyClientBindings.ColorType # value = <ColorType.Gray81: 13619151>
Gray82: TracyClientBindings.ColorType # value = <ColorType.Gray82: 13750737>
Gray83: TracyClientBindings.ColorType # value = <ColorType.Gray83: 13948116>
Gray84: TracyClientBindings.ColorType # value = <ColorType.Gray84: 14079702>
Gray85: TracyClientBindings.ColorType # value = <ColorType.Gray85: 14277081>
Gray86: TracyClientBindings.ColorType # value = <ColorType.Gray86: 14408667>
Gray87: TracyClientBindings.ColorType # value = <ColorType.Gray87: 14606046>
Gray88: TracyClientBindings.ColorType # value = <ColorType.Gray88: 14737632>
Gray89: TracyClientBindings.ColorType # value = <ColorType.Gray89: 14935011>
Gray9: TracyClientBindings.ColorType # value = <ColorType.Gray9: 1513239>
Gray90: TracyClientBindings.ColorType # value = <ColorType.Gray90: 15066597>
Gray91: TracyClientBindings.ColorType # value = <ColorType.Gray91: 15263976>
Gray92: TracyClientBindings.ColorType # value = <ColorType.Gray92: 15461355>
Gray93: TracyClientBindings.ColorType # value = <ColorType.Gray93: 15592941>
Gray94: TracyClientBindings.ColorType # value = <ColorType.Gray94: 15790320>
Gray95: TracyClientBindings.ColorType # value = <ColorType.Gray95: 15921906>
Gray96: TracyClientBindings.ColorType # value = <ColorType.WhiteSmoke: 16119285>
Gray97: TracyClientBindings.ColorType # value = <ColorType.Gray97: 16250871>
Gray98: TracyClientBindings.ColorType # value = <ColorType.Gray98: 16448250>
Gray99: TracyClientBindings.ColorType # value = <ColorType.Gray99: 16579836>
Green: TracyClientBindings.ColorType # value = <ColorType.Green: 65280>
Green1: TracyClientBindings.ColorType # value = <ColorType.Green: 65280>
Green2: TracyClientBindings.ColorType # value = <ColorType.Green2: 60928>
Green3: TracyClientBindings.ColorType # value = <ColorType.Green3: 52480>
Green4: TracyClientBindings.ColorType # value = <ColorType.Green4: 35584>
GreenYellow: TracyClientBindings.ColorType # value = <ColorType.GreenYellow: 11403055>
Grey: TracyClientBindings.ColorType # value = <ColorType.Gray: 12500670>
Grey0: TracyClientBindings.ColorType # value = <ColorType.Black: 0>
Grey1: TracyClientBindings.ColorType # value = <ColorType.Gray1: 197379>
Grey10: TracyClientBindings.ColorType # value = <ColorType.Gray10: 1710618>
Grey100: TracyClientBindings.ColorType # value = <ColorType.White: 16777215>
Grey11: TracyClientBindings.ColorType # value = <ColorType.Gray11: 1842204>
Grey12: TracyClientBindings.ColorType # value = <ColorType.Gray12: 2039583>
Grey13: TracyClientBindings.ColorType # value = <ColorType.Gray13: 2171169>
Grey14: TracyClientBindings.ColorType # value = <ColorType.Gray14: 2368548>
Grey15: TracyClientBindings.ColorType # value = <ColorType.Gray15: 2500134>
Grey16: TracyClientBindings.ColorType # value = <ColorType.Gray16: 2697513>
Grey17: TracyClientBindings.ColorType # value = <ColorType.Gray17: 2829099>
Grey18: TracyClientBindings.ColorType # value = <ColorType.Gray18: 3026478>
Grey19: TracyClientBindings.ColorType # value = <ColorType.Gray19: 3158064>
Grey2: TracyClientBindings.ColorType # value = <ColorType.Gray2: 328965>
Grey20: TracyClientBindings.ColorType # value = <ColorType.Gray20: 3355443>
Grey21: TracyClientBindings.ColorType # value = <ColorType.Gray21: 3552822>
Grey22: TracyClientBindings.ColorType # value = <ColorType.Gray22: 3684408>
Grey23: TracyClientBindings.ColorType # value = <ColorType.Gray23: 3881787>
Grey24: TracyClientBindings.ColorType # value = <ColorType.Gray24: 4013373>
Grey25: TracyClientBindings.ColorType # value = <ColorType.Gray25: 4210752>
Grey26: TracyClientBindings.ColorType # value = <ColorType.Gray26: 4342338>
Grey27: TracyClientBindings.ColorType # value = <ColorType.Gray27: 4539717>
Grey28: TracyClientBindings.ColorType # value = <ColorType.Gray28: 4671303>
Grey29: TracyClientBindings.ColorType # value = <ColorType.Gray29: 4868682>
Grey3: TracyClientBindings.ColorType # value = <ColorType.Gray3: 526344>
Grey30: TracyClientBindings.ColorType # value = <ColorType.Gray30: 5066061>
Grey31: TracyClientBindings.ColorType # value = <ColorType.Gray31: 5197647>
Grey32: TracyClientBindings.ColorType # value = <ColorType.Gray32: 5395026>
Grey33: TracyClientBindings.ColorType # value = <ColorType.Gray33: 5526612>
Grey34: TracyClientBindings.ColorType # value = <ColorType.Gray34: 5723991>
Grey35: TracyClientBindings.ColorType # value = <ColorType.Gray35: 5855577>
Grey36: TracyClientBindings.ColorType # value = <ColorType.Gray36: 6052956>
Grey37: TracyClientBindings.ColorType # value = <ColorType.Gray37: 6184542>
Grey38: TracyClientBindings.ColorType # value = <ColorType.Gray38: 6381921>
Grey39: TracyClientBindings.ColorType # value = <ColorType.Gray39: 6513507>
Grey4: TracyClientBindings.ColorType # value = <ColorType.Gray4: 657930>
Grey40: TracyClientBindings.ColorType # value = <ColorType.Gray40: 6710886>
Grey41: TracyClientBindings.ColorType # value = <ColorType.DimGray: 6908265>
Grey42: TracyClientBindings.ColorType # value = <ColorType.Gray42: 7039851>
Grey43: TracyClientBindings.ColorType # value = <ColorType.Gray43: 7237230>
Grey44: TracyClientBindings.ColorType # value = <ColorType.Gray44: 7368816>
Grey45: TracyClientBindings.ColorType # value = <ColorType.Gray45: 7566195>
Grey46: TracyClientBindings.ColorType # value = <ColorType.Gray46: 7697781>
Grey47: TracyClientBindings.ColorType # value = <ColorType.Gray47: 7895160>
Grey48: TracyClientBindings.ColorType # value = <ColorType.Gray48: 8026746>
Grey49: TracyClientBindings.ColorType # value = <ColorType.Gray49: 8224125>
Grey5: TracyClientBindings.ColorType # value = <ColorType.Gray5: 855309>
Grey50: TracyClientBindings.ColorType # value = <ColorType.Gray50: 8355711>
Grey51: TracyClientBindings.ColorType # value = <ColorType.Gray51: 8553090>
Grey52: TracyClientBindings.ColorType # value = <ColorType.Gray52: 8750469>
Grey53: TracyClientBindings.ColorType # value = <ColorType.Gray53: 8882055>
Grey54: TracyClientBindings.ColorType # value = <ColorType.Gray54: 9079434>
Grey55: TracyClientBindings.ColorType # value = <ColorType.Gray55: 9211020>
Grey56: TracyClientBindings.ColorType # value = <ColorType.Gray56: 9408399>
Grey57: TracyClientBindings.ColorType # value = <ColorType.Gray57: 9539985>
Grey58: TracyClientBindings.ColorType # value = <ColorType.Gray58: 9737364>
Grey59: TracyClientBindings.ColorType # value = <ColorType.Gray59: 9868950>
Grey6: TracyClientBindings.ColorType # value = <ColorType.Gray6: 986895>
Grey60: TracyClientBindings.ColorType # value = <ColorType.Gray60: 10066329>
Grey61: TracyClientBindings.ColorType # value = <ColorType.Gray61: 10263708>
Grey62: TracyClientBindings.ColorType # value = <ColorType.Gray62: 10395294>
Grey63: TracyClientBindings.ColorType # value = <ColorType.Gray63: 10592673>
Grey64: TracyClientBindings.ColorType # value = <ColorType.Gray64: 10724259>
Grey65: TracyClientBindings.ColorType # value = <ColorType.Gray65: 10921638>
Grey66: TracyClientBindings.ColorType # value = <ColorType.Gray66: 11053224>
Grey67: TracyClientBindings.ColorType # value = <ColorType.Gray67: 11250603>
Grey68: TracyClientBindings.ColorType # value = <ColorType.Gray68: 11382189>
Grey69: TracyClientBindings.ColorType # value = <ColorType.Gray69: 11579568>
Grey7: TracyClientBindings.ColorType # value = <ColorType.Gray7: 1184274>
Grey70: TracyClientBindings.ColorType # value = <ColorType.Gray70: 11776947>
Grey71: TracyClientBindings.ColorType # value = <ColorType.Gray71: 11908533>
Grey72: TracyClientBindings.ColorType # value = <ColorType.Gray72: 12105912>
Grey73: TracyClientBindings.ColorType # value = <ColorType.Gray73: 12237498>
Grey74: TracyClientBindings.ColorType # value = <ColorType.Gray74: 12434877>
Grey75: TracyClientBindings.ColorType # value = <ColorType.Gray75: 12566463>
Grey76: TracyClientBindings.ColorType # value = <ColorType.Gray76: 12763842>
Grey77: TracyClientBindings.ColorType # value = <ColorType.Gray77: 12895428>
Grey78: TracyClientBindings.ColorType # value = <ColorType.Gray78: 13092807>
Grey79: TracyClientBindings.ColorType # value = <ColorType.Gray79: 13224393>
Grey8: TracyClientBindings.ColorType # value = <ColorType.Gray8: 1315860>
Grey80: TracyClientBindings.ColorType # value = <ColorType.Gray80: 13421772>
Grey81: TracyClientBindings.ColorType # value = <ColorType.Gray81: 13619151>
Grey82: TracyClientBindings.ColorType # value = <ColorType.Gray82: 13750737>
Grey83: TracyClientBindings.ColorType # value = <ColorType.Gray83: 13948116>
Grey84: TracyClientBindings.ColorType # value = <ColorType.Gray84: 14079702>
Grey85: TracyClientBindings.ColorType # value = <ColorType.Gray85: 14277081>
Grey86: TracyClientBindings.ColorType # value = <ColorType.Gray86: 14408667>
Grey87: TracyClientBindings.ColorType # value = <ColorType.Gray87: 14606046>
Grey88: TracyClientBindings.ColorType # value = <ColorType.Gray88: 14737632>
Grey89: TracyClientBindings.ColorType # value = <ColorType.Gray89: 14935011>
Grey9: TracyClientBindings.ColorType # value = <ColorType.Gray9: 1513239>
Grey90: TracyClientBindings.ColorType # value = <ColorType.Gray90: 15066597>
Grey91: TracyClientBindings.ColorType # value = <ColorType.Gray91: 15263976>
Grey92: TracyClientBindings.ColorType # value = <ColorType.Gray92: 15461355>
Grey93: TracyClientBindings.ColorType # value = <ColorType.Gray93: 15592941>
Grey94: TracyClientBindings.ColorType # value = <ColorType.Gray94: 15790320>
Grey95: TracyClientBindings.ColorType # value = <ColorType.Gray95: 15921906>
Grey96: TracyClientBindings.ColorType # value = <ColorType.WhiteSmoke: 16119285>
Grey97: TracyClientBindings.ColorType # value = <ColorType.Gray97: 16250871>
Grey98: TracyClientBindings.ColorType # value = <ColorType.Gray98: 16448250>
Grey99: TracyClientBindings.ColorType # value = <ColorType.Gray99: 16579836>
Honeydew: TracyClientBindings.ColorType # value = <ColorType.Honeydew: 15794160>
Honeydew1: TracyClientBindings.ColorType # value = <ColorType.Honeydew: 15794160>
Honeydew2: TracyClientBindings.ColorType # value = <ColorType.Honeydew2: 14741216>
Honeydew3: TracyClientBindings.ColorType # value = <ColorType.Honeydew3: 12701121>
Honeydew4: TracyClientBindings.ColorType # value = <ColorType.Honeydew4: 8620931>
HotPink: TracyClientBindings.ColorType # value = <ColorType.HotPink: 16738740>
HotPink1: TracyClientBindings.ColorType # value = <ColorType.HotPink1: 16740020>
HotPink2: TracyClientBindings.ColorType # value = <ColorType.HotPink2: 15624871>
HotPink3: TracyClientBindings.ColorType # value = <ColorType.HotPink3: 13459600>
HotPink4: TracyClientBindings.ColorType # value = <ColorType.HotPink4: 9124450>
IndianRed: TracyClientBindings.ColorType # value = <ColorType.IndianRed: 13458524>
IndianRed1: TracyClientBindings.ColorType # value = <ColorType.IndianRed1: 16738922>
IndianRed2: TracyClientBindings.ColorType # value = <ColorType.IndianRed2: 15623011>
IndianRed3: TracyClientBindings.ColorType # value = <ColorType.IndianRed3: 13456725>
IndianRed4: TracyClientBindings.ColorType # value = <ColorType.IndianRed4: 9124410>
Indigo: TracyClientBindings.ColorType # value = <ColorType.Indigo: 4915330>
Ivory: TracyClientBindings.ColorType # value = <ColorType.Ivory: 16777200>
Ivory1: TracyClientBindings.ColorType # value = <ColorType.Ivory: 16777200>
Ivory2: TracyClientBindings.ColorType # value = <ColorType.Ivory2: 15658720>
Ivory3: TracyClientBindings.ColorType # value = <ColorType.Ivory3: 13487553>
Ivory4: TracyClientBindings.ColorType # value = <ColorType.Ivory4: 9145219>
Khaki: TracyClientBindings.ColorType # value = <ColorType.Khaki: 15787660>
Khaki1: TracyClientBindings.ColorType # value = <ColorType.Khaki1: 16774799>
Khaki2: TracyClientBindings.ColorType # value = <ColorType.Khaki2: 15656581>
Khaki3: TracyClientBindings.ColorType # value = <ColorType.Khaki3: 13485683>
Khaki4: TracyClientBindings.ColorType # value = <ColorType.Khaki4: 9143886>
Lavender: TracyClientBindings.ColorType # value = <ColorType.Lavender: 15132410>
LavenderBlush: TracyClientBindings.ColorType # value = <ColorType.LavenderBlush: 16773365>
LavenderBlush1: TracyClientBindings.ColorType # value = <ColorType.LavenderBlush: 16773365>
LavenderBlush2: TracyClientBindings.ColorType # value = <ColorType.LavenderBlush2: 15655141>
LavenderBlush3: TracyClientBindings.ColorType # value = <ColorType.LavenderBlush3: 13484485>
LavenderBlush4: TracyClientBindings.ColorType # value = <ColorType.LavenderBlush4: 9143174>
LawnGreen: TracyClientBindings.ColorType # value = <ColorType.LawnGreen: 8190976>
LemonChiffon: TracyClientBindings.ColorType # value = <ColorType.LemonChiffon: 16775885>
LemonChiffon1: TracyClientBindings.ColorType # value = <ColorType.LemonChiffon: 16775885>
LemonChiffon2: TracyClientBindings.ColorType # value = <ColorType.LemonChiffon2: 15657407>
LemonChiffon3: TracyClientBindings.ColorType # value = <ColorType.LemonChiffon3: 13486501>
LemonChiffon4: TracyClientBindings.ColorType # value = <ColorType.LemonChiffon4: 9144688>
LightBlue: TracyClientBindings.ColorType # value = <ColorType.LightBlue: 11393254>
LightBlue1: TracyClientBindings.ColorType # value = <ColorType.LightBlue1: 12578815>
LightBlue2: TracyClientBindings.ColorType # value = <ColorType.LightBlue2: 11722734>
LightBlue3: TracyClientBindings.ColorType # value = <ColorType.LightBlue3: 10141901>
LightBlue4: TracyClientBindings.ColorType # value = <ColorType.LightBlue4: 6849419>
LightCoral: TracyClientBindings.ColorType # value = <ColorType.LightCoral: 15761536>
LightCyan: TracyClientBindings.ColorType # value = <ColorType.LightCyan: 14745599>
LightCyan1: TracyClientBindings.ColorType # value = <ColorType.LightCyan: 14745599>
LightCyan2: TracyClientBindings.ColorType # value = <ColorType.LightCyan2: 13758190>
LightCyan3: TracyClientBindings.ColorType # value = <ColorType.LightCyan3: 11849165>
LightCyan4: TracyClientBindings.ColorType # value = <ColorType.LightCyan4: 8031115>
LightGoldenrod: TracyClientBindings.ColorType # value = <ColorType.LightGoldenrod: 15654274>
LightGoldenrod1: TracyClientBindings.ColorType # value = <ColorType.LightGoldenrod1: 16772235>
LightGoldenrod2: TracyClientBindings.ColorType # value = <ColorType.LightGoldenrod2: 15654018>
LightGoldenrod3: TracyClientBindings.ColorType # value = <ColorType.LightGoldenrod3: 13483632>
LightGoldenrod4: TracyClientBindings.ColorType # value = <ColorType.LightGoldenrod4: 9142604>
LightGoldenrodYellow: TracyClientBindings.ColorType # value = <ColorType.LightGoldenrodYellow: 16448210>
LightGray: TracyClientBindings.ColorType # value = <ColorType.LightGrey: 13882323>
LightGreen: TracyClientBindings.ColorType # value = <ColorType.PaleGreen2: 9498256>
LightGrey: TracyClientBindings.ColorType # value = <ColorType.LightGrey: 13882323>
LightPink: TracyClientBindings.ColorType # value = <ColorType.LightPink: 16758465>
LightPink1: TracyClientBindings.ColorType # value = <ColorType.LightPink1: 16756409>
LightPink2: TracyClientBindings.ColorType # value = <ColorType.LightPink2: 15639213>
LightPink3: TracyClientBindings.ColorType # value = <ColorType.LightPink3: 13470869>
LightPink4: TracyClientBindings.ColorType # value = <ColorType.LightPink4: 9133925>
LightSalmon: TracyClientBindings.ColorType # value = <ColorType.LightSalmon: 16752762>
LightSalmon1: TracyClientBindings.ColorType # value = <ColorType.LightSalmon: 16752762>
LightSalmon2: TracyClientBindings.ColorType # value = <ColorType.LightSalmon2: 15635826>
LightSalmon3: TracyClientBindings.ColorType # value = <ColorType.LightSalmon3: 13468002>
LightSalmon4: TracyClientBindings.ColorType # value = <ColorType.LightSalmon4: 9131842>
LightSeaGreen: TracyClientBindings.ColorType # value = <ColorType.LightSeaGreen: 2142890>
LightSkyBlue: TracyClientBindings.ColorType # value = <ColorType.LightSkyBlue: 8900346>
LightSkyBlue1: TracyClientBindings.ColorType # value = <ColorType.LightSkyBlue1: 11592447>
LightSkyBlue2: TracyClientBindings.ColorType # value = <ColorType.LightSkyBlue2: 10802158>
LightSkyBlue3: TracyClientBindings.ColorType # value = <ColorType.LightSkyBlue3: 9287373>
LightSkyBlue4: TracyClientBindings.ColorType # value = <ColorType.LightSkyBlue4: 6323083>
LightSlateBlue: TracyClientBindings.ColorType # value = <ColorType.LightSlateBlue: 8679679>
LightSlateGray: TracyClientBindings.ColorType # value = <ColorType.LightSlateGray: 7833753>
LightSlateGrey: TracyClientBindings.ColorType # value = <ColorType.LightSlateGray: 7833753>
LightSteelBlue: TracyClientBindings.ColorType # value = <ColorType.LightSteelBlue: 11584734>
LightSteelBlue1: TracyClientBindings.ColorType # value = <ColorType.LightSteelBlue1: 13296127>
LightSteelBlue2: TracyClientBindings.ColorType # value = <ColorType.LightSteelBlue2: 12374766>
LightSteelBlue3: TracyClientBindings.ColorType # value = <ColorType.LightSteelBlue3: 10663373>
LightSteelBlue4: TracyClientBindings.ColorType # value = <ColorType.LightSteelBlue4: 7240587>
LightYellow: TracyClientBindings.ColorType # value = <ColorType.LightYellow: 16777184>
LightYellow1: TracyClientBindings.ColorType # value = <ColorType.LightYellow: 16777184>
LightYellow2: TracyClientBindings.ColorType # value = <ColorType.LightYellow2: 15658705>
LightYellow3: TracyClientBindings.ColorType # value = <ColorType.LightYellow3: 13487540>
LightYellow4: TracyClientBindings.ColorType # value = <ColorType.LightYellow4: 9145210>
Lime: TracyClientBindings.ColorType # value = <ColorType.Green: 65280>
LimeGreen: TracyClientBindings.ColorType # value = <ColorType.LimeGreen: 3329330>
Linen: TracyClientBindings.ColorType # value = <ColorType.Linen: 16445670>
Magenta: TracyClientBindings.ColorType # value = <ColorType.Magenta: 16711935>
Magenta1: TracyClientBindings.ColorType # value = <ColorType.Magenta: 16711935>
Magenta2: TracyClientBindings.ColorType # value = <ColorType.Magenta2: 15597806>
Magenta3: TracyClientBindings.ColorType # value = <ColorType.Magenta3: 13435085>
Magenta4: TracyClientBindings.ColorType # value = <ColorType.Magenta4: 9109643>
Maroon: TracyClientBindings.ColorType # value = <ColorType.Maroon: 11546720>
Maroon1: TracyClientBindings.ColorType # value = <ColorType.Maroon1: 16725171>
Maroon2: TracyClientBindings.ColorType # value = <ColorType.Maroon2: 15610023>
Maroon3: TracyClientBindings.ColorType # value = <ColorType.Maroon3: 13445520>
Maroon4: TracyClientBindings.ColorType # value = <ColorType.Maroon4: 9116770>
MediumAquamarine: TracyClientBindings.ColorType # value = <ColorType.MediumAquamarine: 6737322>
MediumBlue: TracyClientBindings.ColorType # value = <ColorType.MediumBlue: 205>
MediumOrchid: TracyClientBindings.ColorType # value = <ColorType.MediumOrchid: 12211667>
MediumOrchid1: TracyClientBindings.ColorType # value = <ColorType.MediumOrchid1: 14706431>
MediumOrchid2: TracyClientBindings.ColorType # value = <ColorType.MediumOrchid2: 13721582>
MediumOrchid3: TracyClientBindings.ColorType # value = <ColorType.MediumOrchid3: 11817677>
MediumOrchid4: TracyClientBindings.ColorType # value = <ColorType.MediumOrchid4: 8009611>
MediumPurple: TracyClientBindings.ColorType # value = <ColorType.MediumPurple: 9662683>
MediumPurple1: TracyClientBindings.ColorType # value = <ColorType.MediumPurple1: 11240191>
MediumPurple2: TracyClientBindings.ColorType # value = <ColorType.MediumPurple2: 10451438>
MediumPurple3: TracyClientBindings.ColorType # value = <ColorType.MediumPurple3: 9005261>
MediumPurple4: TracyClientBindings.ColorType # value = <ColorType.MediumPurple4: 6113163>
MediumSeaGreen: TracyClientBindings.ColorType # value = <ColorType.MediumSeaGreen: 3978097>
MediumSlateBlue: TracyClientBindings.ColorType # value = <ColorType.MediumSlateBlue: 8087790>
MediumSpringGreen: TracyClientBindings.ColorType # value = <ColorType.MediumSpringGreen: 64154>
MediumTurquoise: TracyClientBindings.ColorType # value = <ColorType.MediumTurquoise: 4772300>
MediumVioletRed: TracyClientBindings.ColorType # value = <ColorType.MediumVioletRed: 13047173>
Memory: TracyClientBindings.PlotFormatType # value = <PlotFormatType.Memory: 1>
MidnightBlue: TracyClientBindings.ColorType # value = <ColorType.MidnightBlue: 1644912>
MintCream: TracyClientBindings.ColorType # value = <ColorType.MintCream: 16121850>
MistyRose: TracyClientBindings.ColorType # value = <ColorType.MistyRose: 16770273>
MistyRose1: TracyClientBindings.ColorType # value = <ColorType.MistyRose: 16770273>
MistyRose2: TracyClientBindings.ColorType # value = <ColorType.MistyRose2: 15652306>
MistyRose3: TracyClientBindings.ColorType # value = <ColorType.MistyRose3: 13481909>
MistyRose4: TracyClientBindings.ColorType # value = <ColorType.MistyRose4: 9141627>
Moccasin: TracyClientBindings.ColorType # value = <ColorType.Moccasin: 16770229>
NavajoWhite: TracyClientBindings.ColorType # value = <ColorType.NavajoWhite: 16768685>
NavajoWhite1: TracyClientBindings.ColorType # value = <ColorType.NavajoWhite: 16768685>
NavajoWhite2: TracyClientBindings.ColorType # value = <ColorType.NavajoWhite2: 15650721>
NavajoWhite3: TracyClientBindings.ColorType # value = <ColorType.NavajoWhite3: 13480843>
NavajoWhite4: TracyClientBindings.ColorType # value = <ColorType.NavajoWhite4: 9140574>
Navy: TracyClientBindings.ColorType # value = <ColorType.Navy: 128>
NavyBlue: TracyClientBindings.ColorType # value = <ColorType.Navy: 128>
Number: TracyClientBindings.PlotFormatType # value = <PlotFormatType.Number: 0>
OldLace: TracyClientBindings.ColorType # value = <ColorType.OldLace: 16643558>
Olive: TracyClientBindings.ColorType # value = <ColorType.Olive: 8421376>
OliveDrab: TracyClientBindings.ColorType # value = <ColorType.OliveDrab: 7048739>
OliveDrab1: TracyClientBindings.ColorType # value = <ColorType.OliveDrab1: 12648254>
OliveDrab2: TracyClientBindings.ColorType # value = <ColorType.OliveDrab2: 11791930>
OliveDrab3: TracyClientBindings.ColorType # value = <ColorType.YellowGreen: 10145074>
OliveDrab4: TracyClientBindings.ColorType # value = <ColorType.OliveDrab4: 6916898>
Orange: TracyClientBindings.ColorType # value = <ColorType.Orange: 16753920>
Orange1: TracyClientBindings.ColorType # value = <ColorType.Orange: 16753920>
Orange2: TracyClientBindings.ColorType # value = <ColorType.Orange2: 15636992>
Orange3: TracyClientBindings.ColorType # value = <ColorType.Orange3: 13468928>
Orange4: TracyClientBindings.ColorType # value = <ColorType.Orange4: 9132544>
OrangeRed: TracyClientBindings.ColorType # value = <ColorType.OrangeRed: 16729344>
OrangeRed1: TracyClientBindings.ColorType # value = <ColorType.OrangeRed: 16729344>
OrangeRed2: TracyClientBindings.ColorType # value = <ColorType.OrangeRed2: 15613952>
OrangeRed3: TracyClientBindings.ColorType # value = <ColorType.OrangeRed3: 13448960>
OrangeRed4: TracyClientBindings.ColorType # value = <ColorType.OrangeRed4: 9118976>
Orchid: TracyClientBindings.ColorType # value = <ColorType.Orchid: 14315734>
Orchid1: TracyClientBindings.ColorType # value = <ColorType.Orchid1: 16745466>
Orchid2: TracyClientBindings.ColorType # value = <ColorType.Orchid2: 15629033>
Orchid3: TracyClientBindings.ColorType # value = <ColorType.Orchid3: 13461961>
Orchid4: TracyClientBindings.ColorType # value = <ColorType.Orchid4: 9127817>
PaleGoldenrod: TracyClientBindings.ColorType # value = <ColorType.PaleGoldenrod: 15657130>
PaleGreen: TracyClientBindings.ColorType # value = <ColorType.PaleGreen: 10025880>
PaleGreen1: TracyClientBindings.ColorType # value = <ColorType.PaleGreen1: 10157978>
PaleGreen2: TracyClientBindings.ColorType # value = <ColorType.PaleGreen2: 9498256>
PaleGreen3: TracyClientBindings.ColorType # value = <ColorType.PaleGreen3: 8179068>
PaleGreen4: TracyClientBindings.ColorType # value = <ColorType.PaleGreen4: 5540692>
PaleTurquoise: TracyClientBindings.ColorType # value = <ColorType.PaleTurquoise: 11529966>
PaleTurquoise1: TracyClientBindings.ColorType # value = <ColorType.PaleTurquoise1: 12320767>
PaleTurquoise2: TracyClientBindings.ColorType # value = <ColorType.PaleTurquoise2: 11464430>
PaleTurquoise3: TracyClientBindings.ColorType # value = <ColorType.PaleTurquoise3: 9883085>
PaleTurquoise4: TracyClientBindings.ColorType # value = <ColorType.PaleTurquoise4: 6720395>
PaleVioletRed: TracyClientBindings.ColorType # value = <ColorType.PaleVioletRed: 14381203>
PaleVioletRed1: TracyClientBindings.ColorType # value = <ColorType.PaleVioletRed1: 16745131>
PaleVioletRed2: TracyClientBindings.ColorType # value = <ColorType.PaleVioletRed2: 15628703>
PaleVioletRed3: TracyClientBindings.ColorType # value = <ColorType.PaleVioletRed3: 13461641>
PaleVioletRed4: TracyClientBindings.ColorType # value = <ColorType.PaleVioletRed4: 9127773>
PapayaWhip: TracyClientBindings.ColorType # value = <ColorType.PapayaWhip: 16773077>
PeachPuff: TracyClientBindings.ColorType # value = <ColorType.PeachPuff: 16767673>
PeachPuff1: TracyClientBindings.ColorType # value = <ColorType.PeachPuff: 16767673>
PeachPuff2: TracyClientBindings.ColorType # value = <ColorType.PeachPuff2: 15649709>
PeachPuff3: TracyClientBindings.ColorType # value = <ColorType.PeachPuff3: 13479829>
PeachPuff4: TracyClientBindings.ColorType # value = <ColorType.PeachPuff4: 9140069>
Percentage: TracyClientBindings.PlotFormatType # value = <PlotFormatType.Percentage: 2>
Peru: TracyClientBindings.ColorType # value = <ColorType.Peru: 13468991>
Pink: TracyClientBindings.ColorType # value = <ColorType.Pink: 16761035>
Pink1: TracyClientBindings.ColorType # value = <ColorType.Pink1: 16758213>
Pink2: TracyClientBindings.ColorType # value = <ColorType.Pink2: 15641016>
Pink3: TracyClientBindings.ColorType # value = <ColorType.Pink3: 13472158>
Pink4: TracyClientBindings.ColorType # value = <ColorType.Pink4: 9134956>
Plum: TracyClientBindings.ColorType # value = <ColorType.Plum: 14524637>
Plum1: TracyClientBindings.ColorType # value = <ColorType.Plum1: 16759807>
Plum2: TracyClientBindings.ColorType # value = <ColorType.Plum2: 15642350>
Plum3: TracyClientBindings.ColorType # value = <ColorType.Plum3: 13473485>
Plum4: TracyClientBindings.ColorType # value = <ColorType.Plum4: 9135755>
PowderBlue: TracyClientBindings.ColorType # value = <ColorType.PowderBlue: 11591910>
Purple: TracyClientBindings.ColorType # value = <ColorType.Purple: 10494192>
Purple1: TracyClientBindings.ColorType # value = <ColorType.Purple1: 10170623>
Purple2: TracyClientBindings.ColorType # value = <ColorType.Purple2: 9514222>
Purple3: TracyClientBindings.ColorType # value = <ColorType.Purple3: 8201933>
Purple4: TracyClientBindings.ColorType # value = <ColorType.Purple4: 5577355>
RebeccaPurple: TracyClientBindings.ColorType # value = <ColorType.RebeccaPurple: 6697881>
Red: TracyClientBindings.ColorType # value = <ColorType.Red: 16711680>
Red1: TracyClientBindings.ColorType # value = <ColorType.Red: 16711680>
Red2: TracyClientBindings.ColorType # value = <ColorType.Red2: 15597568>
Red3: TracyClientBindings.ColorType # value = <ColorType.Red3: 13434880>
Red4: TracyClientBindings.ColorType # value = <ColorType.Red4: 9109504>
RosyBrown: TracyClientBindings.ColorType # value = <ColorType.RosyBrown: 12357519>
RosyBrown1: TracyClientBindings.ColorType # value = <ColorType.RosyBrown1: 16761281>
RosyBrown2: TracyClientBindings.ColorType # value = <ColorType.RosyBrown2: 15643828>
RosyBrown3: TracyClientBindings.ColorType # value = <ColorType.RosyBrown3: 13474715>
RosyBrown4: TracyClientBindings.ColorType # value = <ColorType.RosyBrown4: 9136489>
RoyalBlue: TracyClientBindings.ColorType # value = <ColorType.RoyalBlue: 4286945>
RoyalBlue1: TracyClientBindings.ColorType # value = <ColorType.RoyalBlue1: 4749055>
RoyalBlue2: TracyClientBindings.ColorType # value = <ColorType.RoyalBlue2: 4419310>
RoyalBlue3: TracyClientBindings.ColorType # value = <ColorType.RoyalBlue3: 3825613>
RoyalBlue4: TracyClientBindings.ColorType # value = <ColorType.RoyalBlue4: 2572427>
SaddleBrown: TracyClientBindings.ColorType # value = <ColorType.SaddleBrown: 9127187>
Salmon: TracyClientBindings.ColorType # value = <ColorType.Salmon: 16416882>
Salmon1: TracyClientBindings.ColorType # value = <ColorType.Salmon1: 16747625>
Salmon2: TracyClientBindings.ColorType # value = <ColorType.Salmon2: 15630946>
Salmon3: TracyClientBindings.ColorType # value = <ColorType.Salmon3: 13463636>
Salmon4: TracyClientBindings.ColorType # value = <ColorType.Salmon4: 9129017>
SandyBrown: TracyClientBindings.ColorType # value = <ColorType.SandyBrown: 16032864>
SeaGreen: TracyClientBindings.ColorType # value = <ColorType.SeaGreen: 3050327>
SeaGreen1: TracyClientBindings.ColorType # value = <ColorType.SeaGreen1: 5570463>
SeaGreen2: TracyClientBindings.ColorType # value = <ColorType.SeaGreen2: 5172884>
SeaGreen3: TracyClientBindings.ColorType # value = <ColorType.SeaGreen3: 4443520>
SeaGreen4: TracyClientBindings.ColorType # value = <ColorType.SeaGreen: 3050327>
Seashell: TracyClientBindings.ColorType # value = <ColorType.Seashell: 16774638>
Seashell1: TracyClientBindings.ColorType # value = <ColorType.Seashell: 16774638>
Seashell2: TracyClientBindings.ColorType # value = <ColorType.Seashell2: 15656414>
Seashell3: TracyClientBindings.ColorType # value = <ColorType.Seashell3: 13485503>
Seashell4: TracyClientBindings.ColorType # value = <ColorType.Seashell4: 9143938>
Sienna: TracyClientBindings.ColorType # value = <ColorType.Sienna: 10506797>
Sienna1: TracyClientBindings.ColorType # value = <ColorType.Sienna1: 16745031>
Sienna2: TracyClientBindings.ColorType # value = <ColorType.Sienna2: 15628610>
Sienna3: TracyClientBindings.ColorType # value = <ColorType.Sienna3: 13461561>
Sienna4: TracyClientBindings.ColorType # value = <ColorType.Sienna4: 9127718>
Silver: TracyClientBindings.ColorType # value = <ColorType.Silver: 12632256>
SkyBlue: TracyClientBindings.ColorType # value = <ColorType.SkyBlue: 8900331>
SkyBlue1: TracyClientBindings.ColorType # value = <ColorType.SkyBlue1: 8900351>
SkyBlue2: TracyClientBindings.ColorType # value = <ColorType.SkyBlue2: 8306926>
SkyBlue3: TracyClientBindings.ColorType # value = <ColorType.SkyBlue3: 7120589>
SkyBlue4: TracyClientBindings.ColorType # value = <ColorType.SkyBlue4: 4878475>
SlateBlue: TracyClientBindings.ColorType # value = <ColorType.SlateBlue: 6970061>
SlateBlue1: TracyClientBindings.ColorType # value = <ColorType.SlateBlue1: 8613887>
SlateBlue2: TracyClientBindings.ColorType # value = <ColorType.SlateBlue2: 8021998>
SlateBlue3: TracyClientBindings.ColorType # value = <ColorType.SlateBlue3: 6904269>
SlateBlue4: TracyClientBindings.ColorType # value = <ColorType.SlateBlue4: 4668555>
SlateGray: TracyClientBindings.ColorType # value = <ColorType.SlateGray: 7372944>
SlateGray1: TracyClientBindings.ColorType # value = <ColorType.SlateGray1: 13034239>
SlateGray2: TracyClientBindings.ColorType # value = <ColorType.SlateGray2: 12178414>
SlateGray3: TracyClientBindings.ColorType # value = <ColorType.SlateGray3: 10467021>
SlateGray4: TracyClientBindings.ColorType # value = <ColorType.SlateGray4: 7109515>
SlateGrey: TracyClientBindings.ColorType # value = <ColorType.SlateGray: 7372944>
Snow: TracyClientBindings.ColorType # value = <ColorType.Snow: 16775930>
Snow1: TracyClientBindings.ColorType # value = <ColorType.Snow: 16775930>
Snow2: TracyClientBindings.ColorType # value = <ColorType.Snow2: 15657449>
Snow3: TracyClientBindings.ColorType # value = <ColorType.Snow3: 13486537>
Snow4: TracyClientBindings.ColorType # value = <ColorType.Snow4: 9144713>
SpringGreen: TracyClientBindings.ColorType # value = <ColorType.SpringGreen: 65407>
SpringGreen1: TracyClientBindings.ColorType # value = <ColorType.SpringGreen: 65407>
SpringGreen2: TracyClientBindings.ColorType # value = <ColorType.SpringGreen2: 61046>
SpringGreen3: TracyClientBindings.ColorType # value = <ColorType.SpringGreen3: 52582>
SpringGreen4: TracyClientBindings.ColorType # value = <ColorType.SpringGreen4: 35653>
SteelBlue: TracyClientBindings.ColorType # value = <ColorType.SteelBlue: 4620980>
SteelBlue1: TracyClientBindings.ColorType # value = <ColorType.SteelBlue1: 6535423>
SteelBlue2: TracyClientBindings.ColorType # value = <ColorType.SteelBlue2: 6073582>
SteelBlue3: TracyClientBindings.ColorType # value = <ColorType.SteelBlue3: 5215437>
SteelBlue4: TracyClientBindings.ColorType # value = <ColorType.SteelBlue4: 3564683>
Tan: TracyClientBindings.ColorType # value = <ColorType.Tan: 13808780>
Tan1: TracyClientBindings.ColorType # value = <ColorType.Tan1: 16753999>
Tan2: TracyClientBindings.ColorType # value = <ColorType.Tan2: 15637065>
Tan3: TracyClientBindings.ColorType # value = <ColorType.Peru: 13468991>
Tan4: TracyClientBindings.ColorType # value = <ColorType.Tan4: 9132587>
Teal: TracyClientBindings.ColorType # value = <ColorType.Teal: 32896>
Thistle: TracyClientBindings.ColorType # value = <ColorType.Thistle: 14204888>
Thistle1: TracyClientBindings.ColorType # value = <ColorType.Thistle1: 16769535>
Thistle2: TracyClientBindings.ColorType # value = <ColorType.Thistle2: 15651566>
Thistle3: TracyClientBindings.ColorType # value = <ColorType.Thistle3: 13481421>
Thistle4: TracyClientBindings.ColorType # value = <ColorType.Thistle4: 9141131>
Tomato: TracyClientBindings.ColorType # value = <ColorType.Tomato: 16737095>
Tomato1: TracyClientBindings.ColorType # value = <ColorType.Tomato: 16737095>
Tomato2: TracyClientBindings.ColorType # value = <ColorType.Tomato2: 15621186>
Tomato3: TracyClientBindings.ColorType # value = <ColorType.Tomato3: 13455161>
Tomato4: TracyClientBindings.ColorType # value = <ColorType.Tomato4: 9123366>
Turquoise: TracyClientBindings.ColorType # value = <ColorType.Turquoise: 4251856>
Turquoise1: TracyClientBindings.ColorType # value = <ColorType.Turquoise1: 62975>
Turquoise2: TracyClientBindings.ColorType # value = <ColorType.Turquoise2: 58862>
Turquoise3: TracyClientBindings.ColorType # value = <ColorType.Turquoise3: 50637>
Turquoise4: TracyClientBindings.ColorType # value = <ColorType.Turquoise4: 34443>
Violet: TracyClientBindings.ColorType # value = <ColorType.Violet: 15631086>
VioletRed: TracyClientBindings.ColorType # value = <ColorType.VioletRed: 13639824>
VioletRed1: TracyClientBindings.ColorType # value = <ColorType.VioletRed1: 16727702>
VioletRed2: TracyClientBindings.ColorType # value = <ColorType.VioletRed2: 15612556>
VioletRed3: TracyClientBindings.ColorType # value = <ColorType.VioletRed3: 13447800>
VioletRed4: TracyClientBindings.ColorType # value = <ColorType.VioletRed4: 9118290>
WebGray: TracyClientBindings.ColorType # value = <ColorType.WebGray: 8421504>
WebGreen: TracyClientBindings.ColorType # value = <ColorType.WebGreen: 32768>
WebGrey: TracyClientBindings.ColorType # value = <ColorType.WebGray: 8421504>
WebMaroon: TracyClientBindings.ColorType # value = <ColorType.WebMaroon: 8388608>
WebPurple: TracyClientBindings.ColorType # value = <ColorType.WebPurple: 8388736>
Wheat: TracyClientBindings.ColorType # value = <ColorType.Wheat: 16113331>
Wheat1: TracyClientBindings.ColorType # value = <ColorType.Wheat1: 16771002>
Wheat2: TracyClientBindings.ColorType # value = <ColorType.Wheat2: 15653038>
Wheat3: TracyClientBindings.ColorType # value = <ColorType.Wheat3: 13482646>
Wheat4: TracyClientBindings.ColorType # value = <ColorType.Wheat4: 9141862>
White: TracyClientBindings.ColorType # value = <ColorType.White: 16777215>
WhiteSmoke: TracyClientBindings.ColorType # value = <ColorType.WhiteSmoke: 16119285>
X11Gray: TracyClientBindings.ColorType # value = <ColorType.Gray: 12500670>
X11Green: TracyClientBindings.ColorType # value = <ColorType.Green: 65280>
X11Grey: TracyClientBindings.ColorType # value = <ColorType.Gray: 12500670>
X11Maroon: TracyClientBindings.ColorType # value = <ColorType.Maroon: 11546720>
X11Purple: TracyClientBindings.ColorType # value = <ColorType.Purple: 10494192>
Yellow: TracyClientBindings.ColorType # value = <ColorType.Yellow: 16776960>
Yellow1: TracyClientBindings.ColorType # value = <ColorType.Yellow: 16776960>
Yellow2: TracyClientBindings.ColorType # value = <ColorType.Yellow2: 15658496>
Yellow3: TracyClientBindings.ColorType # value = <ColorType.Yellow3: 13487360>
Yellow4: TracyClientBindings.ColorType # value = <ColorType.Yellow4: 9145088>
YellowGreen: TracyClientBindings.ColorType # value = <ColorType.YellowGreen: 10145074>
