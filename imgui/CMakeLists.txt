add_library(
  imgui STATIC misc/freetype/imgui_freetype.cpp imgui_widgets.cpp imgui.cpp
               imgui_tables.cpp imgui_demo.cpp imgui_draw.cpp)

set_default_compile_options(imgui)

target_include_directories(imgui PUBLIC "${CMAKE_SOURCE_DIR}/imgui")

find_package(Freetype REQUIRED)

target_link_libraries(imgui PUBLIC public.common Freetype::Freetype)
