imgui_sources = files('imgui.cpp', 'imgui_draw.cpp', 'imgui_tables.cpp', 'imgui_widgets.cpp')

imgui_inc = include_directories('.')
imgui_lib = library('imgui_lib', imgui_sources, include_directories: imgui_inc)
imgui_dep = declare_dependency(include_directories: imgui_inc, link_with: imgui_lib)
