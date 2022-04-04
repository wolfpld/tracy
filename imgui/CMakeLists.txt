cmake_minimum_required(VERSION 3.10)

project(TracyImGui LANGUAGES C CXX)

add_library(TracyImGui STATIC)
add_library(Tracy::TracyImGui ALIAS TracyImGui)

target_sources(TracyImGui
    PRIVATE
        imconfig.h              
        imgui.cpp               
        imgui.h                 
        imgui_demo.cpp          
        imgui_draw.cpp          
        imgui_internal.h        
        imgui_tables.cpp        
        imgui_widgets.cpp       
        imstb_rectpack.h        
        imstb_textedit.h        
        imstb_truetype.h        
        misc/freetype/imgui_freetype.cpp        
        misc/freetype/imgui_freetype.h        
)
target_include_directories(TracyImGui
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}
)
target_compile_definitions(TracyImGui
    PUBLIC
        IMGUI_ENABLE_FREETYPE
    PRIVATE
        $<$<PLATFORM_ID:Windows>:
            _CRT_SECURE_NO_DEPRECATE
            _CRT_NONSTDC_NO_DEPRECATE
            WIN32_LEAN_AND_MEAN
            NOMINMAX
            _USE_MATH_DEFINES
        >
        $<$<CXX_COMPILER_ID:MSVC>:
            /permissive-
            /W3
        >
)
target_compile_features(TracyImGui
    PUBLIC
        cxx_std_17
)
target_link_libraries(TracyImGui
    PRIVATE
        freetype
)
set_target_properties(TracyImGui
    PROPERTIES
        CXX_STANDARD          17
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS        OFF
)

