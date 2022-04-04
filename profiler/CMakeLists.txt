cmake_minimum_required(VERSION 3.10)

project(TracyProfiler LANGUAGES CXX)

add_executable(TracyProfiler)
add_executable(Tracy::TracyProfiler ALIAS TracyProfiler)

target_sources(TracyProfiler
    PRIVATE
        src/DroidSans.hpp               
        src/FiraCodeRetina.hpp          
        src/FontAwesomeSolid.hpp        
        src/HttpRequest.cpp             
        src/HttpRequest.hpp             
        src/icon.hpp                    
        src/imgui_impl_glfw.cpp         
        src/imgui_impl_glfw.h           
        src/imgui_impl_opengl3.cpp      
        src/imgui_impl_opengl3.h        
        src/imgui_impl_opengl3_loader.h 
        src/main.cpp                    
        src/NativeWindow.cpp            
        src/NativeWindow.hpp            
        src/ResolvService.cpp           
        src/ResolvService.hpp           
        src/stb_image.h                 
        src/winmain.cpp                 
        src/winmainArchDiscovery.cpp    
        $<$<PLATFORM_ID:Windows>:build/win32/Tracy.manifest>
        $<$<PLATFORM_ID:Windows>:build/win32/Tracy.rc>
)
target_compile_definitions(TracyProfiler
    PRIVATE
        TRACY_NO_STATISTICS
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
target_compile_features(TracyProfiler
    PRIVATE
        cxx_std_17
)
target_link_libraries(TracyProfiler
    PRIVATE
        TracyCommon
        TracyImGui
        TracyNFD
        TracyServer
        glfw
)
set_target_properties(TracyProfiler
    PROPERTIES
        CXX_STANDARD          17
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS        OFF
        OUTPUT_NAME           "Tracy"
)

if(UNIX AND NOT APPLE)
    if(TRACY_USE_WAYLAND)
        target_compile_definitions(TracyProfiler
            PRIVATE
                DISPLAY_SERVER_WAYLAND
        )
        target_link_libraries(TracyProfiler
            PRIVATE
                PkgConfig::WAYLAND
        )
    else()
        target_compile_definitions(TracyProfiler
            PRIVATE
                DISPLAY_SERVER_X11
        )
    endif()
endif()
