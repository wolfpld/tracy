project(TracyNFD LANGUAGES C)

add_library(TracyNFD STATIC)
add_library(Tracy::TracyNFD ALIAS TracyNFD)

target_sources(TracyNFD
    PRIVATE
        common.h                 
        LICENSE                  
        nfd.h                    
        nfd_common.c             
        nfd_common.h             
        $<$<PLATFORM_ID:Linux>:nfd_gtk.c>                
        $<$<PLATFORM_ID:Darwin>:nfd_cocoa.m>              
        $<$<PLATFORM_ID:Windows>:nfd_win.cpp>       
)
target_include_directories(TracyNFD
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}
)
target_compile_definitions(TracyNFD
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
target_link_libraries(TracyNFD
    PRIVATE
        $<$<PLATFORM_ID:Linux>:
            PkgConfig::GTK3
        >
        $<$<PLATFORM_ID:Darwin>:
            "-framework CoreFoundation"
            "-framework AppKit"
        >
)
