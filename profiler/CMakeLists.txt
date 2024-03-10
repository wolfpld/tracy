cmake_minimum_required(VERSION 3.19)
project(Profiler C CXX ASM)

set(CMAKE_CXX_STANDARD 17)

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/vendor.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../cmake/server.cmake)

set(PROFILER_SOURCE
    src/ImGuiContext.cpp
    src/HttpRequest.cpp
    src/RunQueue.cpp
    src/main.cpp
    src/winmainArchDiscovery.cpp
    src/winmain.cpp
    src/WindowPosition.cpp
    src/imgui/imgui_impl_opengl3.cpp
    src/ResolvService.cpp
    src/Fonts.cpp
    src/ConnectionHistory.cpp
    src/IsElevated.cpp
    src/Filters.cpp
    src/ini.c
)

set(GLFW_SOURCE
    src/BackendGlfw.cpp
    src/imgui/imgui_impl_glfw.cpp
)

set(WAYLAND_SOURCE
    src/wayland/xdg-decoration.c
    src/wayland/xdg-shell.c
    src/wayland/xdg-activation.c
    src/BackendWayland.cpp
)

if (NOT UNIX)
    set(LEGACY ON)
endif()

if (LEGACY)
    message(STATUS "Using legacy backend")
    list(APPEND PROFILER_SOURCE ${GLFW_SOURCE})
else()
    message(STATUS "Using Wayland backend")
    list(APPEND PROFILER_SOURCE ${WAYLAND_SOURCE})
endif()


add_executable(Tracy ${PROFILER_SOURCE})
target_include_directories(Tracy PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(Tracy PRIVATE TracyImGui TracyServer)

if (TRACY_NO_FILESELECTOR)
    target_compile_definitions(Tracy PRIVATE TRACY_NO_FILESELECTOR)
else()
    target_link_libraries(Tracy PRIVATE TracyNfd)
endif()
