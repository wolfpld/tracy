add_executable(
  Tracy WIN32
  src/WindowPosition.cpp
  src/ConnectionHistory.cpp
  src/RunQueue.cpp
  src/BackendGlfw.cpp
  src/Fonts.cpp
  src/imgui/imgui_impl_opengl3.cpp
  src/imgui/imgui_impl_glfw.cpp
  src/winmainArchDiscovery.cpp
  src/winmain.cpp
  src/ResolvService.cpp
  src/Filters.cpp
  src/ImGuiContext.cpp
  src/main.cpp
  src/HttpRequest.cpp
  build/win32/Tracy.rc)

set_default_compile_options(Tracy)

find_package(glfw REQUIRED)

target_link_libraries(Tracy PRIVATE server glfw::glfw imgui nfd)

if(APPLE)
  find_library(FRAMEWORK_COREFOUNDATION CoreFoundation REQUIRED)
  find_library(FRAMEWORK_APPKIT AppKit REQUIRED)
  # Available from macOS 11.0+
  find_library(FRAMEWORK_UTI UniformTypeIdentifiers)

  target_link_libraries(
    Tracy
    PRIVATE
      ${FRAMEWORK_COREFOUNDATION}
      ${FRAMEWORK_APPKIT}
      $<$<VERSION_GREATER_EQUAL:${CMAKE_OSX_DEPLOYMENT_TARGET},11.0>:${FRAMEWORK_UTI}>
  )
endif()
