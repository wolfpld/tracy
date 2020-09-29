#include "NativeWindow.hpp"

#include <GLFW/glfw3.h>

#ifdef _WIN32
#  define GLFW_EXPOSE_NATIVE_WIN32
#  include <GLFW/glfw3native.h>
#elif defined __linux__
#  ifdef DISPLAY_SERVER_X11
#    define GLFW_EXPOSE_NATIVE_X11
#  elif defined DISPLAY_SERVER_WAYLAND
#    define GLFW_EXPOSE_NATIVE_WAYLAND
#  else
#    error "unsupported linux display server"
#  endif
#  include <GLFW/glfw3native.h>
#endif

extern GLFWwindow* s_glfwWindow;

void* GetMainWindowNative()
{
#ifdef _WIN32
    return (void*)glfwGetWin32Window( s_glfwWindow );
#elif defined __linux__
#  ifdef DISPLAY_SERVER_X11
    return (void*)glfwGetX11Window( s_glfwWindow );
#  elif defined DISPLAY_SERVER_WAYLAND
    return (void*)glfwGetWaylandWindow( s_glfwWindow );
#  endif
#else
    return nullptr;
#endif
}
