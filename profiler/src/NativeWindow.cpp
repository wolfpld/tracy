#include "NativeWindow.hpp"

#include <GLFW/glfw3.h>

#ifdef _WIN32
#  define GLFW_EXPOSE_NATIVE_WIN32
#  include <GLFW/glfw3native.h>
#elif defined __linux__
#  define GLFW_EXPOSE_NATIVE_X11
#  include <GLFW/glfw3native.h>
#endif

extern GLFWwindow* s_glfwWindow;

void* GetMainWindowNative()
{
#ifdef _WIN32
    return (void*)glfwGetWin32Window( s_glfwWindow );
#elif defined __linux__
    return (void*)glfwGetX11Window( s_glfwWindow );
#else
    return nullptr;
#endif
}
