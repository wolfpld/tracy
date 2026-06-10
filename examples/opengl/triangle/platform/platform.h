// platform.h — interface between platform-agnostic code and platform backends
//
// Each platform_*.mm / platform_*.cpp file implements these four functions.
// Exactly one backend must be linked into the final binary.

#pragma once

#ifdef __APPLE__
// OpenGL is only available on MacOS (no iOS support)
// Anything from gl3.h will spew deprecation warnings when used,
// unless GL_SILENCE_DEPRECATION has been defined beforehand
//#  define GL_SILENCE_DEPRECATION
#  include <OpenGL/gl3.h>
#else
#  include <GL/glew.h>
#endif

// Initialize the windowing system, create a window, and make an OpenGL 3.3
// Core Profile context current on the calling thread.
// Returns true on success.
bool platformInit(int width, int height, const char* title);

// Load OpenGL function pointers (no-op on macOS where the framework exports them directly).
// Must be called after platformInit() while the GL context is current.
// Returns true on success.
bool platformInitGL();

// Elapsed wall-clock time in seconds since platformInit().
double platformGetTime();

// Swap front and back buffers (present the rendered frame).
void platformSwapBuffers();

// Enter the platform event/render loop.
// Calls render() each frame at ~60 fps.
// Calls shutdown() exactly once before returning.
void platformRunLoop(void (*render)(), void (*shutdown)());
