// spinning_triangle.cpp — OpenGL spinning triangle demo with Tracy GPU profiling.

#ifdef __APPLE__
// NOTE: OpenGL is only available on MacOS (no iOS support)
// Including and using anything related to OpenGL on Apple (like <OpenGL/gl3.h>)
// will emit deprecation warnings, unless GL_SILENCE_DEPRECATION is defined
#define GL_SILENCE_DEPRECATION
// NOTE: TracyOpenGL.hpp will not work as expected even on Apple devices that
// support OpenGL, because the OpenGL drivers do not implement ARB_timer_query
// properly (querying GL_TIMESTAMP always resolves to 0). TracyOpenGL.hpp will
// emit a compiler warning, and a Tracy message to the trace/profiler, but the
// program will still run.
#endif

#include "platform/platform.h"  // also includes OpenGL headers

#include <tracy/Tracy.hpp>

// NOTE: opt-in toggle for periodic recalibrations during Collect()
#define TRACY_OPENGL_AUTO_CALIBRATION
#include <tracy/TracyOpenGL.hpp>

static const int kWidth  = 800;
static const int kHeight = 600;

static GLuint gProgram  = 0;
static GLuint gVao      = 0;
static GLint  gAngleLoc = -1;

// Vertex colors and positions are baked in; rotation is driven by a uniform.
static const char* kVertSrc = R"(
#version 150 core
uniform float uAngle;
const vec2 kPos[3] = vec2[3](
    vec2( 0.0,    0.5  ),
    vec2(-0.433, -0.25 ),
    vec2( 0.433, -0.25 )
);
const vec3 kCol[3] = vec3[3](
    vec3(1.0, 0.0, 0.0),
    vec3(0.0, 1.0, 0.0),
    vec3(0.0, 0.0, 1.0)
);
out vec3 vColor;
void main() {
    float c = cos(uAngle);
    float s = sin(uAngle);
    vec2  p = kPos[gl_VertexID];
    gl_Position = vec4(p.x*c - p.y*s, p.x*s + p.y*c, 0.0, 1.0);
    vColor = kCol[gl_VertexID];
}
)";

static const char* kFragSrc = R"(
#version 150 core
in  vec3 vColor;
out vec4 fragColor;
void main() { fragColor = vec4(vColor, 1.0); }
)";

static GLuint compileShader(GLenum type, const char* src) {
    GLuint s = glCreateShader(type);
    glShaderSource(s, 1, &src, nullptr);
    glCompileShader(s);
    GLint ok = 0;
    glGetShaderiv(s, GL_COMPILE_STATUS, &ok);
    if (!ok) {
        char log[512];
        glGetShaderInfoLog(s, sizeof(log), nullptr, log);
        fprintf(stderr, "Shader compile error: %s\n", log);
        glDeleteShader(s);
        return 0;
    }
    return s;
}

static int initGL() {
    if (!platformInitGL()) return 1;

    TracyGpuContext;
    TracyGpuContextName("OpenGL", 6);

    GLuint vert = compileShader(GL_VERTEX_SHADER,   kVertSrc);
    GLuint frag = compileShader(GL_FRAGMENT_SHADER, kFragSrc);
    if (!vert || !frag) return 1;

    gProgram = glCreateProgram();
    glAttachShader(gProgram, vert);
    glAttachShader(gProgram, frag);
    glLinkProgram(gProgram);
    glDeleteShader(vert);
    glDeleteShader(frag);

    GLint ok = 0;
    glGetProgramiv(gProgram, GL_LINK_STATUS, &ok);
    if (!ok) {
        char log[512];
        glGetProgramInfoLog(gProgram, sizeof(log), nullptr, log);
        fprintf(stderr, "Program link error: %s\n", log);
        return 1;
    }

    gAngleLoc = glGetUniformLocation(gProgram, "uAngle");

    // Core profile requires a bound VAO even with no vertex attributes.
    glGenVertexArrays(1, &gVao);
    glBindVertexArray(gVao);

    glClearColor(0.05f, 0.05f, 0.08f, 1.0f);
    float scaleX, scaleY;
    platformGetPixelDensityScale(&scaleX, &scaleY);
    glViewport(0, 0, (int)(kWidth * scaleX), (int)(kHeight * scaleY));
    return 0;
}

static void renderFrame() {
    ZoneScoped;

    glClear(GL_COLOR_BUFFER_BIT);
    glUseProgram(gProgram);

    {
        TracyGpuZone("triangle draw");
        glUniform1f(gAngleLoc, (float)platformGetTime());
        glDrawArrays(GL_TRIANGLES, 0, 3);
    }

    platformSwapBuffers();
    TracyGpuCollect;
}

static void shutdown() {
    fprintf(stderr, "application is shutting down...\n");
    glDeleteVertexArrays(1, &gVao);
    glDeleteProgram(gProgram);
}

int main() {
    if (!platformInit(kWidth, kHeight, "OpenGL Spinning Triangle"))
        return 1;
    if (initGL() != 0)
        return 2;
    platformRunLoop(renderFrame, shutdown);
    return 0;
}
