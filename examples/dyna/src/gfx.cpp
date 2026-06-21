#include "gfx.hpp"

#include "texture.hpp"
#include "timer.hpp"

#include <SDL3/SDL.h>
#include <tracy/Tracy.hpp>

#include <cassert>
#include <cstdio>
#include <vector>

namespace dyna
{

namespace
{

SDL_Window* g_window = nullptr;
SDL_GLContext g_gl_context = nullptr;

GLuint g_program = 0;
GLuint g_vao = 0;
GLuint g_vbo = 0;

// Current draw state, applied to every quad appended to the batch.
GLuint g_current_tex = 0;
int g_current_layer = 0;
float g_alpha = 1.0f;

// One vertex of the streaming batch: screen position, atlas-array texcoord,
// the array layer to sample and a per-vertex alpha multiplier.
struct GlVert
{
    float px, py, tx, ty, layer, a;
};

// A run of consecutive vertices that share one texture, drawn in a single call.
struct DrawCmd
{
    GLuint tex;
    GLsizei count;
};

std::vector<GlVert> g_verts;
std::vector<DrawCmd> g_cmds;

const char* VERT_SRC = R"(
#version 330 core
uniform mat4 uProjection;
layout(location = 0) in vec2 aPosition;
layout(location = 1) in vec2 aTexCoord;
layout(location = 2) in float aLayer;
layout(location = 3) in float aAlpha;
out vec3 vTexCoord;
out float vAlpha;
void main() {
    gl_Position = uProjection * vec4(aPosition, 0.0, 1.0);
    vTexCoord = vec3(aTexCoord, aLayer);
    vAlpha = aAlpha;
}
)";

const char* FRAG_SRC = R"(
#version 330 core
uniform sampler2DArray uTexture;
in vec3 vTexCoord;
in float vAlpha;
out vec4 fragColor;
void main() {
    fragColor = texture(uTexture, vTexCoord) * vec4(1.0, 1.0, 1.0, vAlpha);
}
)";

GLuint compile_shader( GLenum type, const char* src )
{
    ZoneScoped;
    GLuint s = glCreateShader( type );
    glShaderSource( s, 1, &src, nullptr );
    glCompileShader( s );
    GLint ok = 0;
    glGetShaderiv( s, GL_COMPILE_STATUS, &ok );
    if( !ok )
    {
        char log[512];
        glGetShaderInfoLog( s, 512, nullptr, log );
        std::fprintf( stderr, "Shader compile error: %s\n", log );
        glDeleteShader( s );
        return 0;
    }
    return s;
}

bool init_shaders()
{
    ZoneScoped;
    GLuint vs = compile_shader( GL_VERTEX_SHADER, VERT_SRC );
    if( !vs ) return false;
    GLuint fs = compile_shader( GL_FRAGMENT_SHADER, FRAG_SRC );
    if( !fs )
    {
        glDeleteShader( vs );
        return false;
    }

    g_program = glCreateProgram();
    glAttachShader( g_program, vs );
    glAttachShader( g_program, fs );
    glLinkProgram( g_program );
    glDeleteShader( vs );
    glDeleteShader( fs );

    GLint ok = 0;
    glGetProgramiv( g_program, GL_LINK_STATUS, &ok );
    if( !ok )
    {
        char log[512];
        glGetProgramInfoLog( g_program, 512, nullptr, log );
        std::fprintf( stderr, "Program link error: %s\n", log );
        glDeleteProgram( g_program );
        g_program = 0;
        return false;
    }

    // Bottom-left origin orthographic projection, matching the original
    // gluOrtho2D(0, w, 0, h) so the ported draw code carries over verbatim.
    float l = 0.0f, r = static_cast<float>( Gfx::w );
    float b = 0.0f, t = static_cast<float>( Gfx::h );
    float proj[16] = {
        2.0f / ( r - l ), 0.0f, 0.0f, 0.0f,
        0.0f, 2.0f / ( t - b ), 0.0f, 0.0f,
        0.0f, 0.0f, -1.0f, 0.0f,
        -( r + l ) / ( r - l ), -( t + b ) / ( t - b ), 0.0f, 1.0f };

    glUseProgram( g_program );
    glUniformMatrix4fv( glGetUniformLocation( g_program, "uProjection" ), 1, GL_FALSE, proj );
    glUniform1i( glGetUniformLocation( g_program, "uTexture" ), 0 );
    glUseProgram( 0 );
    return true;
}

void init_quad_vao()
{
    ZoneScoped;
    glGenVertexArrays( 1, &g_vao );
    glGenBuffers( 1, &g_vbo );

    glBindVertexArray( g_vao );
    glBindBuffer( GL_ARRAY_BUFFER, g_vbo );

    const GLsizei stride = sizeof( GlVert );
    glEnableVertexAttribArray( 0 );
    glVertexAttribPointer( 0, 2, GL_FLOAT, GL_FALSE, stride, (void*)0 );
    glEnableVertexAttribArray( 1 );
    glVertexAttribPointer( 1, 2, GL_FLOAT, GL_FALSE, stride, (void*)8 );
    glEnableVertexAttribArray( 2 );
    glVertexAttribPointer( 2, 1, GL_FLOAT, GL_FALSE, stride, (void*)16 );
    glEnableVertexAttribArray( 3 );
    glVertexAttribPointer( 3, 1, GL_FLOAT, GL_FALSE, stride, (void*)20 );

    glBindVertexArray( 0 );
    glBindBuffer( GL_ARRAY_BUFFER, 0 );
}

// Draw and clear everything accumulated since the last flush, in submission
// order. Consecutive quads that share a texture collapse into one draw call.
void flush_batch()
{
    ZoneScoped;
    if( g_verts.empty() )
        return;

    glBindBuffer( GL_ARRAY_BUFFER, g_vbo );
    glBufferData( GL_ARRAY_BUFFER,
                  static_cast<GLsizeiptr>( g_verts.size() * sizeof( GlVert ) ),
                  g_verts.data(), GL_STREAM_DRAW );

    glUseProgram( g_program );
    glBindVertexArray( g_vao );

    GLint offset = 0;
    for( const DrawCmd& cmd : g_cmds )
    {
        glBindTexture( GL_TEXTURE_2D_ARRAY, cmd.tex );
        glDrawArrays( GL_TRIANGLES, offset, cmd.count );
        offset += cmd.count;
    }

    glBindVertexArray( 0 );
    glUseProgram( 0 );
    glBindBuffer( GL_ARRAY_BUFFER, 0 );

    g_verts.clear();
    g_cmds.clear();
}

// Frame image capture, following the OpenGL example in the Tracy manual. The
// backbuffer is downscaled on the GPU to a small fixed size and read back
// asynchronously, so a screenshot can be attached to every frame without
// stalling the CPU on the GPU. Several buffer sets are cycled because rendering
// runs a few frames ahead of the GPU.
// Half the render resolution, preserving its aspect ratio; both dimensions
// stay divisible by 4 as FrameImage requires.
constexpr int FI_W = Gfx::w / 2;
constexpr int FI_H = Gfx::h / 2;
constexpr int FI_COUNT = 4;

GLuint g_fi_texture[FI_COUNT];
GLuint g_fi_framebuffer[FI_COUNT];
GLuint g_fi_pbo[FI_COUNT];
GLsync g_fi_fence[FI_COUNT] = {};
int g_fi_idx = 0;
std::vector<int> g_fi_queue;

void init_frame_images()
{
    ZoneScoped;
    glGenTextures( FI_COUNT, g_fi_texture );
    glGenFramebuffers( FI_COUNT, g_fi_framebuffer );
    glGenBuffers( FI_COUNT, g_fi_pbo );
    for( int i = 0; i < FI_COUNT; i++ )
    {
        glBindTexture( GL_TEXTURE_2D, g_fi_texture[i] );
        glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
        glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
        glTexImage2D( GL_TEXTURE_2D, 0, GL_RGBA, FI_W, FI_H, 0, GL_RGBA, GL_UNSIGNED_BYTE, nullptr );

        glBindFramebuffer( GL_FRAMEBUFFER, g_fi_framebuffer[i] );
        glFramebufferTexture2D( GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, g_fi_texture[i], 0 );

        glBindBuffer( GL_PIXEL_PACK_BUFFER, g_fi_pbo[i] );
        glBufferData( GL_PIXEL_PACK_BUFFER, FI_W * FI_H * 4, nullptr, GL_STREAM_READ );
    }
    glBindFramebuffer( GL_FRAMEBUFFER, 0 );
    glBindBuffer( GL_PIXEL_PACK_BUFFER, 0 );
}

void shutdown_frame_images()
{
    ZoneScoped;
    glDeleteTextures( FI_COUNT, g_fi_texture );
    glDeleteFramebuffers( FI_COUNT, g_fi_framebuffer );
    glDeleteBuffers( FI_COUNT, g_fi_pbo );
}

// Send any captures the GPU has already finished, then queue a capture of the
// frame just rendered. Call after the batch is flushed but before swapping.
void capture_frame_image()
{
    ZoneScoped;

    // Hand finished captures from earlier frames to the profiler. The queue
    // size is the number of frames we are still ahead of the GPU, which is the
    // frame lag Tracy needs as the FrameImage offset.
    while( !g_fi_queue.empty() )
    {
        const int idx = g_fi_queue.front();
        if( glClientWaitSync( g_fi_fence[idx], 0, 0 ) == GL_TIMEOUT_EXPIRED ) break;
        glDeleteSync( g_fi_fence[idx] );
        glBindBuffer( GL_PIXEL_PACK_BUFFER, g_fi_pbo[idx] );
        void* ptr = glMapBufferRange( GL_PIXEL_PACK_BUFFER, 0, FI_W * FI_H * 4, GL_MAP_READ_BIT );
        FrameImage( ptr, FI_W, FI_H, g_fi_queue.size(), true );
        glUnmapBuffer( GL_PIXEL_PACK_BUFFER );
        g_fi_queue.erase( g_fi_queue.begin() );
    }

    // Downscale the current backbuffer into the next buffer set and start an
    // asynchronous read-back, signalled by a fence.
    assert( g_fi_queue.empty() || g_fi_queue.front() != g_fi_idx );  // buffer overrun
    glBindFramebuffer( GL_DRAW_FRAMEBUFFER, g_fi_framebuffer[g_fi_idx] );
    glBlitFramebuffer( 0, 0, Gfx::w, Gfx::h, 0, 0, FI_W, FI_H, GL_COLOR_BUFFER_BIT, GL_LINEAR );
    glBindFramebuffer( GL_DRAW_FRAMEBUFFER, 0 );
    glBindFramebuffer( GL_READ_FRAMEBUFFER, g_fi_framebuffer[g_fi_idx] );
    glBindBuffer( GL_PIXEL_PACK_BUFFER, g_fi_pbo[g_fi_idx] );
    glReadPixels( 0, 0, FI_W, FI_H, GL_RGBA, GL_UNSIGNED_BYTE, nullptr );
    glBindFramebuffer( GL_READ_FRAMEBUFFER, 0 );
    g_fi_fence[g_fi_idx] = glFenceSync( GL_SYNC_GPU_COMMANDS_COMPLETE, 0 );
    g_fi_queue.emplace_back( g_fi_idx );
    g_fi_idx = ( g_fi_idx + 1 ) % FI_COUNT;
}

} // namespace

namespace Render
{

bool init()
{
    ZoneScoped;
    if( !init_shaders() ) return false;
    init_quad_vao();
    init_frame_images();
    return true;
}

void shutdown()
{
    ZoneScoped;
    shutdown_frame_images();
    if( g_vbo ) glDeleteBuffers( 1, &g_vbo );
    if( g_vao ) glDeleteVertexArrays( 1, &g_vao );
    if( g_program ) glDeleteProgram( g_program );
    g_vbo = g_vao = g_program = 0;
}

void use_texture( GLuint tex, int layer )
{
    g_current_tex = tex;
    g_current_layer = layer;
}

GLuint make_texture( int w, int h, int layers, const void* rgba )
{
    ZoneScoped;
    GLuint tex = 0;
    glGenTextures( 1, &tex );
    glBindTexture( GL_TEXTURE_2D_ARRAY, tex );
    glTexParameteri( GL_TEXTURE_2D_ARRAY, GL_TEXTURE_MIN_FILTER, GL_NEAREST );
    glTexParameteri( GL_TEXTURE_2D_ARRAY, GL_TEXTURE_MAG_FILTER, GL_NEAREST );
    glTexParameteri( GL_TEXTURE_2D_ARRAY, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    glTexParameteri( GL_TEXTURE_2D_ARRAY, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );
    glPixelStorei( GL_UNPACK_ALIGNMENT, 1 );
    glTexImage3D( GL_TEXTURE_2D_ARRAY, 0, GL_RGBA, w, h, layers, 0, GL_RGBA, GL_UNSIGNED_BYTE, rgba );
    return tex;
}

} // namespace Render

namespace Gfx
{

void clear()
{
    glClear( GL_COLOR_BUFFER_BIT );
}

void swap()
{
    ZoneScoped;
    flush_batch();
    capture_frame_image();
    SDL_GL_SwapWindow( g_window );
    FrameMark;
}

void alpha( float a )
{
    g_alpha = a;
}

void draw_quad( const Vertex corners[4] )
{
    ZoneScoped;
    // Two triangles, vertices appended in submission order so painter ordering
    // (and the transient per-monster alpha) is preserved by the batch.
    const int idx[6] = { 0, 1, 2, 0, 2, 3 };
    for( int i : idx )
    {
        const Vertex& c = corners[i];
        g_verts.push_back( { c.x, c.y, c.u, c.v,
                             static_cast<float>( g_current_layer ), g_alpha } );
    }

    if( !g_cmds.empty() && g_cmds.back().tex == g_current_tex )
        g_cmds.back().count += 6;
    else
        g_cmds.push_back( { g_current_tex, 6 } );
}

void draw_sprite( int x, int y )
{
    ZoneScoped;
    float fx = static_cast<float>( x );
    float fy = static_cast<float>( y );
    float top = static_cast<float>( h ) - fy;
    float bottom = static_cast<float>( h ) - ( fy + 64.0f );
    Vertex corners[4] = {
        { fx, top, 0.0f, 0.0f },
        { fx + 64.0f, top, 1.0f, 0.0f },
        { fx + 64.0f, bottom, 1.0f, 1.0f },
        { fx, bottom, 0.0f, 1.0f },
    };
    draw_quad( corners );
}

void draw_square( int x, int y )
{
    draw_sprite( x * 64, y * 64 );
}

void show_help()
{
    ZoneScoped;
    Textures::menu.bind();

    const float fw = static_cast<float>( w );
    const float fh = static_cast<float>( h );
    Vertex bg[4] = {
        { 0.0f, fh, 0.0f, 0.0f },
        { fw, fh, 832.0f / 1024, 0.0f },
        { fw, 0.0f, 832.0f / 1024, 704.0f / 1024 },
        { 0.0f, 0.0f, 0.0f, 704.0f / 1024 },
    };
    draw_quad( bg );

    int t = static_cast<int>( Timer::get_timestamp() / 40 );

    Textures::p_r.bind( t );
    draw_sprite( 150, 85 );
    Textures::m1_r.bind( t );
    draw_sprite( 75, 160 );
    Textures::m2_r.bind( t );
    draw_sprite( 150, 160 );
    Textures::m3_r.bind( t );
    draw_sprite( 225, 160 );
    Textures::bomb.bind( static_cast<int>( Timer::get_timestamp() / 100 % 2 ) );
    draw_sprite( 150, 235 );
    Textures::wall.bind();
    draw_sprite( 150, 310 );
    Textures::crate.bind();
    draw_sprite( 150, 385 );
    Textures::vortex.bind( t );
    draw_sprite( 150, 460 );
    Textures::bonus1.bind( t );
    draw_sprite( 112, 535 );
    Textures::bonus2.bind( t );
    draw_sprite( 187, 535 );
}

void show_menu()
{
    ZoneScoped;
    Textures::menu.bind();

    Vertex logo[4] = {
        { float( ( w - 594 ) / 2 ), float( h - 50 ), 1.0f, 0.0f },
        { float( ( w + 594 ) / 2 ), float( h - 50 ), 1.0f, 594.0f / 1024 },
        { float( ( w + 594 ) / 2 ), float( h - 50 - 180 ), 1.0f - 180.0f / 1024, 594.0f / 1024 },
        { float( ( w - 594 ) / 2 ), float( h - 50 - 180 ), 1.0f - 180.0f / 1024, 0.0f },
    };
    draw_quad( logo );

    Vertex prompt[4] = {
        { float( ( w - 527 ) / 2 ), 335.0f, 0.0f, 704.0f / 1024 },
        { float( ( w + 527 ) / 2 ), 335.0f, 527.0f / 1024, 704.0f / 1024 },
        { float( ( w + 527 ) / 2 ), 20.0f, 527.0f / 1024, 1019.0f / 1024 },
        { float( ( w - 527 ) / 2 ), 20.0f, 0.0f, 1019.0f / 1024 },
    };
    draw_quad( prompt );
}

} // namespace Gfx

namespace Init
{

bool all()
{
    ZoneScoped;
    if( !SDL_Init( SDL_INIT_VIDEO ) )
    {
        std::fprintf( stderr, "SDL_Init failed: %s\n", SDL_GetError() );
        return false;
    }

    SDL_GL_SetAttribute( SDL_GL_DOUBLEBUFFER, 1 );
    SDL_GL_SetAttribute( SDL_GL_CONTEXT_MAJOR_VERSION, 3 );
    SDL_GL_SetAttribute( SDL_GL_CONTEXT_MINOR_VERSION, 3 );
    SDL_GL_SetAttribute( SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE );

    g_window = SDL_CreateWindow( "Dyna.net", Gfx::w, Gfx::h, SDL_WINDOW_OPENGL );
    if( !g_window )
    {
        std::fprintf( stderr, "SDL_CreateWindow failed: %s\n", SDL_GetError() );
        return false;
    }

    g_gl_context = SDL_GL_CreateContext( g_window );
    if( !g_gl_context )
    {
        std::fprintf( stderr, "SDL_GL_CreateContext failed: %s\n", SDL_GetError() );
        return false;
    }

    int version = gladLoadGL( (GLADloadfunc)SDL_GL_GetProcAddress );
    if( version == 0 )
    {
        std::fprintf( stderr, "gladLoadGL failed\n" );
        return false;
    }

    SDL_GL_SetSwapInterval( 1 );   // vsync; the game is time-based so speed is unaffected

    glViewport( 0, 0, Gfx::w, Gfx::h );
    glClearColor( 0.0f, 0.0f, 0.0f, 1.0f );
    glEnable( GL_BLEND );
    glBlendFunc( GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA );

    if( !Render::init() ) return false;

    Timer::reset();
    Textures::preload();
    return true;
}

void shutdown()
{
    ZoneScoped;
    Render::shutdown();
    if( g_gl_context ) SDL_GL_DestroyContext( g_gl_context );
    if( g_window ) SDL_DestroyWindow( g_window );
    SDL_Quit();
}

} // namespace Init

}
