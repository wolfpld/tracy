#pragma once

#include <glad/gl.h>

namespace dyna
{

// Screen dimensions, matching the original 13x11 grid of 64px tiles.
namespace Gfx
{
constexpr int w = 832;
constexpr int h = 704;

void clear();
void swap();

// Drawing primitives ported from gfx.cs. They render with the currently
// bound texture (see Texture::bind) and the current alpha. The coordinate
// system is bottom-left origin with y growing upward, exactly as the C#
// gluOrtho2D setup; draw_sprite/draw_square take y measured from the top
// and flip internally, so game-side coordinates stay top-left based.
void alpha( float a );
void draw_sprite( int x, int y );   // pixel position of the top-left corner
void draw_square( int x, int y );   // grid position (multiplied by 64)

// A single textured quad given four explicit (position, texcoord) corners,
// used by the menu/help screens which sample rotated regions of the atlas.
struct Vertex
{
    float x, y, u, v;
};
void draw_quad( const Vertex corners[4] );

void show_help();
void show_menu();
}

// Renderer back end shared by the texture loaders.
namespace Render
{
bool init();         // shaders + streaming VBO/VAO
void shutdown();     // delete the program and buffers

// Select the array texture (and layer within it) used by subsequent draws.
void use_texture( GLuint tex, int layer );

// Upload `layers` tightly packed RGBA8 images of size w*h as one
// GL_TEXTURE_2D_ARRAY and return its name (0 on failure).
GLuint make_texture( int w, int h, int layers, const void* rgba );
}

// One-time startup/shutdown, ported from the Init class in gfx.cs.
namespace Init
{
bool all();        // SDL, GL context, renderer, textures, timer
void shutdown();
}

}
