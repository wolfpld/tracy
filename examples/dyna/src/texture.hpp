#pragma once

#include <glad/gl.h>

struct SDL_Surface;

namespace dyna
{

// Move-only RAII owner of a GL texture name. Every texture in the game is a
// GL_TEXTURE_2D_ARRAY (static images use a single layer, animations use one
// layer per frame) so the renderer only ever has to deal with one sampler type.
class GlTexture
{
public:
    GlTexture() = default;
    explicit GlTexture( GLuint id ) noexcept : id_( id ) {}
    ~GlTexture() { reset(); }

    GlTexture( GlTexture&& o ) noexcept : id_( o.id_ ) { o.id_ = 0; }
    GlTexture& operator=( GlTexture&& o ) noexcept
    {
        if( this != &o )
        {
            reset();
            id_ = o.id_;
            o.id_ = 0;
        }
        return *this;
    }

    GlTexture( const GlTexture& ) = delete;
    GlTexture& operator=( const GlTexture& ) = delete;

    GLuint get() const { return id_; }
    explicit operator bool() const { return id_ != 0; }

    void reset();   // glDeleteTextures; safe on an empty handle

private:
    GLuint id_ = 0;
};

// A single static texture loaded from a whole image file. Ported from
// texture.cs; binding just records the texture for the next draw call.
class Texture
{
public:
    bool load( const char* fn );
    void bind() const;

private:
    GlTexture tex_;
};

// A vertical strip of 64x64 animation frames cut out of a sprite sheet, stored
// as the layers of one array texture. Mirrors AnimTexture in texture.cs.
class AnimTexture
{
public:
    // Extract n frames from column `tilex`, starting at row `tiley`, where each
    // coordinate is in 64px tile units. Mirrors AnimTexture.load in texture.cs.
    void load( SDL_Surface* sheet, int tilex, int tiley, int n );
    void bind( int frame ) const;   // frame is taken modulo the frame count

private:
    GlTexture tex_;
    int frames_ = 0;
};

// All game textures, loaded once at startup. Mirrors the Textures class.
namespace Textures
{
extern Texture menu, sand, wall, crate;

extern AnimTexture p_wait, p_u, p_d, p_l, p_r, p_death;

extern AnimTexture bomb, bomb_appear, e_c, e_h, e_v, e_le, e_re, e_de, e_ue;

extern AnimTexture m1_death, m1_l, m1_r, m1_d, m1_u;
extern AnimTexture m2_death, m2_l, m2_r, m2_d, m2_u;
extern AnimTexture m3_death, m3_l, m3_r, m3_d, m3_u;

extern AnimTexture bonus1, bonus2;

extern AnimTexture vortex_appear, vortex;

void preload();
}

}
