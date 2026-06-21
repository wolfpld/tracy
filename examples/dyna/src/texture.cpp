#include "texture.hpp"

#include "datapath.hpp"
#include "gfx.hpp"

#include <SDL3/SDL.h>
#include <SDL3_image/SDL_image.h>
#include <tracy/Tracy.hpp>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>

namespace dyna
{

void GlTexture::reset()
{
    if( id_ )
    {
        // The texture globals outlive main(), so their destructors can run after
        // the GL context is already gone (which frees its textures anyway). Only
        // call into GL while a context is current; otherwise just drop the name.
        if( SDL_GL_GetCurrentContext() )
            glDeleteTextures( 1, &id_ );
        id_ = 0;
    }
}

namespace
{

struct SurfaceDeleter
{
    void operator()( SDL_Surface* s ) const { SDL_DestroySurface( s ); }
};
using SurfacePtr = std::unique_ptr<SDL_Surface, SurfaceDeleter>;

// Convert an arbitrary surface to tightly addressable RGBA8. Returns null on
// failure; the result owns its pixels.
SurfacePtr to_rgba( SDL_Surface* src )
{
    ZoneScoped;
    if( !src ) return nullptr;
    return SurfacePtr{ SDL_ConvertSurface( src, SDL_PIXELFORMAT_RGBA32 ) };
}

} // namespace

bool Texture::load( const char* fn )
{
    ZoneScoped;
    ZoneText( fn, strlen( fn ) );

    SurfacePtr image{ IMG_Load( fn ) };
    if( !image )
    {
        std::fprintf( stderr, "Cannot open texture %s: %s\n", fn, SDL_GetError() );
        return false;
    }

    SurfacePtr rgba = to_rgba( image.get() );
    if( !rgba )
    {
        std::fprintf( stderr, "Cannot convert texture %s: %s\n", fn, SDL_GetError() );
        return false;
    }

    // Pack the surface into a tight RGBA8 block, skipping any per-row padding.
    const int w = rgba->w, h = rgba->h;
    std::vector<std::uint8_t> packed( static_cast<size_t>( w ) * h * 4 );
    const auto* pixels = static_cast<const std::uint8_t*>( rgba->pixels );
    for( int row = 0; row < h; row++ )
    {
        std::memcpy( &packed[static_cast<size_t>( row ) * w * 4],
                     pixels + static_cast<size_t>( row ) * rgba->pitch,
                     static_cast<size_t>( w ) * 4 );
    }

    tex_ = GlTexture{ Render::make_texture( w, h, 1, packed.data() ) };
    return static_cast<bool>( tex_ );
}

void Texture::bind() const
{
    Render::use_texture( tex_.get(), 0 );
}

void AnimTexture::load( SDL_Surface* sheet, int tilex, int tiley, int n )
{
    ZoneScoped;

    SurfacePtr rgba = to_rgba( sheet );
    if( !rgba )
    {
        std::fprintf( stderr, "Cannot convert sprite sheet: %s\n", SDL_GetError() );
        return;
    }

    const auto* pixels = static_cast<const std::uint8_t*>( rgba->pixels );
    const int pitch = rgba->pitch;

    // Lay the n frames out back to back as the layers of an array texture.
    constexpr int frame_bytes = 64 * 64 * 4;
    std::vector<std::uint8_t> frames( static_cast<size_t>( n ) * frame_bytes );
    for( int i = 0; i < n; i++ )
    {
        for( int fy = 0; fy < 64; fy++ )
        {
            int srcy = 64 * ( tiley + i ) + fy;
            int srcx = 64 * tilex;
            std::memcpy( &frames[static_cast<size_t>( i ) * frame_bytes + static_cast<size_t>( fy ) * 64 * 4],
                         pixels + static_cast<size_t>( srcy ) * pitch + static_cast<size_t>( srcx ) * 4,
                         static_cast<size_t>( 64 ) * 4 );
        }
    }

    tex_ = GlTexture{ Render::make_texture( 64, 64, n, frames.data() ) };
    frames_ = n;
}

void AnimTexture::bind( int frame ) const
{
    if( frames_ <= 0 ) return;
    int layer = frame % frames_;
    if( layer < 0 ) layer += frames_;
    Render::use_texture( tex_.get(), layer );
}

namespace Textures
{
Texture menu, sand, wall, crate;

AnimTexture p_wait, p_u, p_d, p_l, p_r, p_death;

AnimTexture bomb, bomb_appear, e_c, e_h, e_v, e_le, e_re, e_de, e_ue;

AnimTexture m1_death, m1_l, m1_r, m1_d, m1_u;
AnimTexture m2_death, m2_l, m2_r, m2_d, m2_u;
AnimTexture m3_death, m3_l, m3_r, m3_d, m3_u;

AnimTexture bonus1, bonus2;

AnimTexture vortex_appear, vortex;

void preload()
{
    ZoneScoped;

    menu.load( data_path( "data/gfx/menu.png" ).c_str() );
    sand.load( data_path( "data/gfx/sand.png" ).c_str() );
    wall.load( data_path( "data/gfx/wall.png" ).c_str() );
    crate.load( data_path( "data/gfx/crate.png" ).c_str() );

    {
        SurfacePtr img{ IMG_Load( data_path( "data/gfx/Player.png" ).c_str() ) };
        p_wait.load( img.get(), 0, 0, 20 );
        p_d.load( img.get(), 1, 0, 20 );
        p_u.load( img.get(), 2, 0, 20 );
        p_l.load( img.get(), 3, 0, 20 );
        p_r.load( img.get(), 4, 0, 20 );
        p_death.load( img.get(), 5, 0, 20 );
    }

    {
        SurfacePtr img{ IMG_Load( data_path( "data/gfx/Bomb.png" ).c_str() ) };
        bomb.load( img.get(), 0, 0, 10 );
        bomb_appear.load( img.get(), 5, 0, 10 );
        e_c.load( img.get(), 1, 0, 5 );
        e_h.load( img.get(), 2, 0, 5 );
        e_v.load( img.get(), 1, 5, 5 );
        e_le.load( img.get(), 3, 0, 5 );
        e_re.load( img.get(), 2, 5, 5 );
        e_de.load( img.get(), 4, 0, 5 );
        e_ue.load( img.get(), 3, 5, 5 );
    }

    {
        SurfacePtr img{ IMG_Load( data_path( "data/gfx/monster1.png" ).c_str() ) };
        m1_death.load( img.get(), 0, 0, 20 );
        m1_u.load( img.get(), 1, 0, 10 );
        m1_l.load( img.get(), 2, 0, 10 );
        m1_d.load( img.get(), 1, 10, 10 );
        m1_r.load( img.get(), 2, 10, 10 );
    }

    {
        SurfacePtr img{ IMG_Load( data_path( "data/gfx/monster2.png" ).c_str() ) };
        m2_death.load( img.get(), 0, 0, 20 );
        m2_d.load( img.get(), 1, 0, 20 );
        m2_u.load( img.get(), 2, 0, 20 );
        m2_l.load( img.get(), 3, 0, 20 );
        m2_r.load( img.get(), 4, 0, 20 );
    }

    {
        SurfacePtr img{ IMG_Load( data_path( "data/gfx/monster3.png" ).c_str() ) };
        m3_death.load( img.get(), 0, 0, 20 );
        m3_d.load( img.get(), 1, 0, 9 );
        m3_u.load( img.get(), 2, 0, 9 );
        m3_l.load( img.get(), 1, 10, 9 );
        m3_r.load( img.get(), 2, 10, 9 );
    }

    {
        SurfacePtr img{ IMG_Load( data_path( "data/gfx/bonusy.png" ).c_str() ) };
        bonus1.load( img.get(), 0, 0, 20 );
        bonus2.load( img.get(), 1, 0, 20 );
    }

    {
        SurfacePtr img{ IMG_Load( data_path( "data/gfx/portal.png" ).c_str() ) };
        vortex_appear.load( img.get(), 0, 0, 20 );
        vortex.load( img.get(), 1, 0, 20 );
    }
}
}

}
