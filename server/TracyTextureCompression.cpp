#include "../zstd/zstd.h"

#include "TracyEvent.hpp"
#include "TracyTextureCompression.hpp"

namespace tracy
{

TextureCompression::TextureCompression()
    : m_buf( nullptr )
    , m_bufSize( 0 )
    , m_cctx( ZSTD_createCCtx() )
    , m_dctx( ZSTD_createDCtx() )
{
}

TextureCompression::~TextureCompression()
{
    delete[] m_buf;
    ZSTD_freeCCtx( m_cctx );
    ZSTD_freeDCtx( m_dctx );
}

void TextureCompression::Pack( struct ZSTD_CCtx_s* ctx, char*& buf, size_t& bufsz, const char* image, uint32_t inBytes, uint32_t& csz ) const
{
    const auto maxout = ZSTD_COMPRESSBOUND( inBytes );
    if( bufsz < maxout )
    {
        bufsz = maxout;
        delete[] buf;
        buf = new char[maxout];
    }
    assert( ctx );
    const auto outsz = ZSTD_compressCCtx( ctx, buf, maxout, image, inBytes, 3 );
    csz = uint32_t( outsz );
}

uint32_t TextureCompression::PackImpl( const char* image, uint32_t inBytes )
{
    const auto maxout = ZSTD_COMPRESSBOUND( inBytes );
    if( m_bufSize < maxout )
    {
        m_bufSize = maxout;
        delete[] m_buf;
        m_buf = new char[maxout];
    }
    assert( m_cctx );
    return (uint32_t)ZSTD_compressCCtx( m_cctx, m_buf, maxout, image, inBytes, 1 );
}

const char* TextureCompression::Unpack( const FrameImage& image )
{
    const auto outsz = size_t( image.w ) * size_t( image.h ) / 2;
    if( m_bufSize < outsz )
    {
        m_bufSize = outsz;
        delete[] m_buf;
        m_buf = new char[outsz];
    }
    assert( m_dctx );
    ZSTD_decompressDCtx( m_dctx, m_buf, outsz, image.ptr, image.csz );
    return m_buf;
}

}
