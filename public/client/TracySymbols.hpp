#ifndef __TRACYSYMBOLS_HPP__
#define __TRACYSYMBOLS_HPP__

#include <limits>
#include <new>
#include <stdio.h>
#include <string.h>
#include "TracyCallstack.hpp"
#include "TracyDebug.hpp"
#include "TracyFastVector.hpp"
#include "TracyStringHelpers.hpp"
#include "../common/TracyAlloc.hpp"

//TODO: move to DL_ITERATE_PHDR symbol file.
#if defined(TRACY_USE_LIBBACKTRACE) && TRACY_HAS_CALLSTACK != 4 // dl_iterate_phdr is required for the current image cache. Need to move it to libbacktrace?
#   define TRACY_HAS_DL_ITERATE_PHDR_TO_REFRESH_IMAGE_CACHE
#   include <link.h>
#endif

namespace tracy
{
#ifdef TRACY_SYMBOL_OFFLINE_RESOLVE
constexpr bool s_shouldResolveSymbolsOffline = true;
#else
extern bool s_shouldResolveSymbolsOffline;
#endif // #ifdef TRACY_SYMBOL_OFFLINE_RESOLVE

inline bool ShouldResolveSymbolsOffline()
{
// when "TRACY_SYMBOL_OFFLINE_RESOLVE" is set, instead of fully resolving symbols at runtime,
// simply resolve the offset and image name (which will be enough the resolving to be done offline)
    const char* symbolOfflineResolve = GetEnvVar( "TRACY_SYMBOL_OFFLINE_RESOLVE" );
    return (symbolOfflineResolve && symbolOfflineResolve[0] == '1');
}

static bool IsKernelAddress(uint64_t addr) {
    return (addr >> 63) != 0;
}

void DestroyImageEntry( ImageEntry& entry )
{
    tracy_free( entry.m_path );
    tracy_free( entry.m_name );
}

class ImageCache
{
public:
    
    ImageCache( size_t imageCacheCapacity = 512 )
        : m_images( imageCacheCapacity )
    {
    }

    ~ImageCache()
    {
        Clear();
    }
    
    ImageEntry* AddEntry( const ImageEntry& entry )
    {
        if( m_sorted ) m_sorted = m_images.empty() || ( entry.m_startAddress < m_images.back().m_startAddress );
        ImageEntry* newEntry = m_images.push_next();
        *newEntry = entry;
        return newEntry;
    }

    const ImageEntry* GetImageForAddress( uint64_t address )
    {
        Sort();

        auto it = std::lower_bound( m_images.begin(), m_images.end(), address,
            []( const ImageEntry& lhs, const uint64_t rhs ) { return lhs.m_startAddress > rhs; } );

        if( it != m_images.end() && address < it->m_endAddress )
        {
            return it;
        }
        return nullptr;
    }
    
    void Sort()
    {
        if( m_sorted ) return;

        std::sort( m_images.begin(), m_images.end(),
            []( const ImageEntry& lhs, const ImageEntry& rhs ) { return lhs.m_startAddress > rhs.m_startAddress; } );
        m_sorted = true;
    }

    void Clear()
    {
        for( ImageEntry& entry : m_images )
        {
            DestroyImageEntry( entry );
        }

        m_sorted = true;
        m_images.clear();
    }

    bool ContainsImage( uint64_t startAddress ) const
    {
        return std::any_of( m_images.begin(), m_images.end(), [startAddress]( const ImageEntry& entry ) { return startAddress == entry.m_startAddress; } );
    }
protected:
    tracy::FastVector<ImageEntry> m_images;
    bool m_sorted = true;
};

//TODO: move to DL_ITERATE_PHDR symbol file.
#ifdef TRACY_HAS_DL_ITERATE_PHDR_TO_REFRESH_IMAGE_CACHE
// when we have access to dl_iterate_phdr(), we can build a cache of address ranges to image paths
// so we can quickly determine which image an address falls into.
// We refresh this cache only when we hit an address that doesn't fall into any known range.
class ImageCacheDlIteratePhdr : public ImageCache
{
public:

    ImageCacheDlIteratePhdr()
    {
        Refresh();
    }

    ~ImageCacheDlIteratePhdr()
    {
    }

    const ImageEntry* GetImageForAddress( uint64_t address )
    {
        const ImageEntry* entry = ImageCache::GetImageForAddress( address );
        if( !entry )
        {
            Refresh();
            return ImageCache::GetImageForAddress( address );
        }
        return entry;
    }

private:
    bool m_updated = false;
    bool m_haveMainImageName = false;

    static int Callback( struct dl_phdr_info* info, size_t size, void* data )
    {
        ImageCacheDlIteratePhdr* cache = reinterpret_cast<ImageCacheDlIteratePhdr*>( data );

        const auto startAddress = static_cast<uint64_t>( info->dlpi_addr );
        if( cache->ContainsImage( startAddress ) ) return 0;

        const uint32_t headerCount = info->dlpi_phnum;
        assert( headerCount > 0);
        const auto endAddress = static_cast<uint64_t>( info->dlpi_addr +
            info->dlpi_phdr[info->dlpi_phnum - 1].p_vaddr + info->dlpi_phdr[info->dlpi_phnum - 1].p_memsz);

        ImageEntry image{};
        image.m_startAddress = startAddress;
        image.m_endAddress = endAddress;

        // the base executable name isn't provided when iterating with dl_iterate_phdr,
        // we will have to patch the executable image name outside this callback
        image.m_name = info->dlpi_name && info->dlpi_name[0] != '\0' ? CopyStringFast( info->dlpi_name ) : nullptr;

        cache->AddEntry( image );
        cache->m_updated = true;

        return 0;
    }

    void Refresh()
    {
        m_updated = false;
        dl_iterate_phdr( Callback, this );

        if( m_updated )
        {
            Sort();
            // patch the main executable image name here, as calling dl_* functions inside the dl_iterate_phdr callback might cause deadlocks
            UpdateMainImageName();
        }
    }

    void UpdateMainImageName()
    {
        if( m_haveMainImageName )
        {
            return;
        }

        for( ImageEntry& entry : m_images )
        {
            if( entry.m_name == nullptr )
            {
                Dl_info dlInfo;
                if( dladdr( (void *)entry.m_startAddress, &dlInfo ) )
                {
                    if( dlInfo.dli_fname )
                    {
                        entry.m_name = CopyString( dlInfo.dli_fname );
                    }
                }

                // we only expect one entry to be null for the main executable entry
                break;
            }
        }

        m_haveMainImageName = true;
    }
    void Clear()
    {
        ImageCache::Clear();
        m_haveMainImageName = false;
    }
};
using UserlandImageCache = ImageCacheDlIteratePhdr;
#else
using UserlandImageCache = ImageCache;
#endif //#ifdef TRACY_HAS_DL_ITERATE_PHDR_TO_REFRESH_IMAGE_CACHE

extern UserlandImageCache* s_imageCache;
extern ImageCache* s_krnlCache;

inline void CreateImageCaches()
{
    assert( s_imageCache == nullptr && s_krnlCache == nullptr );
    s_imageCache = new ( tracy_malloc( sizeof( UserlandImageCache ) ) ) UserlandImageCache();
    s_krnlCache = new ( tracy_malloc( sizeof( ImageCache ) ) ) ImageCache();
}

inline void DestroyImageCaches()
{
    if( s_krnlCache != nullptr )
    {
        s_krnlCache->~ImageCache();
        tracy_free( s_krnlCache );
        s_krnlCache = nullptr;
    }

    if( s_imageCache != nullptr )
    {
        s_imageCache->~UserlandImageCache();
        tracy_free( s_imageCache );
        s_imageCache = nullptr;
    }

}


}

#endif // __TRACYSYMBOLS_HPP__