#ifdef __linux__

#include <algorithm>
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>

#include "TracyDebug.hpp"
#include "TracyElf.hpp"
#include "TracyKCore.hpp"
#include "../common/TracyAlloc.hpp"


namespace tracy
{

KCore::KCore()
    : m_offsets( 16 )
{
    m_fd = open( "/proc/kcore", O_RDONLY );
    if( m_fd == -1 ) return;

    elf_ehdr ehdr;
    if( read( m_fd, &ehdr, sizeof( ehdr ) ) != sizeof( ehdr ) ) goto err;

    assert( ehdr.e_phentsize == sizeof( elf_phdr ) );

    for( elf_half i=0; i<ehdr.e_phnum; i++ )
    {
        elf_phdr phdr;
        if( lseek( m_fd, ehdr.e_phoff + i * ehdr.e_phentsize, SEEK_SET ) == -1 ) goto err;
        if( read( m_fd, &phdr, sizeof( phdr ) ) != sizeof( phdr ) ) goto err;
        if( phdr.p_type != 1 ) continue;

        auto ptr = m_offsets.push_next();
        ptr->start = phdr.p_vaddr;
        ptr->size = phdr.p_memsz;
        ptr->offset = phdr.p_offset;
    }

    std::sort( m_offsets.begin(), m_offsets.end(), []( const Offset& lhs, const Offset& rhs ) { return lhs.start < rhs.start; } );
    TracyDebug( "KCore: %zu segments found", m_offsets.size() );
    return;

err:
    close( m_fd );
    m_fd = -1;
}

KCore::~KCore()
{
    if( m_fd != -1 ) close( m_fd );
}

void* KCore::Retrieve( uint64_t addr, uint64_t size ) const
{
    if( m_fd == -1 ) return nullptr;
    auto it = std::lower_bound( m_offsets.begin(), m_offsets.end(), addr, []( const Offset& lhs, uint64_t rhs ) { return lhs.start + lhs.size < rhs; } );
    if( it == m_offsets.end() ) return nullptr;
    if( addr + size > it->start + it->size ) return nullptr;
    if( lseek( m_fd, it->offset + addr - it->start, SEEK_SET ) == -1 ) return nullptr;
    auto ptr = tracy_malloc( size );
    if( read( m_fd, ptr, size ) != ssize_t( size ) )
    {
        tracy_free( ptr );
        return nullptr;
    }
    return ptr;
}

}

#endif