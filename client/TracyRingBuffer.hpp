namespace tracy
{

class RingBuffer
{
public:
    RingBuffer( uint32_t size, int fd )
        : m_size( size )
        , m_fd( fd )
    {
        const auto pageSize = uint32_t( getpagesize() );
        assert( size >= pageSize );
        assert( __builtin_popcount( size ) == 1 );
        m_mapSize = size + pageSize;
        m_mapAddr = mmap( nullptr, m_mapSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0 );
        if( !m_mapAddr )
        {
            m_fd = 0;
            close( fd );
            return;
        }
        m_metadata = (perf_event_mmap_page*)m_mapAddr;
        assert( m_metadata->data_offset == pageSize );
        m_buffer = ((char*)m_mapAddr) + pageSize;
    }

    ~RingBuffer()
    {
        if( m_mapAddr ) munmap( m_mapAddr, m_mapSize );
        if( m_fd ) close( m_fd );
    }

    RingBuffer( const RingBuffer& ) = delete;
    RingBuffer& operator=( const RingBuffer& ) = delete;

    RingBuffer( RingBuffer&& other )
    {
        memcpy( (char*)&other, (char*)this, sizeof( RingBuffer ) );
        m_mapAddr = nullptr;
        m_fd = 0;
    }

    RingBuffer& operator=( RingBuffer&& other )
    {
        memcpy( (char*)&other, (char*)this, sizeof( RingBuffer ) );
        m_mapAddr = nullptr;
        m_fd = 0;
        return *this;
    }

    bool IsValid() const { return m_mapAddr != nullptr; }

    void Enable()
    {
        ioctl( m_fd, PERF_EVENT_IOC_ENABLE, 0 );
    }

    bool HasData() const
    {
        const auto head = LoadHead();
        return head > m_metadata->data_tail;
    }

    void Read( void* dst, uint64_t offset, uint64_t cnt )
    {
        auto src = ( m_metadata->data_tail + offset ) % m_size;
        if( src + cnt <= m_size )
        {
            memcpy( dst, m_buffer + src, cnt );
        }
        else
        {
            const auto s0 = m_size - src;
            memcpy( dst, m_buffer + src, s0 );
            memcpy( (char*)dst + s0, m_buffer, cnt - s0 );
        }
    }

    void Advance( uint64_t cnt )
    {
        StoreTail( m_metadata->data_tail + cnt );
    }

private:
    uint64_t LoadHead() const
    {
        return std::atomic_load_explicit( (const volatile std::atomic<uint64_t>*)&m_metadata->data_head, std::memory_order_acquire );
    }

    void StoreTail( uint64_t tail )
    {
        std::atomic_store_explicit( (volatile std::atomic<uint64_t>*)&m_metadata->data_tail, tail, std::memory_order_release );
    }

    size_t m_size;
    size_t m_mapSize;
    void* m_mapAddr;

    perf_event_mmap_page* m_metadata;
    char* m_buffer;

    int m_fd;
};

}
