namespace tracy
{

template<size_t Size>
class RingBuffer
{
public:
    RingBuffer( int fd )
        : m_fd( fd )
    {
        const auto pageSize = uint32_t( getpagesize() );
        assert( Size >= pageSize );
        assert( __builtin_popcount( Size ) == 1 );
        m_mapSize = Size + pageSize;
        auto mapAddr = mmap( nullptr, m_mapSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0 );
        if( !mapAddr )
        {
            m_fd = 0;
            close( fd );
            return;
        }
        m_metadata = (perf_event_mmap_page*)mapAddr;
        assert( m_metadata->data_offset == pageSize );
        m_buffer = ((char*)mapAddr) + pageSize;
    }

    ~RingBuffer()
    {
        if( m_metadata ) munmap( m_metadata, m_mapSize );
        if( m_fd ) close( m_fd );
    }

    RingBuffer( const RingBuffer& ) = delete;
    RingBuffer& operator=( const RingBuffer& ) = delete;

    RingBuffer( RingBuffer&& other )
    {
        memcpy( (char*)&other, (char*)this, sizeof( RingBuffer ) );
        m_metadata = nullptr;
        m_fd = 0;
    }

    RingBuffer& operator=( RingBuffer&& other )
    {
        memcpy( (char*)&other, (char*)this, sizeof( RingBuffer ) );
        m_metadata = nullptr;
        m_fd = 0;
        return *this;
    }

    bool IsValid() const { return m_metadata != nullptr; }

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
        auto src = ( m_metadata->data_tail + offset ) % Size;
        if( src + cnt <= Size )
        {
            memcpy( dst, m_buffer + src, cnt );
        }
        else
        {
            const auto s0 = Size - src;
            memcpy( dst, m_buffer + src, s0 );
            memcpy( (char*)dst + s0, m_buffer, cnt - s0 );
        }
    }

    void Advance( uint64_t cnt )
    {
        StoreTail( m_metadata->data_tail + cnt );
    }

    bool CheckTscCaps() const
    {
        return m_metadata->cap_user_time_zero;
    }

    int64_t ConvertTimeToTsc( int64_t timestamp ) const
    {
        assert( m_metadata->cap_user_time_zero );
        const auto time = timestamp - m_metadata->time_zero;
        const auto quot = time / m_metadata->time_mult;
        const auto rem = time % m_metadata->time_mult;
        return ( quot << m_metadata->time_shift ) + ( rem << m_metadata->time_shift ) / m_metadata->time_mult;
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

    perf_event_mmap_page* m_metadata;
    char* m_buffer;

    size_t m_mapSize;
    int m_fd;
};

}
