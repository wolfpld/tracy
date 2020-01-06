#ifndef __TRACYLFQ_HPP__
#define __TRACYLFQ_HPP__

#include <atomic>
#include <assert.h>
#include <stdint.h>
#include <thread>

#include "../common/TracyApi.h"
#include "../common/TracyAlign.hpp"
#include "../common/TracyAlloc.hpp"
#include "../common/TracyForceInline.hpp"
#include "../common/TracyQueue.hpp"
#include "../common/TracySystem.hpp"
#include "../common/TracyYield.hpp"


#define TracyLfqPrepare( type ) \
    char* __nextPtr; \
    QueueItem* item; \
    auto& __tail = LfqProducer::PrepareNext( item, __nextPtr, type );

#define TracyLfqCommit \
    LfqProducer::CommitNext( __tail, __nextPtr );

#define TracyLfqPrepareC( type ) \
    char* nextPtr; \
    tracy::QueueItem* item; \
    auto& tail = tracy::LfqProducer::PrepareNext( item, nextPtr, type );

#define TracyLfqCommitC \
    tracy::LfqProducer::CommitNext( tail, nextPtr );

namespace tracy
{


class LockFreeQueue;
class LfqProducer;

TRACY_API LfqProducer& GetProducer();


class LfqBlock
{
public:
    enum { BlockSize = 64*1024 };

    tracy_force_inline LfqBlock()
        : head( nullptr )
        , tail( nullptr )
        , next( nullptr )
        , thread( 0 )
    {
        dataEnd = data + BlockSize;
        head.store( data, std::memory_order_relaxed );
        tail.store( data, std::memory_order_release );
    }

    tracy_force_inline void Reset()
    {
        head.store( data, std::memory_order_relaxed );
        tail.store( data, std::memory_order_release );
    }

    LfqBlock( const LfqBlock& ) = delete;
    LfqBlock( LfqBlock&& ) = delete;

    LfqBlock& operator=( const LfqBlock& ) = delete;
    LfqBlock& operator=( LfqBlock&& ) = delete;

    alignas(64) std::atomic<char*> head;
    alignas(64) std::atomic<char*> tail;
    alignas(64) std::atomic<LfqBlock*> next;
    alignas(64) const char* dataEnd;
    uint64_t thread;
    char data[BlockSize];
};


struct LfqData
{
    const char* dataEnd;
    std::atomic<char*>* tail;
};

extern thread_local LfqData lfq;


class LfqProducerImpl
{
public:
    tracy_force_inline LfqProducerImpl( LockFreeQueue* queue )
        : m_block( nullptr )
        , m_active( false )
        , m_available( true )
        , m_queue( queue )
    {
        assert( m_queue );
    }

    tracy_force_inline void PrepareThread();
    tracy_force_inline void CleanupThread();

    tracy_force_inline std::atomic<char*>& PrepareNext( char*& ptr, char*& nextPtr, size_t sz )
    {
        auto blk = NextBlock();
        auto& tail = blk->tail;
        ptr = tail.load( std::memory_order_relaxed );
        nextPtr = ptr + sz;
        return tail;
    }

    tracy_no_inline LfqBlock* NextBlock();

    inline void FlushDataImpl();

    alignas(64) std::atomic<LfqProducerImpl*> m_next;
    alignas(64) std::atomic<bool> m_active;
    alignas(64) std::atomic<bool> m_available;
    alignas(64) std::atomic<LfqBlock*> m_block;


    LfqProducerImpl( const LfqProducerImpl& ) = delete;
    LfqProducerImpl( LfqProducerImpl&& ) = delete;

    LfqProducerImpl& operator=( const LfqProducerImpl& ) = delete;
    LfqProducerImpl& operator=( LfqProducerImpl&& ) = delete;

private:
    uint64_t m_thread;
    LockFreeQueue* m_queue;
};


class LfqProducer
{
public:
    inline LfqProducer( LockFreeQueue& queue );
    inline ~LfqProducer();

    inline LfqProducer& operator=( LfqProducer&& ) noexcept;

    static tracy_force_inline std::atomic<char*>& PrepareNext( QueueItem*& item, char*& nextPtr, QueueType type )
    {
        char* ptr;
        auto& ret = PrepareNext( ptr, nextPtr, QueueDataSize[(uint8_t)type] );
        item = (QueueItem*)ptr;
        MemWrite( &item->hdr.type, type );
        return ret;
    }

    static tracy_force_inline std::atomic<char*>& PrepareNext( char*& ptr, char*& nextPtr, size_t sz )
    {
        auto& tail = *lfq.tail;
        ptr = tail.load( std::memory_order_relaxed );
        auto np = ptr + sz;
        if( np <= lfq.dataEnd )
        {
            nextPtr = np;
            return tail;
        }
        else
        {
            return GetProducer().m_prod->PrepareNext( ptr, nextPtr, sz );
        }
    }

    static tracy_force_inline void CommitNext( std::atomic<char*>& tail, char* nextPtr )
    {
        tail.store( nextPtr, std::memory_order_release );
    }

    static tracy_force_inline void FlushData()
    {
        GetProducer().m_prod->FlushDataImpl();
    }


    LfqProducer( const LfqProducer& ) = delete;
    LfqProducer( LfqProducer&& ) = delete;

    LfqProducer& operator=( const LfqProducer& ) = delete;

private:
    LfqProducerImpl* m_prod;
    LockFreeQueue* m_queue;
};


class LockFreeQueue
{
public:
    LockFreeQueue()
        : m_freeBlocks( nullptr )
        , m_blocksHead( nullptr )
        , m_blocksTail( nullptr )
        , m_producers( nullptr )
        , m_currentProducer( nullptr )
    {
        const auto numCpus = std::thread::hardware_concurrency();

        LfqBlock* prev = nullptr;
        for( unsigned int i=0; i<numCpus; i++ )
        {
            auto blk = AllocNewBlock();
            blk->next.store( prev, std::memory_order_relaxed );
            prev = blk;
        }
        m_freeBlocks.store( prev, std::memory_order_release );

        LfqProducerImpl* prevProd = nullptr;
        for( unsigned int i=0; i<numCpus; i++ )
        {
            auto prod = AllocNewProducer();
            prod->m_next.store( prevProd, std::memory_order_relaxed );
            prevProd = prod;
        }
        m_producers.store( prevProd, std::memory_order_release );
    }

    // Don't free anything, application is shutting down anyway
    ~LockFreeQueue()
    {
    }

    LfqBlock* GetFreeBlock()
    {
        LfqBlock* ptr = m_freeBlocks.load( std::memory_order_acquire );
        for(;;)
        {
            if( !ptr ) return AllocNewBlock();
            auto next = ptr->next.load( std::memory_order_acquire );
            if( m_freeBlocks.compare_exchange_strong( ptr, next, std::memory_order_release, std::memory_order_relaxed ) )
            {
                ptr->next.store( nullptr, std::memory_order_relaxed );
                ptr->Reset();
                return ptr;
            }
        }
    }

    void ReleaseBlock( LfqBlock* blk )
    {
        assert( blk );
        assert( blk->next.load( std::memory_order_relaxed ) == nullptr );
        auto tail = m_blocksTail.load( std::memory_order_acquire );
        for(;;)
        {
            if( !tail )
            {
                auto head = m_blocksHead.load( std::memory_order_acquire );
                if( !head )
                {
                    if( m_blocksHead.compare_exchange_strong( head, blk, std::memory_order_release, std::memory_order_relaxed ) )
                    {
                        assert( m_blocksTail.load( std::memory_order_relaxed ) == nullptr );
                        m_blocksTail.store( blk, std::memory_order_release );
                        return;
                    }
                }
            }
            else
            {
                auto next = tail->next.load( std::memory_order_acquire );
                if( !next )
                {
                    if( tail->next.compare_exchange_strong( next, blk, std::memory_order_release, std::memory_order_relaxed ) )
                    {
                        m_blocksTail.store( blk, std::memory_order_release );
                        return;
                    }
                }
            }
        }
    }

    void FreeBlock( LfqBlock* blk )
    {
        assert( blk );
        auto head = m_freeBlocks.load( std::memory_order_relaxed );
        blk->next.store( head, std::memory_order_relaxed );
        while( !m_freeBlocks.compare_exchange_weak( head, blk, std::memory_order_release, std::memory_order_relaxed ) ) { blk->next.store( head, std::memory_order_relaxed ); YieldThread(); }
    }

    LfqProducerImpl* GetIdleProducer()
    {
        LfqProducerImpl* prod = m_producers.load( std::memory_order_acquire );
        assert( prod );
        for(;;)
        {
            bool available = prod->m_available.load( std::memory_order_acquire );
            if( available )
            {
                if( prod->m_available.compare_exchange_strong( available, false, std::memory_order_release, std::memory_order_relaxed ) ) return prod;
            }
            prod = prod->m_next.load( std::memory_order_acquire );
            if( !prod )
            {
                prod = AllocNewProducer();
                prod->m_available.store( false, std::memory_order_release );
                auto head = m_producers.load( std::memory_order_relaxed );
                prod->m_next.store( head, std::memory_order_relaxed );
                while( !m_producers.compare_exchange_weak( head, prod, std::memory_order_release, std::memory_order_relaxed ) ) { prod->m_next.store( head, std::memory_order_relaxed ); YieldThread(); }
                return prod;
            }
        }
    }

    void ReleaseProducer( LfqProducerImpl* prod )
    {
        assert( prod->m_available.load( std::memory_order_relaxed ) == false );
        prod->m_available.store( true, std::memory_order_release );
    }

    size_t Dequeue( char* ptr, size_t sz, uint64_t& thread )
    {
        {
            auto blk = m_blocksHead.load( std::memory_order_acquire );
            if( blk != nullptr )
            {
                auto next = blk->next.load( std::memory_order_acquire );
                if( m_blocksHead.compare_exchange_strong( blk, next, std::memory_order_release, std::memory_order_relaxed ) )
                {
                    if( next == nullptr )
                    {
                        m_blocksTail.store( nullptr, std::memory_order_release );
                    }
                    auto head = blk->head.load( std::memory_order_relaxed );
                    auto tail = blk->tail.load( std::memory_order_acquire );
                    const auto datasz = tail - head;
                    if( datasz > 0 )
                    {
                        thread = blk->thread;
                        memcpy( ptr, head, datasz );
                        FreeBlock( blk );
                        return datasz;
                    }
                    FreeBlock( blk );
                }
            }
        }

        {
            LfqBlock* blk = nullptr;
            char* head;
            char* tail;
            auto prod = m_currentProducer;
            if( !prod ) prod = m_producers.load( std::memory_order_acquire );
            while( prod )
            {
                if( prod->m_active.load( std::memory_order_acquire ) == true )
                {
                    blk = prod->m_block.load( std::memory_order_acquire );
                    head = blk->head.load( std::memory_order_relaxed );
                    tail = blk->tail.load( std::memory_order_acquire );
                    if( tail - head != 0 )
                    {
                        break;
                    }
                }
                prod = prod->m_next.load( std::memory_order_acquire );
            }
            m_currentProducer = prod;

            if( prod )
            {
                const auto datasz = tail - head;
                assert( datasz != 0 );
                thread = blk->thread;
                memcpy( ptr, head, datasz );
                blk->head.store( tail, std::memory_order_release );
                return datasz;
            }
        }

        return 0;
    }


    LockFreeQueue( const LockFreeQueue& ) = delete;
    LockFreeQueue( LockFreeQueue&& ) = delete;

    LockFreeQueue& operator=( const LockFreeQueue& ) = delete;
    LockFreeQueue& operator=( LockFreeQueue&& ) = delete;

private:
    LfqBlock* AllocNewBlock()
    {
        auto blk = (LfqBlock*)tracy_malloc( sizeof( LfqBlock ) );
        new(blk) LfqBlock();
        return blk;
    }

    LfqProducerImpl* AllocNewProducer()
    {
        auto prod = (LfqProducerImpl*)tracy_malloc( sizeof( LfqProducerImpl ) );
        new(prod) LfqProducerImpl( this );
        return prod;
    }

    alignas(64) std::atomic<LfqBlock*> m_freeBlocks;
    alignas(64) std::atomic<LfqBlock*> m_blocksHead;
    alignas(64) std::atomic<LfqBlock*> m_blocksTail;
    alignas(64) std::atomic<LfqProducerImpl*> m_producers;
    alignas(64) LfqProducerImpl* m_currentProducer;
};


inline LfqProducer::LfqProducer( LockFreeQueue& queue )
    : m_prod( queue.GetIdleProducer() )
    , m_queue( &queue )
{
    assert( m_queue );
    m_prod->PrepareThread();
    assert( m_prod->m_active.load( std::memory_order_relaxed ) == false );
    m_prod->m_active.store( true, std::memory_order_release );
}

inline LfqProducer::~LfqProducer()
{
    if( m_prod )
    {
        assert( m_prod->m_active.load( std::memory_order_relaxed ) == true );
        m_prod->m_active.store( false, std::memory_order_release );
        m_prod->CleanupThread();
        m_queue->ReleaseProducer( m_prod );
    }
}

inline LfqProducer& LfqProducer::operator=( LfqProducer&& other ) noexcept
{
    m_prod = other.m_prod;
    m_queue = other.m_queue;

    other.m_prod = nullptr;
    other.m_queue = nullptr;

    return *this;
}


tracy_force_inline void LfqProducerImpl::PrepareThread()
{
    m_thread = detail::GetThreadHandleImpl();
    auto blk = m_queue->GetFreeBlock();
    assert( blk );
    assert( blk->next.load( std::memory_order_relaxed ) == nullptr );
    blk->thread = m_thread;
    lfq.dataEnd = blk->dataEnd;
    lfq.tail = &blk->tail;
    m_block.store( blk, std::memory_order_release );
}

tracy_force_inline void LfqProducerImpl::CleanupThread()
{
    auto blk = m_block.load( std::memory_order_relaxed );
    assert( blk );
    while( !m_block.compare_exchange_weak( blk, nullptr, std::memory_order_release, std::memory_order_relaxed ) ) { YieldThread(); }
    auto head = blk->head.load( std::memory_order_relaxed );
    auto tail = blk->tail.load( std::memory_order_acquire );
    if( head == tail )
    {
        m_queue->FreeBlock( blk );
    }
    else
    {
        m_queue->ReleaseBlock( blk );
    }
}

void LfqProducerImpl::FlushDataImpl()
{
    LfqBlock* blk = m_block.load( std::memory_order_acquire );
    m_block.store( nullptr, std::memory_order_release );
    if( blk ) m_queue->FreeBlock( blk );
    PrepareThread();
}

}

#endif
