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
    enum { BlockSize = 64*1024 };

public:
    tracy_force_inline LfqBlock()
        : head( nullptr )
        , tail( nullptr )
        , next( nullptr )
        , thread( 0 )
    {
        head.store( data );
        tail.store( data );
        dataEnd = data + BlockSize;
    }

    tracy_force_inline void Reset()
    {
        head.store( data );
        tail.store( data );
    }

    LfqBlock( const LfqBlock& ) = delete;
    LfqBlock( LfqBlock&& ) = delete;

    LfqBlock& operator=( const LfqBlock& ) = delete;
    LfqBlock& operator=( LfqBlock&& ) = delete;

    std::atomic<char*> head, tail;
    std::atomic<LfqBlock*> next;
    const char* dataEnd;
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
        : m_head( nullptr )
        , m_tail( nullptr )
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
        auto tailBlk = NextBlock( m_tail.load() );
        auto& tail = tailBlk->tail;
        ptr = tail.load();
        nextPtr = ptr + sz;
        return tail;
    }

    tracy_no_inline LfqBlock* NextBlock( LfqBlock* tailBlk );

    inline void FlushDataImpl();

    std::atomic<LfqProducerImpl*> m_next;
    std::atomic<bool> m_active, m_available;


    LfqProducerImpl( const LfqProducerImpl& ) = delete;
    LfqProducerImpl( LfqProducerImpl&& ) = delete;

    LfqProducerImpl& operator=( const LfqProducerImpl& ) = delete;
    LfqProducerImpl& operator=( LfqProducerImpl&& ) = delete;

private:
    uint64_t m_thread;
    std::atomic<LfqBlock*> m_head, m_tail;
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
        ptr = tail.load();
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
    {
        const auto numCpus = std::thread::hardware_concurrency();

        LfqBlock* prev = nullptr;
        for( unsigned int i=0; i<numCpus; i++ )
        {
            auto blk = AllocNewBlock();
            blk->next.store( prev );
            prev = blk;
        }
        m_freeBlocks.store( prev );

        LfqProducerImpl* prevProd = nullptr;
        for( unsigned int i=0; i<numCpus; i++ )
        {
            auto prod = AllocNewProducer();
            prod->m_next.store( prevProd );
            prevProd = prod;
        }
        m_producers.store( prevProd );
    }

    // Don't free anything, application is shutting down anyway
    ~LockFreeQueue()
    {
    }

    LfqBlock* GetFreeBlock()
    {
        LfqBlock* ptr = m_freeBlocks.load();
        for(;;)
        {
            if( !ptr ) return AllocNewBlock();
            auto next = ptr->next.load();
            if( m_freeBlocks.compare_exchange_strong( ptr, next ) )
            {
                ptr->next.store( nullptr );
                ptr->Reset();
                return ptr;
            }
        }
    }

    void ReleaseBlocks( LfqBlock* blk, LfqBlock* blkTail )
    {
        assert( blk );
        assert( blkTail );

        auto tail = m_blocksTail.load();
        for(;;)
        {
            if( !tail )
            {
                if( m_blocksTail.compare_exchange_strong( tail, blkTail ) )
                {
                    assert( m_blocksHead.load() == nullptr );
                    m_blocksHead.store( blk );
                    return;
                }
            }
            else
            {
                auto next = tail->next.load();
                if( next == nullptr )
                {
                    if( tail->next.compare_exchange_strong( next, blk ) )
                    {
                        m_blocksTail.store( blkTail );
                        assert( m_blocksHead.load() != nullptr );
                        return;
                    }
                }
                tail = m_blocksTail.load();
            }
        }
    }

    void FreeBlocks( LfqBlock* blk )
    {
        auto tail = blk;
        for(;;)
        {
            auto next = tail->next.load();
            if( !next ) break;
            tail = next;
        }
        auto head = m_freeBlocks.load();
        tail->next.store( head );
        while( !m_freeBlocks.compare_exchange_weak( head, blk ) ) tail->next.store( head );
    }

    LfqProducerImpl* GetIdleProducer()
    {
        LfqProducerImpl* prod = m_producers.load();
        assert( prod );
        for(;;)
        {
            bool available = prod->m_available.load();
            if( available )
            {
                if( prod->m_available.compare_exchange_strong( available, false ) ) return prod;
            }
            prod = prod->m_next.load();
            if( !prod )
            {
                prod = AllocNewProducer();
                prod->m_available.store( false );
                auto head = m_producers.load();
                prod->m_next.store( head );
                while( !m_producers.compare_exchange_weak( head, prod ) ) { prod->m_next.store( head ); }
                return prod;
            }
        }
    }

    void ReleaseProducer( LfqProducerImpl* prod )
    {
        assert( prod->m_available.load() == false );
        prod->m_available.store( true );
    }

    tracy_force_inline size_t Dequeue( char* ptr, size_t sz, uint64_t& thread )
    {
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

    std::atomic<LfqBlock*> m_freeBlocks;
    std::atomic<LfqBlock*> m_blocksHead, m_blocksTail;
    std::atomic<LfqProducerImpl*> m_producers;
};


inline LfqProducer::LfqProducer( LockFreeQueue& queue )
    : m_prod( queue.GetIdleProducer() )
    , m_queue( &queue )
{
    assert( m_queue );
    m_prod->PrepareThread();
    assert( m_prod->m_active.load() == false );
    m_prod->m_active.store( true );
}

inline LfqProducer::~LfqProducer()
{
    if( m_prod )
    {
        assert( m_prod->m_active.load() == true );
        m_prod->m_active.store( false );
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
    assert( blk->next.load() == nullptr );
    blk->thread = m_thread;
    lfq.dataEnd = blk->dataEnd;
    lfq.tail = &blk->tail;
    m_head.store( blk );
    m_tail.store( blk );
}

tracy_force_inline void LfqProducerImpl::CleanupThread()
{
    auto blk = m_head.load();
    assert( blk );
    while( !m_head.compare_exchange_weak( blk, nullptr ) ) {}
    assert( blk );
    auto blkTail = m_tail.load();
    m_queue->ReleaseBlocks( blk, blkTail );
}

void LfqProducerImpl::FlushDataImpl()
{
    auto blk = m_head.load();
    m_queue->FreeBlocks( blk );
    PrepareThread();
}

}

#endif
