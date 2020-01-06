#include "TracyLfq.hpp"

namespace tracy
{

LfqBlock* LfqProducerImpl::NextBlock()
{
    LfqBlock* blk = m_queue->GetFreeBlock();
    assert( blk );
    assert( blk->next.load( std::memory_order_relaxed ) == nullptr );
    blk->thread = m_thread;
    lfq.dataEnd = blk->dataEnd;
    lfq.tail = &blk->tail;
    LfqBlock* oldBlk = m_block.load( std::memory_order_relaxed );
    m_block.store( blk, std::memory_order_release );
    m_queue->ReleaseBlock( oldBlk );
    return blk;
}

}
