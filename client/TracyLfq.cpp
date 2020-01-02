#include "TracyLfq.hpp"

namespace tracy
{

LfqBlock* LfqProducerImpl::NextBlock( LfqBlock* tailBlk )
{
    auto next = m_queue->GetFreeBlock();
    assert( next );
    assert( next->next.load() == nullptr );
    assert( tailBlk->next.load() == nullptr );
    next->thread = m_thread;
    tailBlk->next.store( next );
    m_tail.store( next );
    lfq_dataEnd = next->dataEnd;
    lfq_tail = &next->tail;
    return next;
}

}
