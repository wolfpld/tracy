#ifndef __TRACYMESH_HPP__
#define __TRACYMESH_HPP__

#include "TracyProfiler.hpp"

namespace tracy
{
namespace mesh
{

static void MeshTri( float x0, float y0, float x1, float y1, float x2, float y2 )
{
    Magic magic;
    auto token = GetToken();
    auto& tail = token->get_tail_index();
    auto item = token->enqueue_begin( magic );
    MemWrite( &item->hdr.type, QueueType::MeshTri );
    MemWrite( &item->meshTri.x0, x0 );
    MemWrite( &item->meshTri.y0, y0 );
    MemWrite( &item->meshTri.x1, x1 );
    MemWrite( &item->meshTri.y1, y1 );
    MemWrite( &item->meshTri.x2, x2 );
    MemWrite( &item->meshTri.y2, y2 );
    tail.store( magic + 1, std::memory_order_release );
}

static void MeshEnd()
{
    Magic magic;
    auto token = GetToken();
    auto& tail = token->get_tail_index();
    auto item = token->enqueue_begin( magic );
    MemWrite( &item->hdr.type, QueueType::MeshEnd );
    tail.store( magic + 1, std::memory_order_release );
}

}
}

#endif
