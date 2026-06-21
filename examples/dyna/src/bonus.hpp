#pragma once

#include "entity.hpp"

namespace dyna
{

// The level-exit portal. Unlike the other entities its coordinates are stored in
// grid units (it draws via draw_square), matching bonus.cs.
class Vortex : public Entity
{
public:
    Vortex( int gx, int gy );

    void draw() override;
    void tick( World& world ) override;
    void die( World& world ) override;
};

}
