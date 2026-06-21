#pragma once

#include "entity.hpp"

namespace dyna
{

class Player : public Entity
{
public:
    Player( int gx, int gy );

    void tick( World& world ) override;
    void draw() override;
    void die( World& world ) override;

    void move( Action a );   // queues the next direction; applied between tiles

protected:
    bool killed( const Map& map ) const override;

private:
    static constexpr int t = 6;   // ms per movement sub-step
    Action queue = Action::wait;
};

}
