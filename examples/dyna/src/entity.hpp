#pragma once

#include <cstdint>

namespace dyna
{

class Map;
class World;

// Movement/state verbs shared by the player and monsters. In the C# source this
// lived as Entity.Action; promoted to namespace scope so Game can refer to it.
enum class Action
{
    wait,
    up,
    down,
    left,
    right,
    death,
    place_bomb,
    appear
};

// Base for everything that moves on the grid. Coordinates are in pixels
// (64 per tile) and laid out top-left origin, matching entity.cs.
class Entity
{
public:
    virtual ~Entity() = default;

    virtual void set_action( Action a );

    int getx() const { return x; }
    int gety() const { return y; }

    virtual void draw() = 0;
    virtual void tick( World& world ) = 0;
    virtual void die( World& world ) = 0;

protected:
    bool can_move( Action a, const Map& map ) const;
    virtual bool killed( const Map& map ) const;

    int x = 0, y = 0;
    std::int64_t action_start = 0;
    int delta = 0;
    Action action = Action::wait;
    int left = 0;
};

}
