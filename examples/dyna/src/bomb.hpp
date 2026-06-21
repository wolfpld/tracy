#pragma once

#include <utility>
#include <vector>

namespace dyna
{

class World;

// A bomb on the grid: fades in, counts down, then paints a cross-shaped
// explosion onto the map and clears it again. Ported from bomb.cs.
class Bomb
{
public:
    Bomb( int x, int y );

    void draw();
    void tick( World& world );

    bool is_dead() const { return dead; }

private:
    void explode( World& world );
    void die( World& world );

    enum class Stage
    {
        appear,
        ticking,
        exploding
    };

    int x, y;                 // grid coordinates
    Stage stage = Stage::appear;
    int left;
    int delta = 0;
    static constexpr int time = 150;
    static constexpr int maxrange = 1;
    std::vector<std::pair<int, int>> etiles;   // tiles to revert to floor
    bool dead = false;
};

}
