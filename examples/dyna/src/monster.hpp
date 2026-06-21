#pragma once

#include "entity.hpp"

#include <vector>

namespace dyna
{

class AnimTexture;

// The three monster variants from monster.cs differed only in speed, sprite set
// and respawn delay, so they fold into one class parameterised by `type` (1-3).
class Monster : public Entity
{
public:
    Monster( int type, int gx, int gy );

    void set_action( Action a ) override;
    void tick( World& world ) override;
    void draw() override;
    void die( World& world ) override;

    bool is_dead() const { return dead; }
    int type() const { return mtype; }

private:
    std::vector<Action> possible_dirs( const Map& map ) const;
    static bool straight( const std::vector<Action>& dirs );
    Action rand_dir( const Map& map );
    Action any_dir( const Map& map );        // __rand_dir in the original
    void think( const Map& map );
    void generic_draw( const AnimTexture& tex );
    const AnimTexture& texture_for( Action a ) const;

    int mtype;   // 1, 2 or 3
    int t;       // ms per movement sub-step (per-type speed)
    bool dead = false;
};

}
