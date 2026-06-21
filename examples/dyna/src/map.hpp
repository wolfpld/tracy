#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace dyna
{

class Player;
class Bomb;
class Monster;
class Vortex;
class World;

// How a tile reacts to an explosion sweeping through it.
enum class Destruction
{
    none,    // blocks the blast (wall, bomb, existing explosion, vortex)
    single,  // destroyed and stops the blast (crate)
    multi    // passable, blast continues (floor)
};

// A grid cell. The C# version used a small class hierarchy rooted at a Field
// interface; since the variants differ only in a couple of flags and how they
// draw, this collapses them into one value type tagged by Kind. Note that in
// the original everything except Wall derived from Floor, so the "is Floor"
// checks there map to "kind != Wall" here.
struct Field
{
    enum class Kind
    {
        floor,
        wall,
        crate,
        bomb,       // tile occupied by a live bomb (solid, indestructible)
        explosion,  // transient blast tile
        vortex      // level exit portal
    };

    enum class ExplosionType
    {
        center,
        vertical,
        horizontal,
        left,
        right,
        down,
        up
    };

    Kind kind = Kind::floor;
    ExplosionType etype = ExplosionType::center;
    std::int64_t tstart = 0;   // explosion animation start, set on creation

    static Field floor() { return Field{}; }
    static Field wall() { return Field{ Kind::wall, {}, 0 }; }
    static Field crate() { return Field{ Kind::crate, {}, 0 }; }
    static Field bomb() { return Field{ Kind::bomb, {}, 0 }; }
    static Field vortex() { return Field{ Kind::vortex, {}, 0 }; }
    static Field explosion( ExplosionType t );

    bool solid() const;
    Destruction destructible() const;
    void draw( int x, int y ) const;

    bool is_floor_family() const { return kind != Kind::wall; }
};

class Map
{
public:
    explicit Map( const std::string& fn );
    ~Map();   // defined in map.cpp where the entity types are complete

    Field& at( int x, int y ) { return grid[index( x, y )]; }
    const Field& at( int x, int y ) const { return grid[index( x, y )]; }

    void draw();
    void tick( World& world );

    int getx() const { return X; }
    int gety() const { return Y; }
    int get_crates() const { return destructibles; }

    std::unique_ptr<Player> create_player() const;

    void place_bomb( int x, int y );
    bool monster_collide( int tx, int ty ) const;

private:
    static constexpr int X = 13, Y = 11;

    // Deferred monster respawn timer, mirroring Map.MWait.
    struct MWait
    {
        int type;             // 1, 2 or 3
        std::int64_t time;    // timestamp at which it respawns
    };

    static int index( int x, int y ) { return x * Y + y; }

    void load( const std::string& fn );
    void generate_destructibles();
    void populate_map();
    bool monster_ok( int rx, int ry, int px, int py, int r ) const;

    std::vector<Field> grid;
    int px = -10, py = -10;
    int destructibles = 0;
    int m1 = 0, m2 = 0, m3 = 0;

    std::vector<std::unique_ptr<Bomb>> bombs;
    std::vector<std::unique_ptr<Monster>> monsters;
    std::vector<std::unique_ptr<Vortex>> bonuses;
    std::vector<MWait> mwait;
};

}
