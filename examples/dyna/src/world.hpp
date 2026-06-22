#pragma once

#include <memory>
#include <string>

namespace dyna
{

class Map;
class Player;

// Owns the state for one running level: the map, the player (absent on the
// menu screen), and the flags the gameplay code used to reach through global
// variables. Passing a World& into the tick path replaces the old Game::p /
// Game::current_map / Game::killed globals, so there are no non-owning pointers
// to outlive the objects they point at.
class World
{
public:
    // Loads `level_fn`; spawns a player from the map's '@' marker when
    // with_player is set (gameplay) and leaves it null otherwise (menu).
    World( const std::string& level_fn, bool with_player );
    ~World();

    World( const World& ) = delete;
    World& operator=( const World& ) = delete;

    Map& map() { return *map_; }
    const Map& map() const { return *map_; }
    Player* player() { return player_.get(); }   // null on the menu screen
    const std::string& name() const { return name_; }

    void tick();
    void draw();

    bool killed = false;
    bool next_level = false;
    int crates_left = 0;

private:
    std::unique_ptr<Map> map_;
    std::unique_ptr<Player> player_;
    std::string name_;
};

}
