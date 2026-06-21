#pragma once

namespace dyna
{

// Top-level game flow, ported from game.cs. The C# original kept the running
// game's state (player, map, win/lose flags) in static fields; that state now
// lives in a World object owned by the loops below, so nothing leaks out here.
namespace Game
{
void menu_loop();
}

}
