#pragma once

#include <cstdint>

namespace dyna
{

// Frame timing, ported from timer.cs. Timestamps are milliseconds since
// Timer::reset(); kept 64-bit so the modulo arithmetic the animation code
// relies on never overflows during a session.
namespace Timer
{
void reset();
int tick();                  // advances the clock, returns delta in ms
std::int64_t get_timestamp();
extern int delta;            // ms elapsed during the last tick()
}

// Thin wrapper over a single global PRNG, mirroring the C# RNG helper.
namespace RNG
{
int next( int n );             // uniform in [0, n)
}

}
