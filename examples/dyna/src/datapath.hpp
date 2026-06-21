#pragma once

#include <string>

namespace dyna
{

// Resolve a path relative to the directory containing the executable, so the
// game finds its data files regardless of the current working directory (e.g.
// when launched from the build tree). The data/ tree is copied next to the
// binary at build time; see CMakeLists.txt.
std::string data_path( const std::string& rel );

}
