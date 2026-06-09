#include <array>
#include <stdint.h>
#include <random>

#include "TracyNameGen.hpp"

namespace tracy
{

struct NameBank
{
    const char* const* adjectives;
    const char* const* nouns;
    size_t numAdjectives;
    size_t numNouns;
};

constexpr const char* AnalysisAdjectives[] = { "Granular", "Forensic", "Acute", "Lucid", "Precise", "Deep", "Exact", "Critical", "Analytical", "Transparent", "Subtle", "Sharp", "Rigid", "Focused", "Absolute" };
constexpr const char* AnalysisNouns[] = { "Probe", "Trace", "Lens", "Scope", "Metric", "Insight", "Scan", "Audit", "Point", "Vector", "Signal", "Marker", "Frame", "Detail", "View" };

constexpr const char* PerformanceAdjectives[] = { "Swift", "Lean", "Kinetic", "Agile", "Hyper", "Rapid", "Fluid", "Peak", "Instant", "Nimble", "Optimal", "Sonic", "Linear", "Warp", "Turbo" };
constexpr const char* PerformanceNouns[] = { "Pulse", "Flow", "Cycle", "Burst", "Stream", "Tick", "Glide", "Shift", "Velocity", "Spike", "Pace", "Rhythm", "Drive", "Path", "Edge" };

constexpr const char* CoreAdjectives[] = { "Binary", "Raw", "Atomic", "Static", "Core", "Virtual", "Base", "Solid", "Dense", "Linear", "Primitive", "Native", "Hard", "Direct", "Stable" };
constexpr const char* CoreNouns[] = { "Stack", "Heap", "Node", "Buffer", "Segment", "Thread", "Kernel", "Block", "Page", "Shell", "Layer", "Bit", "Logic", "Port", "Root" };

constexpr const char* ModernAdjectives[] = { "Synthetic", "Neural", "Dynamic", "Async", "Elastic", "Cloud", "Distributed", "Reactive", "Orbital", "Flux", "Poly", "Infinite", "Quantum", "Parallel", "Modular" };
constexpr const char* ModernNouns[] = { "Nexus", "Grid", "Matrix", "Vertex", "Sync", "Prism", "Axiom", "Sphere", "Logic", "Hub", "Mesh", "Bridge", "Link", "Core", "Unit" };

constexpr std::array NameBanks = {
    NameBank { AnalysisAdjectives, AnalysisNouns, sizeof(AnalysisAdjectives) / sizeof(AnalysisAdjectives[0]), sizeof(AnalysisNouns) / sizeof(AnalysisNouns[0]) },
    NameBank { PerformanceAdjectives, PerformanceNouns, sizeof(PerformanceAdjectives) / sizeof(PerformanceAdjectives[0]), sizeof(PerformanceNouns) / sizeof(PerformanceNouns[0]) },
    NameBank { CoreAdjectives, CoreNouns, sizeof(CoreAdjectives) / sizeof(CoreAdjectives[0]), sizeof(CoreNouns) / sizeof(CoreNouns[0]) },
    NameBank { ModernAdjectives, ModernNouns, sizeof(ModernAdjectives) / sizeof(ModernAdjectives[0]), sizeof(ModernNouns) / sizeof(ModernNouns[0]) }
};


std::string GenerateAbstractName()
{
    std::random_device rd;
    std::default_random_engine gen( rd() );
    std::uniform_int_distribution<uint32_t> dist( 0, UINT32_MAX );

    const auto bank = NameBanks[dist( gen ) % NameBanks.size()];
    if( dist( gen ) % 6 != 0 )
    {
        return std::string( bank.adjectives[dist( gen ) % bank.numAdjectives] ) + " " + std::string( bank.nouns[dist( gen ) % bank.numNouns] );
    }

    const auto bank2 = NameBanks[dist( gen ) % NameBanks.size()];
    return std::string( bank.adjectives[dist( gen ) % bank.numAdjectives] ) + " " + std::string( bank2.nouns[dist( gen ) % bank2.numNouns] );
}

}
