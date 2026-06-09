#include <algorithm>
#include <array>
#include <assert.h>
#include <stdint.h>
#include <random>
#include <vector>

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

constexpr const char* AnalysisAdjectives[] = {
    "Granular", "Forensic", "Acute", "Lucid", "Precise",
    "Deep", "Exact", "Critical", "Analytical", "Transparent",
    "Subtle", "Sharp", "Rigid", "Focused", "Absolute",
    "Meticulous", "Spectral", "Diagnostic", "Pervasive", "Introspective",
    "Systematic", "Optical", "Minute", "Piercing", "Detailed",
    "Scrutinized", "Clear", "Keen", "Rigorous", "Vast",
    "Incisive", "Exhaustive", "Lateral", "Prismatic", "Observant"
};
constexpr const char* AnalysisNouns[] = {
    "Probe", "Trace", "Lens", "Scope", "Metric",
    "Insight", "Scan", "Audit", "Point", "Vector",
    "Signal", "Marker", "Frame", "Detail", "View",
    "Spectrum", "Snapshot", "Blueprint", "Aperture", "Index",
    "Radar", "Prism", "Gauge", "Focal", "Pattern",
    "Echo", "Signature", "Horizon", "Mirror", "Scale",
    "Telemetry", "Graph", "Stratum", "Artifact", "Aspect"
};

constexpr const char* PerformanceAdjectives[] = {
    "Swift", "Lean", "Kinetic", "Agile", "Hyper",
    "Rapid", "Fluid", "Peak", "Instant", "Nimble",
    "Optimal", "Sonic", "Linear", "Warp", "Turbo",
    "Frictionless", "Seamless", "Electric", "Blazing", "Aerodynamic",
    "Quantum", "Prompt", "Direct", "Streamlined", "Volatile",
    "Highgain", "Rapidfire", "Torrential", "Sleek", "Velocity",
    "Dynamic", "Active", "Persistent", "Lightweight", "Snappy"
};
constexpr const char* PerformanceNouns[] = {
    "Pulse", "Flow", "Cycle", "Burst", "Stream",
    "Tick", "Glide", "Shift", "Velocity", "Spike",
    "Pace", "Rhythm", "Drive", "Path", "Edge",
    "Sprint", "Torrent", "Current", "Surge", "Momentum",
    "Flux", "Wave", "Accelerator", "Spark", "Jet",
    "Thrust", "Orbit", "Apex", "Bolt", "Phase", 
    "Rush", "Impact", "Frequency", "Lapse", "Kick"
};

constexpr const char* CoreAdjectives[] = {
    "Binary", "Raw", "Atomic", "Static", "Core",
    "Virtual", "Base", "Solid", "Dense", "Opaque",
    "Primitive", "Native", "Hard", "Stable", "Immutable",
    "Monolithic", "Bare", "Rigid", "Concrete", "Fundamental",
    "Discrete", "Fixed", "Heavy", "Latent", "Symmetric",
    "Implicit", "Explicit", "Cold", "Basic", "Granite",
    "Stark", "Brute", "Firm", "Stout", "Coarse"
};
constexpr const char* CoreNouns[] = {
    "Stack", "Heap", "Node", "Buffer", "Segment",
    "Thread", "Kernel", "Block", "Page", "Shell",
    "Layer", "Bit", "Logic", "Port", "Root",
    "Register", "Pointer", "Address", "Cache", "Opcode",
    "Slab", "Pipeline", "Bus", "Socket", "Sector",
    "Vault", "Anchor", "Pillar", "Base", "Primitive",
    "Offset", "Handle", "Struct", "Memory", "Word"
};

constexpr const char* ModernAdjectives[] = {
    "Synthetic", "Neural", "Async", "Elastic", "Cloud",
    "Distributed", "Reactive", "Orbital", "Poly", "Infinite",
    "Parallel", "Modular", "Virtualized", "Scalable", "Agnostic",
    "Adaptive", "Hybrid", "Autonomous", "Global", "Synergic",
    "Omnipresent", "Evolving", "Abstract", "Unified", "Concurrent",
    "Remote", "Digital", "Cluster", "Ephemeral", "Stateful",
    "Stateless", "Serverless", "Decoupled", "Fluent", "Native"
};
constexpr const char* ModernNouns[] = {
    "Nexus", "Grid", "Matrix", "Vertex", "Sync",
    "Axiom", "Sphere", "Hub", "Mesh", "Bridge",
    "Link", "Unit", "Fabric", "Cluster", "Portal",
    "Ecosystem", "Catalyst", "Interface", "Domain", "Gateway",
    "Lattice", "Cloud", "Instance", "Schema", "Registry",
    "Tenant", "Namespace", "Pod", "Stream", "Endpoint",
    "Payload", "Relay", "Orchestrator", "Broker", "Agent"
};

constexpr const char* FailureAdjectives[] = {
    "Clumsy", "Wobbly", "Confused", "Chaotic", "Sneaky",
    "Lazy", "Dizzy", "Broken", "Leaky", "Fragile",
    "Shaky", "Erratic", "Sleepy", "Lost", "Random",
    "Glitchy", "Unstable", "Paradoxical", "Cluttery", "Hiccupy",
    "Wonky", "Flaky", "Stubborn", "Moody", "Nervous",
    "Fumbling", "Drifting", "Tangled", "Blurred", "Absent",
    "Haphazard", "Spasmodic", "Clunky", "Jittery", "Bewildered"
};
constexpr const char* FailureNouns[] = {
    "Crash", "Bug", "Leak", "Hang", "Timeout",
    "Panic", "Loop", "Spill", "Hiccup", "Glitch",
    "Wobble", "Tumble", "Void", "Abyss", "Maze",
    "Knot", "Static", "Noise", "Drift", "Stumble",
    "Gap", "Fragment", "Shard", "Spark", "Bubble",
    "Slip", "Trip", "Fall", "Ghost", "Shadow",
    "Blur", "Overflow", "Sinkhole", "Echo", "Mirage"
};

constexpr const char* MythicAdjectives[] = {
    "Mythic", "Arcane", "Ancient", "Eternal", "Sacred",
    "Divine", "Forgotten", "Elder", "Primordial", "Venerable",
    "Runic", "Prophetic", "Colossal", "Imperial", "Regal",
    "Sovereign", "Mystic", "Occult", "Hidden", "Cryptic",
    "Ethereal", "Celestial", "Gnostic", "Hermetic", "Alchemical",
    "Astral", "Golden", "Iron", "Bronze", "Obsidian",
    "Silver", "Timeless", "Boundless", "Omnipotent", "Everlasting"
};
constexpr const char* MythicNouns[] = {
    "Aegis", "Helios", "Oracle", "Titan", "Rune",
    "Lex", "Codex", "Obelisk", "Monolith", "Temple",
    "Altar", "Scepter", "Crown", "Sigil", "Glyph",
    "Tome", "Relic", "Artifact", "Sanctum", "Citadel",
    "Bastion", "Spire", "Pillar", "Throne", "Vault",
    "Key", "Gate", "Bridge", "Seal", "Pact",
    "Covenant", "Legacy", "Epoch", "Era", "Myth"
};

constexpr const char* CosmosAdjectives[] = {
    "Relativistic", "Baryonic", "Intergalactic", "Event-Horizon", "Singular",
    "Celestial", "Nebular", "Void-Born", "Astral", "Luminous",
    "Spectral", "Ionized", "Gravitational", "Ecliptic", "Zenithal",
    "Stellar", "Cosmological", "Parallactic", "Zero-Point", "Dark-Matter",
    "Radiant", "Orbital", "Supernova", "Hyper-Spatial", "Aetheric",
    "Cold-Void", "Infinite", "Dimensional", "Crystalline", "Tidal",
    "Planetary", "Solar", "Lunar", "Galactic", "Oblique"
};
constexpr const char* CosmosNouns[] = {
    "Pulsar", "Quasar", "Singularity", "Void", "Nebula",
    "Horizon", "Apex", "Zenith", "Equinox", "Corona",
    "Aperture", "Axis", "Parallax", "Cluster", "Constellation",
    "Vacuum", "Symmetry", "Continuum", "Flux", "Vortex",
    "Nova", "Eclipse", "Solenoid", "Sphere", "Vector",
    "Siderostat", "Sextant", "Obliquity", "Precession", "Azimuth",
    "Wavelength", "Frequency", "Radiance", "Entropy", "Magnitude"
};

constexpr const char* GameAdjectives[] = {
    "Frame-Locked", "Pixel-Perfect", "Arcade", "Retro", "Hardcore",
    "Unlocked", "Godlike", "Buffed", "Nerfed", "Overclocked",
    "Clutch", "Lagless", "Sweaty", "Tryhard", "Broken",
    "Turbo", "Min-Max", "Rage-Quit", "No-Scope", "Frame-Perfect",
    "Savescum", "Co-Op", "Modded", "Patched", "Hotfixed",
    "Debugged", "Optimized", "Smoothed", "Playtest", "Sandbox",
    "Scripted", "Speedrun", "Cheat-Code", "Invincible", "Flawless"
};
constexpr const char* GameNouns[] = {
    "Frame", "Tick", "Sprite", "Polygon", "Shader",
    "Texture", "Voxel", "Render", "Hitbox", "Hurtbox",
    "Collision", "Input", "Viewport", "Level", "Checkpoint",
    "Boss", "Loot", "Quest", "Spawn", "Respawn",
    "Grind", "Scroll", "Tilemap", "Backdrop", "Rig",
    "Build", "Frag", "Gib", "Drawcall", "Pass",
    "Batch", "Delta", "Pool", "Arena", "Worker"
};

constexpr std::array NameBanks = {
    NameBank { AnalysisAdjectives, AnalysisNouns, sizeof(AnalysisAdjectives) / sizeof(AnalysisAdjectives[0]), sizeof(AnalysisNouns) / sizeof(AnalysisNouns[0]) },
    NameBank { PerformanceAdjectives, PerformanceNouns, sizeof(PerformanceAdjectives) / sizeof(PerformanceAdjectives[0]), sizeof(PerformanceNouns) / sizeof(PerformanceNouns[0]) },
    NameBank { CoreAdjectives, CoreNouns, sizeof(CoreAdjectives) / sizeof(CoreAdjectives[0]), sizeof(CoreNouns) / sizeof(CoreNouns[0]) },
    NameBank { ModernAdjectives, ModernNouns, sizeof(ModernAdjectives) / sizeof(ModernAdjectives[0]), sizeof(ModernNouns) / sizeof(ModernNouns[0]) },
    NameBank { FailureAdjectives, FailureNouns, sizeof(FailureAdjectives) / sizeof(FailureAdjectives[0]), sizeof(FailureNouns) / sizeof(FailureNouns[0]) },
    NameBank { MythicAdjectives, MythicNouns, sizeof(MythicAdjectives) / sizeof(MythicAdjectives[0]), sizeof(MythicNouns) / sizeof(MythicNouns[0]) },
    NameBank { CosmosAdjectives, CosmosNouns, sizeof(CosmosAdjectives) / sizeof(CosmosAdjectives[0]), sizeof(CosmosNouns) / sizeof(CosmosNouns[0]) },
    NameBank { GameAdjectives, GameNouns, sizeof(GameAdjectives) / sizeof(GameAdjectives[0]), sizeof(GameNouns) / sizeof(GameNouns[0]) },
};

constexpr std::array NameStructure = { "an", "aan", "nn" };


std::string GenerateAbstractName()
{
    std::random_device rd;
    std::default_random_engine gen( rd() );
    std::uniform_int_distribution<uint32_t> dist( 0, UINT32_MAX );

    const auto baseBank = NameBanks[dist( gen ) % NameBanks.size()];
    const char* structure = NameStructure[dist( gen ) % NameStructure.size()];

    std::vector<std::string> parts;
    while( *structure )
    {
        const auto type = *structure++;
        assert( type == 'a' || type == 'n' );
        const auto bank = dist( gen ) % 6 == 0 ? NameBanks[dist( gen ) % NameBanks.size()] : baseBank;
        for(;;)
        {
            auto part = std::string( type == 'a' ? bank.adjectives[dist( gen ) % bank.numAdjectives] : bank.nouns[dist( gen ) % bank.numNouns] );
            if( std::ranges::find( parts, part ) == parts.end() )
            {
                parts.emplace_back( std::move( part ) );
                break;
            }
        }
    };

    std::string ret = parts[0];
    for( size_t i=1; i<parts.size(); i++ )
    {
        ret += " " + parts[i];
    }
    return ret;
}

}
