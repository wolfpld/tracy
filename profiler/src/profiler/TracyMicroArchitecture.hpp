#include <stdint.h>

namespace tracy
{

struct AsmDesc
{
    uint8_t type;
    uint16_t width;
};

struct AsmVar
{
    int descNum;
    AsmDesc desc[5];
    int isaSet;
    float tp;
    int port, uops, minlat, maxlat;
    bool minbound, maxbound;
};

struct AsmOp
{
    int id;
    int descId;
    int numVariants;
    const AsmVar*const* variant;
};

struct MicroArchitecture
{
    int numOps;
    const AsmOp*const* ops;
};

extern const char* MicroArchitectureList[];
extern const char* PortList[];
extern const char* OpsList[];
extern const char* OpDescList[];
extern const char* IsaList[];
extern const MicroArchitecture* const MicroArchitectureData[];

extern int OpsNum;
extern int MicroArchitectureNum;

};
