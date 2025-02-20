#pragma once

#include <vector>

#pragma pack( push, 1 )
struct TracyPdbInfo
{
    uint32_t CvSignature;
    uint8_t Signature[16]; // GUID
    uint32_t Age;
};
#pragma pack( pop )

namespace tracy
{



#pragma pack( push, 1 )
struct WindowsDebugData
{
    uint16_t majorVersion;
    uint16_t minorVersion;
    uint32_t exeDataTimeStamp;
    TracyPdbInfo cvInfo;
};
#pragma pack( pop )

enum struct DebugFormat : uint8_t
{
    NoDebugFormat,
    PdbDebugFormat,
    DwarfDebugFormat,
};


}
