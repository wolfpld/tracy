#pragma once


namespace tracy
{

#pragma pack( push, 1 )

struct PdbInfo
{
    uint32_t CvSignature;
    uint8_t Signature[16]; // GUID
    uint32_t Age;
};

struct PEImageDebugData
{
    uint16_t majorVersion;
    uint16_t minorVersion;
    uint32_t exeDataTimeStamp;
    PdbInfo cvInfo;
};

#pragma pack( pop )


}
