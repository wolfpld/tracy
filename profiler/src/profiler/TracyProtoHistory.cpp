#include "TracyFileHeader.hpp"
#include "TracyProtoHistory.hpp"

namespace tracy
{

constexpr ProtocolHistory_t ProtocolHistoryArr[] = {
    { 66, FileVersion( 0, 11, 0 ) },
    { 64, FileVersion( 0, 10, 0 ) },
    { 63, FileVersion( 0, 9, 0 ), FileVersion( 0, 9, 1 ) },
    { 57, FileVersion( 0, 8, 2 ) },
    { 56, FileVersion( 0, 8, 1 ) },
    { 55, FileVersion( 0, 8, 0 ) },
    { 46, FileVersion( 0, 7, 6 ), FileVersion( 0, 7, 8 ) },
    { 44, FileVersion( 0, 7, 5 ) },
    { 42, FileVersion( 0, 7, 3 ), FileVersion( 0, 7, 4 ) },
    { 40, FileVersion( 0, 7, 1 ), FileVersion( 0, 7, 2 ) },
    { 35, FileVersion( 0, 7, 0 ) },
    { 25, FileVersion( 0, 6, 2 ), FileVersion( 0, 6, 3 ) },
    { 24, FileVersion( 0, 6, 1 ) },
    { 23, FileVersion( 0, 6, 0 ) },
    { 14, FileVersion( 0, 5, 0 ) },
    { 1, FileVersion( 0, 4, 1 ) },
    {}
};

const ProtocolHistory_t* ProtocolHistory = ProtocolHistoryArr;

}
