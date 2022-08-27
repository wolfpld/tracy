#include <stdint.h>
#include <stdio.h>

#include "../server/TracyFileHeader.hpp"
#include "../public/common/TracyVersion.hpp"

int main()
{
    const auto ver = uint32_t( tracy::FileVersion( tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch ) );
    fwrite( &ver, 1, 4, stdout );
}
