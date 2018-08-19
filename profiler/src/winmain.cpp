#ifdef _WIN32
#  include <windows.h>
#  include <stdlib.h>
#  include <intrin.h>
#  include <stdint.h>

namespace tracy
{
bool DiscoveryAVX();
bool DiscoveryAVX2();
}

int main( int argc, char** argv );

int WINAPI WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpszCmd, int nCmd )
{
    {
        uint32_t regs[4];
        __cpuidex( (int*)regs, 0, 0 );
        const uint32_t maxLeaf = regs[0];
        bool cpuHasAVX = false;
        bool cpuHasAVX2 = false;
        if( maxLeaf >= 1 )
        {
            __cpuidex( (int*)regs, 1, 0 );
            cpuHasAVX = ( regs[2] & 0x10000000 ) != 0;
        }
        if( maxLeaf >= 7 )
        {
            __cpuidex( (int*)regs, 7, 0 );
            cpuHasAVX2 = ( regs[1] & 0x00000020 ) != 0;
        }

        if( tracy::DiscoveryAVX2() && !cpuHasAVX2 )
        {
            MessageBoxA( nullptr, "This program is compiled with AVX2 instruction set, but your CPU doesn't support it. You must recompile with lower instruction set.\n\nIn Visual Studio go to Project properties -> C/C++ -> Code Generation -> Enable Enhanced Instruction Set and select appropriate value for your CPU.", "Wrong CPU architecture", MB_ICONERROR );
            return 0;
        }
        if( tracy::DiscoveryAVX() && !cpuHasAVX )
        {
            MessageBoxA( nullptr, "This program is compiled with AVX instruction set, but your CPU doesn't support it. You must recompile with lower instruction set.\n\nIn Visual Studio go to Project properties -> C/C++ -> Code Generation -> Enable Enhanced Instruction Set and select appropriate value for your CPU.", "Wrong CPU architecture", MB_ICONERROR );
            return 0;
        }
    }

    return main( __argc, __argv );
}
#endif
