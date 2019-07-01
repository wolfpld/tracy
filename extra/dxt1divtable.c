#include <stdint.h>
#include <stdio.h>

int main()
{
    for( int i=0; i<255*3+1; i++ )
    {
        // replace 4 with 2 for ARM NEON table
        uint32_t range = ( 4 << 16 ) / ( 1+i );
        if( range > 0xFFFF ) range = 0xFFFF;
        if( i % 16 == 15 )
        {
            printf( "0x%04x,\n", range );
        }
        else
        {
            printf( "0x%04x, ", range );
        }
    }
    printf( "\n" );
    return 0;
}
