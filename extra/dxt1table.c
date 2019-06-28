#include <stdint.h>
#include <stdio.h>

static const uint8_t IndexTable[4] = { 1, 3, 2, 0 };

int convert( int v )
{
    int v0 = v & 0x3;
    int v1 = ( v >> 2 ) & 0x3;
    int v2 = ( v >> 4 ) & 0x3;
    int v3 = ( v >> 6 );

    int t0 = IndexTable[v0];
    int t1 = IndexTable[v1];
    int t2 = IndexTable[v2];
    int t3 = IndexTable[v3];

    return t0 | ( t1 << 2 ) | ( t2 << 4 ) | ( t3 << 6 );
}

int main()
{
    for( int i=0; i<256; i++ )
    {
        if( i % 16 == 15 )
        {
            printf( "%i,\n", convert( i ) );
        }
        else
        {
            printf( "%i,\t", convert( i ) );
        }
    }
    printf( "\n" );
    return 0;
}
