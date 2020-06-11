#include <stdio.h>

int main()
{
    //int a = 16, b = 44, s = 4;
    //int av = 12, bv = 6, cv = 3;

    //int a = 32, b = 48, s = 16;
    //int av = 12, bv = 6, cv = 3;

    int a = 48, b = 64, s = 16;
    int av = 48, bv = 32, cv = 24;

    printf( "int TrTbl[] = { " );
    int first = 1;
    for( int i=0; i<256; i+=s )
    {
        if( first ) first = 0; else printf( ", " );
        if( i < a ) printf( "%i", av );
        else if( i < b ) printf( "%i", bv );
        else printf( "%i", cv );
    }
    printf( " };\n" );
}
