#include <stdio.h>
#include <stdlib.h>

int main()
{
    FILE* f = fopen( "rgb.txt", "rb" );

    char buf[1024];
    int off = 0;
    for(;;)
    {
        int sz = fread( buf+off, 1, 1, f );
        if( buf[off] == '\r' || buf[off] == '\n' || sz == 0 )
        {
            if( off == 0 )
            {
                if( sz == 0 ) break;
                continue;
            }
            int ok = 1;
            for( int i=13; i<off; i++ )
            {
                if( buf[i] == ' ' ) ok = 0;
            }
            if( ok == 1 )
            {
                buf[off] = '\0';
                int r, g, b;
                sscanf( buf, "%i %i %i", &r, &g, &b );
                printf( "%s = 0x%02x%02x%02x,\n", buf+13, r, g, b );
            }
            off = 0;
        }
        else
        {
            off++;
        }
        if( sz == 0 ) break;
    }

    fclose( f );
}
