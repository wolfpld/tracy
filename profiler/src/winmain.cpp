#ifdef _WIN32
#  include <windows.h>
#  include <stdlib.h>

int main( int argc, char** argv );

int WINAPI WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpszCmd, int nCmd )
{
    return main( __argc, __argv );
}
#endif
