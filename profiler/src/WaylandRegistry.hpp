#ifndef __WAYLANDREGISTRY_HPP__
#define __WAYLANDREGISTRY_HPP__

#include <stdio.h>
#include <stdlib.h>
#include <wayland-client.h>

template<typename T>
static inline T* RegistryBindImpl( wl_registry* reg, uint32_t name, const char* interfaceName, const wl_interface* interface, uint32_t version, uint32_t versionMin = 1, uint32_t versionMax = 1 )
{
    if( version < versionMin )
    {
        printf( "Wayland interface %s version %u is too old (minimum required is %u)\n", interfaceName, version, versionMin );
        abort();
    }
    if( version > versionMax ) version = versionMax;
    return (T*)wl_registry_bind( reg, name, interface, version );
}

// Two optional parameters: versionMin and versionMax.
#define RegistryBind( type, ... ) RegistryBindImpl<type>( reg, name, interface, &type ## _interface, version, ##__VA_ARGS__ )

#endif
