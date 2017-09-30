/*
  Native File Dialog

  Internal, common across platforms

  http://www.frogtoss.com/labs
 */


#ifndef _NFD_COMMON_H
#define _NFD_COMMON_H

#include "nfd.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NFD_MAX_STRLEN 256
#define _NFD_UNUSED(x) ((void)x)

#define NFD_UTF8_BOM "\xEF\xBB\xBF"


void  *NFDi_Malloc( size_t bytes );
void   NFDi_Free( void *ptr );
void   NFDi_SetError( const char *msg );
int    NFDi_SafeStrncpy( char *dst, const char *src, size_t maxCopy );
size_t NFDi_UTF8_Strlen( const nfdchar_t *str );
int    NFDi_IsFilterSegmentChar( char ch );
    
#ifdef __cplusplus
}
#endif


#endif
