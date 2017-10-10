/*
  Native File Dialog

  Internal, common across platforms

  http://www.frogtoss.com/labs
 */


#ifndef _NFD_COMMON_H
#define _NFD_COMMON_H

#define NFD_MAX_STRLEN 256
#define _NFD_UNUSED(x) ((void)x) 

void *NFDi_Malloc( size_t bytes );
void  NFDi_Free( void *ptr );
void  NFDi_SetError( const char *msg );
void  NFDi_SafeStrncpy( char *dst, const char *src, size_t maxCopy );

#endif
