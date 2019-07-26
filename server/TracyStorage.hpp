#ifndef __TRACYSTORAGE_HPP__
#define __TRACYSTORAGE_HPP__

#include <stdint.h>

namespace tracy
{

const char* GetSavePath( const char* file );
const char* GetSavePath( const char* program, uint64_t time, const char* file, bool create );

}

#endif
