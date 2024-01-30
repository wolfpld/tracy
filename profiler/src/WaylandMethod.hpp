#ifndef __WAYLANDMETHOD_HPP__
#define __WAYLANDMETHOD_HPP__

#include <assert.h>

#define Method( func ) [](void* ptr, auto... args) { assert( ptr ); ((decltype(this))ptr)->func( args... ); }

#endif
