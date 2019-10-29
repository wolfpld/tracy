// Copyright (c) 2013 Doug Binks
// 
// This software is provided 'as-is', without any express or implied
// warranty. In no event will the authors be held liable for any damages
// arising from the use of this software.
// 
// Permission is granted to anyone to use this software for any purpose,
// including commercial applications, and to alter it and redistribute it
// freely, subject to the following restrictions:
// 
// 1. The origin of this software must not be misrepresented; you must not
//    claim that you wrote the original software. If you use this software
//    in a product, an acknowledgement in the product documentation would be
//    appreciated but is not required.
// 2. Altered source versions must be plainly marked as such, and must not be
//    misrepresented as being the original software.
// 3. This notice may not be removed or altered from any source distribution.

#pragma once

#include <stdint.h>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <Windows.h>
	#undef GetObject
    #include <intrin.h>

    extern "C" void _ReadWriteBarrier();
    #pragma intrinsic(_ReadWriteBarrier)
    #pragma intrinsic(_InterlockedCompareExchange)
    #pragma intrinsic(_InterlockedExchangeAdd)

    // Memory Barriers to prevent CPU and Compiler re-ordering
    #define BASE_MEMORYBARRIER_ACQUIRE() _ReadWriteBarrier()
    #define BASE_MEMORYBARRIER_RELEASE() _ReadWriteBarrier()
    #define BASE_ALIGN(x) __declspec( align( x ) ) 

#else
    #define BASE_MEMORYBARRIER_ACQUIRE() __asm__ __volatile__("": : :"memory")  
    #define BASE_MEMORYBARRIER_RELEASE() __asm__ __volatile__("": : :"memory")  
	#define BASE_ALIGN(x)  __attribute__ ((aligned( x )))
#endif

namespace enki
{
    // Atomically performs: if( *pDest == compareWith ) { *pDest = swapTo; }
    // returns old *pDest (so if successfull, returns compareWith)
    inline uint32_t AtomicCompareAndSwap( volatile uint32_t* pDest, uint32_t swapTo, uint32_t compareWith )
    {
       #ifdef _WIN32
			// assumes two's complement - unsigned / signed conversion leads to same bit pattern
            return _InterlockedCompareExchange( (volatile long*)pDest,swapTo, compareWith );
        #else
            return __sync_val_compare_and_swap( pDest, compareWith, swapTo );
        #endif      
    }

    inline uint64_t AtomicCompareAndSwap( volatile uint64_t* pDest, uint64_t swapTo, uint64_t compareWith )
    {
       #ifdef _WIN32
			// assumes two's complement - unsigned / signed conversion leads to same bit pattern
            return _InterlockedCompareExchange64( (__int64 volatile*)pDest, swapTo, compareWith );
        #else
            return __sync_val_compare_and_swap( pDest, compareWith, swapTo );
        #endif      
    }	

    // Atomically performs: tmp = *pDest; *pDest += value; return tmp;
    inline int32_t AtomicAdd( volatile int32_t* pDest, int32_t value )
    {
       #ifdef _WIN32
            return _InterlockedExchangeAdd( (long*)pDest, value );
        #else
            return __sync_fetch_and_add( pDest, value );
        #endif      
    }

}