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
#include <assert.h>

#include "Atomics.h"
#include <string.h>


namespace enki
{
    // LockLessMultiReadPipe - Single writer, multiple reader thread safe pipe using (semi) lockless programming
    // Readers can only read from the back of the pipe
    // The single writer can write to the front of the pipe, and read from both ends (a writer can be a reader)
    // for many of the principles used here, see http://msdn.microsoft.com/en-us/library/windows/desktop/ee418650(v=vs.85).aspx
    // Note: using log2 sizes so we do not need to clamp (multi-operation)
    // T is the contained type
    // Note this is not true lockless as the use of flags as a form of lock state.
    template<uint8_t cSizeLog2, typename T> class LockLessMultiReadPipe
    {
    public:
        LockLessMultiReadPipe();
        ~LockLessMultiReadPipe() {}

        // ReaderTryReadBack returns false if we were unable to read
        // This is thread safe for both multiple readers and the writer
        bool ReaderTryReadBack(   T* pOut );

        // WriterTryReadFront returns false if we were unable to read
        // This is thread safe for the single writer, but should not be called by readers
        bool WriterTryReadFront(  T* pOut );

        // WriterTryWriteFront returns false if we were unable to write
        // This is thread safe for the single writer, but should not be called by readers
        bool WriterTryWriteFront( const T& in );

        // IsPipeEmpty() is a utility function, not intended for general use
        // Should only be used very prudently.
        bool IsPipeEmpty() const
        {
            return 0 == m_WriteIndex - m_ReadCount;
        }

        void Clear()
        {
            m_WriteIndex = 0;
            m_ReadIndex = 0;
            m_ReadCount = 0;
            memset( (void*)m_Flags, 0, sizeof( m_Flags ) );
        }

    private:
        const static uint32_t           ms_cSize        = ( 1 << cSizeLog2 );
        const static uint32_t           ms_cIndexMask   = ms_cSize - 1;
        const static uint32_t           FLAG_INVALID    = 0xFFFFFFFF; // 32bit for CAS
        const static uint32_t           FLAG_CAN_WRITE  = 0x00000000; // 32bit for CAS
        const static uint32_t           FLAG_CAN_READ   = 0x11111111; // 32bit for CAS

        T                               m_Buffer[ ms_cSize ];

        // read and write indexes allow fast access to the pipe, but actual access
        // controlled by the access flags. 
        volatile uint32_t BASE_ALIGN(4) m_WriteIndex;
        volatile uint32_t BASE_ALIGN(4) m_ReadCount;
        volatile uint32_t               m_Flags[  ms_cSize ];
        volatile uint32_t BASE_ALIGN(4) m_ReadIndex;
    };

    template<uint8_t cSizeLog2, typename T> inline
        LockLessMultiReadPipe<cSizeLog2,T>::LockLessMultiReadPipe()
        : m_WriteIndex(0)
        , m_ReadIndex(0)
        , m_ReadCount(0)
    {
        assert( cSizeLog2 < 32 );
        memset( (void*)m_Flags, 0, sizeof( m_Flags ) );
    }

    template<uint8_t cSizeLog2, typename T> inline
        bool LockLessMultiReadPipe<cSizeLog2,T>::ReaderTryReadBack(   T* pOut )
    {

        uint32_t actualReadIndex;

        uint32_t readCount  = m_ReadCount;

        // We get hold of read index for consistency,
        // and do first pass starting at read count
        uint32_t readIndexToUse  = readCount;


        while(true)
        {

            uint32_t writeIndex = m_WriteIndex;
            // power of two sizes ensures we can use a simple calc without modulus
            uint32_t numInPipe = writeIndex - readCount;
            if( 0 == numInPipe )
            {
                return false;
            }
            if( readIndexToUse >= writeIndex )
            {
                // move back to start
                readIndexToUse = m_ReadIndex;
            }


            // power of two sizes ensures we can perform AND for a modulus
            actualReadIndex    = readIndexToUse & ms_cIndexMask;

            // Multiple potential readers mean we should check if the data is valid,
            // using an atomic compare exchange
            uint32_t previous = AtomicCompareAndSwap( &m_Flags[  actualReadIndex ], FLAG_INVALID, FLAG_CAN_READ );
            if( FLAG_CAN_READ == previous )
            {
                break;
            }
            ++readIndexToUse;

            //update known readcount
            readCount  = m_ReadCount;
        }

        // we update the read index using an atomic add, as we've only read one piece of data.
        // this ensure consistency of the read index, and the above loop ensures readers
        // only read from unread data
        AtomicAdd(  (volatile int32_t*)&m_ReadCount, 1 );

        BASE_MEMORYBARRIER_ACQUIRE();
        // now read data, ensuring we do so after above reads & CAS
        *pOut = m_Buffer[ actualReadIndex ];

        m_Flags[  actualReadIndex ] = FLAG_CAN_WRITE;

        return true;
    }

    template<uint8_t cSizeLog2, typename T> inline
        bool LockLessMultiReadPipe<cSizeLog2,T>::WriterTryReadFront(  T* pOut )
    {
        uint32_t writeIndex = m_WriteIndex;
        uint32_t frontReadIndex  = writeIndex;

        // Multiple potential readers mean we should check if the data is valid,
        // using an atomic compare exchange - which acts as a form of lock (so not quite lockless really).
        uint32_t previous = FLAG_INVALID;
        uint32_t actualReadIndex = 0;
        while( true )
        {
            // power of two sizes ensures we can use a simple calc without modulus
            uint32_t readCount = m_ReadCount;
            uint32_t numInPipe = writeIndex - readCount;
            if( 0 == numInPipe || 0 == frontReadIndex )
            {
                // frontReadIndex can get to 0 here if that item was just being read by another thread.
                m_ReadIndex = readCount;
                return false;
            }
            --frontReadIndex;
            actualReadIndex = frontReadIndex & ms_cIndexMask;
            previous = AtomicCompareAndSwap( &m_Flags[  actualReadIndex ], FLAG_INVALID, FLAG_CAN_READ );
            if( FLAG_CAN_READ == previous )
            {
                break;
            }
            else if( m_ReadIndex >= frontReadIndex  )
            {
                return false;
            }
        }

        // now read data, ensuring we do so after above reads & CAS
        *pOut = m_Buffer[ actualReadIndex ];

        m_Flags[  actualReadIndex ] = FLAG_CAN_WRITE;

        BASE_MEMORYBARRIER_RELEASE();

        // 32-bit aligned stores are atomic, and writer owns the write index
        // we only move one back as this is as many as we have read, not where we have read from.
        --m_WriteIndex;
        return true;
    }


    template<uint8_t cSizeLog2, typename T> inline
        bool LockLessMultiReadPipe<cSizeLog2,T>::WriterTryWriteFront( const T& in )
    {
        // The writer 'owns' the write index, and readers can only reduce
        // the amount of data in the pipe.
        // We get hold of both values for consistency and to reduce false sharing
        // impacting more than one access
        uint32_t writeIndex = m_WriteIndex;


        // power of two sizes ensures we can perform AND for a modulus
        uint32_t actualWriteIndex    = writeIndex & ms_cIndexMask;

        // a reader may still be reading this item, as there are multiple readers
        if( m_Flags[ actualWriteIndex ] != FLAG_CAN_WRITE ) 
        {
            return false; // still being read, so have caught up with tail. 
        }


        // as we are the only writer we can update the data without atomics
        //  whilst the write index has not been updated
        m_Buffer[ actualWriteIndex ] = in;
        m_Flags[  actualWriteIndex ] = FLAG_CAN_READ;

        // We need to ensure the above writes occur prior to updating the write index,
        // otherwise another thread might read before it's finished
        BASE_MEMORYBARRIER_RELEASE();

        // 32-bit aligned stores are atomic, and the writer controls the write index
        ++writeIndex;
        m_WriteIndex = writeIndex;
        return true;
    }

}
