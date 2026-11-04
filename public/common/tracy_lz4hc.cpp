/*
    LZ4 HC - High Compression Mode of LZ4
    Copyright (c) Yann Collet. All rights reserved.

    BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are
    met:

    * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above
    copyright notice, this list of conditions and the following disclaimer
    in the documentation and/or other materials provided with the
    distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
    A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
    OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
    LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
    DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
    THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

    You can contact the author at :
       - LZ4 source repository : https://github.com/lz4/lz4
       - LZ4 public forum : https://groups.google.com/forum/#!forum/lz4c
*/
/* note : lz4hc is not an independent module, it requires lz4.h/lz4.c for proper compilation */


/* *************************************
*  Tuning Parameter
***************************************/

/*! HEAPMODE :
 *  Select how stateless HC compression functions like `LZ4_compress_HC()`
 *  allocate memory for their workspace:
 *  in stack (0:fastest), or in heap (1:default, requires malloc()).
 *  Since workspace is rather large, heap mode is recommended.
**/
#ifndef LZ4HC_HEAPMODE
#  define LZ4HC_HEAPMODE 1
#endif


/*===    Dependency    ===*/
#define LZ4_HC_STATIC_LINKING_ONLY
#include "tracy_lz4hc.hpp"
#include <limits.h>


/*===   Shared lz4.c code   ===*/
#ifndef LZ4_SRC_INCLUDED
# if defined(__GNUC__)
#  pragma GCC diagnostic ignored "-Wunused-function"
# endif
# if defined (__clang__)
#  pragma clang diagnostic ignored "-Wunused-function"
# endif
# define LZ4_COMMONDEFS_ONLY
#include "tracy_lz4.cpp"   /* LZ4_count, constants, mem */
#endif

namespace tracy
{


/*===   Enums   ===*/
typedef enum { noDictCtx, usingDictCtxHc } dictCtx_directive;


/*===   Constants   ===*/
#define OPTIMAL_ML (int)((ML_MASK-1)+MINMATCH)
#define LZ4_OPT_NUM   (1<<12)


/*===   Macros   ===*/
#undef MIN
#define MIN(a,b)   ( (a) < (b) ? (a) : (b) )
#undef MAX
#define MAX(a,b)   ( (a) > (b) ? (a) : (b) )


/*===   Levels definition   ===*/
typedef enum { lz4mid, lz4hc, lz4opt } lz4hc_strat_e;
typedef struct {
    lz4hc_strat_e strat;
    int nbSearches;
    U32 targetLength;
    int nbSearchesSeq;   /* lz4opt with favorDecSpeed only : budget at positions only worth searching to save a sequence */
    int dictCopyMin;     /* attached dictionary : from this input size, its tables (256 KB) are copied rather than referenced (dictCtx),
                          * which compresses as well or better, and pays off sooner at levels which search more */
} cParams_t;
static const cParams_t k_clTable[LZ4HC_CLEVEL_MAX+1] = {
    { lz4mid,    2, 16,  0, 4 KB },  /* 0, unused */
    { lz4mid,    2, 16,  0, 4 KB },  /* 1, unused */
    { lz4mid,    2, 16,  0, 4 KB },  /* 2 */
    { lz4hc,     4, 16,  0, 4 KB },  /* 3 */
    { lz4hc,     8, 16,  0, 4 KB },  /* 4 */
    { lz4hc,    16, 16,  0, 4 KB },  /* 5 */
    { lz4hc,    32, 16,  0, 4 KB },  /* 6 */
    { lz4hc,    64, 16,  0, 4 KB },  /* 7 */
    { lz4hc,   128, 16,  0, 4 KB },  /* 8 */
    { lz4hc,   256, 16,  0, 4 KB },  /* 9 */
    { lz4opt,   96, 64,  1, 4 KB },  /*10==LZ4HC_CLEVEL_OPT_MIN*/
    { lz4opt,  512,128,  2, 2 KB },  /*11 */
    { lz4opt,16384,LZ4_OPT_NUM, 64, 1 KB },  /* 12==LZ4HC_CLEVEL_MAX */
};

static cParams_t LZ4HC_getCLevelParams(int cLevel)
{
    /* note : clevel convention is a bit different from lz4frame,
     * possibly something worth revisiting for consistency */
    if (cLevel < 1)
        cLevel = LZ4HC_CLEVEL_DEFAULT;
    cLevel = MIN(LZ4HC_CLEVEL_MAX, cLevel);
    return k_clTable[cLevel];
}


/*===   Hashing   ===*/
#define LZ4HC_HASHSIZE 4
#define HASH_FUNCTION(i)      (((i) * 2654435761U) >> ((MINMATCH*8)-LZ4HC_HASH_LOG))
static U32 LZ4HC_hashPtr(const void* ptr) { return HASH_FUNCTION(LZ4_read32(ptr)); }

#if defined(LZ4_FORCE_MEMORY_ACCESS) && (LZ4_FORCE_MEMORY_ACCESS==2)
/* lie to the compiler about data alignment; use with caution */
static U64 LZ4_read64(const void* memPtr) { return *(const U64*) memPtr; }

#elif defined(LZ4_FORCE_MEMORY_ACCESS) && (LZ4_FORCE_MEMORY_ACCESS==1)
/* __pack instructions are safer, but compiler specific */
LZ4_PACK(typedef struct { U64 u64; }) LZ4_unalign64;
static U64 LZ4_read64(const void* ptr) { return ((const LZ4_unalign64*)ptr)->u64; }

#else  /* safe and portable access using memcpy() */
static U64 LZ4_read64(const void* memPtr)
{
    U64 val; LZ4_memcpy(&val, memPtr, sizeof(val)); return val;
}

#endif /* LZ4_FORCE_MEMORY_ACCESS */

#define LZ4MID_HASHSIZE 8
#define LZ4MID_HASHLOG (LZ4HC_HASH_LOG-1)
#define LZ4MID_HASHTABLESIZE (1 << LZ4MID_HASHLOG)

static U32 LZ4MID_hash4(U32 v) { return (v * 2654435761U) >> (32-LZ4MID_HASHLOG); }
static U32 LZ4MID_hash4Ptr(const void* ptr) { return LZ4MID_hash4(LZ4_read32(ptr)); }
/* note: hash7 hashes the lower 56-bits.
 * It presumes input was read using little endian.*/
static U32 LZ4MID_hash7(U64 v) { return (U32)(((v  << (64-56)) * 58295818150454627ULL) >> (64-LZ4MID_HASHLOG)) ; }
static U64 LZ4_readLE64(const void* memPtr);
static U32 LZ4MID_hash8Ptr(const void* ptr) { return LZ4MID_hash7(LZ4_readLE64(ptr)); }

static U64 LZ4_readLE64(const void* memPtr)
{
    if (LZ4_isLittleEndian()) {
        return LZ4_read64(memPtr);
    } else {
        const BYTE* p = (const BYTE*)memPtr;
        /* note: relies on the compiler to simplify this expression */
        return (U64)p[0] | ((U64)p[1]<<8) | ((U64)p[2]<<16) | ((U64)p[3]<<24)
            | ((U64)p[4]<<32) | ((U64)p[5]<<40) | ((U64)p[6]<<48) | ((U64)p[7]<<56);
    }
}


/*===   Count match length   ===*/
LZ4_FORCE_INLINE
unsigned LZ4HC_NbCommonBytes32(U32 val)
{
    assert(val != 0);
    if (LZ4_isLittleEndian()) {
#     if defined(_MSC_VER) && (_MSC_VER >= 1400) && !defined(LZ4_FORCE_SW_BITCOUNT)
        unsigned long r;
        _BitScanReverse(&r, val);
        return (unsigned)((31 - r) >> 3);
#     elif (defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 3) || \
                            ((__GNUC__ == 3) && (__GNUC_MINOR__ >= 4))))) && \
                                        !defined(LZ4_FORCE_SW_BITCOUNT)
        return (unsigned)__builtin_clz(val) >> 3;
#     else
        val >>= 8;
        val = ((((val + 0x00FFFF00) | 0x00FFFFFF) + val) |
              (val + 0x00FF0000)) >> 24;
        return (unsigned)val ^ 3;
#     endif
    } else {
#     if defined(_MSC_VER) && (_MSC_VER >= 1400) && !defined(LZ4_FORCE_SW_BITCOUNT)
        unsigned long r;
        _BitScanForward(&r, val);
        return (unsigned)(r >> 3);
#     elif (defined(__clang__) || (defined(__GNUC__) && ((__GNUC__ > 3) || \
                            ((__GNUC__ == 3) && (__GNUC_MINOR__ >= 4))))) && \
                                        !defined(LZ4_FORCE_SW_BITCOUNT)
        return (unsigned)__builtin_ctz(val) >> 3;
#     else
        const U32 m = 0x01010101;
        return (unsigned)((((val - 1) ^ val) & (m - 1)) * m) >> 24;
#     endif
    }
}

/** LZ4HC_countBack() :
 * @return : negative value, nb of common bytes before ip/match */
LZ4_FORCE_INLINE
int LZ4HC_countBack(const BYTE* const ip, const BYTE* const match,
                    const BYTE* const iMin, const BYTE* const mMin)
{
    int back = 0;
    int const min = (int)MAX(iMin - ip, mMin - match);
    assert(min <= 0);
    assert(ip >= iMin); assert((size_t)(ip-iMin) < (1U<<31));
    assert(match >= mMin); assert((size_t)(match - mMin) < (1U<<31));

    while ((back - min) > 3) {
        U32 const v = LZ4_read32(ip + back - 4) ^ LZ4_read32(match + back - 4);
        if (v) {
            return (back - (int)LZ4HC_NbCommonBytes32(v));
        } else back -= 4; /* 4-byte step */
    }
    /* check remainder if any */
    while ( (back > min)
         && (ip[back-1] == match[back-1]) )
            back--;
    return back;
}

/*===   Chain table updates   ===*/
#define DELTANEXTU16(table, pos) table[(U16)(pos)]   /* faster */
/* Make fields passed to, and updated by LZ4HC_encodeSequence explicit */
#define UPDATABLE(ip, op, anchor) &ip, &op, &anchor


/**************************************
*  Init
**************************************/
static void LZ4HC_clearTables (LZ4HC_CCtx_internal* hc4)
{
    MEM_INIT(hc4->hashTable, 0, sizeof(hc4->hashTable));
    MEM_INIT(hc4->chainTable, 0xFF, sizeof(hc4->chainTable));
}

static void LZ4HC_init_internal (LZ4HC_CCtx_internal* hc4, const BYTE* start)
{
    size_t const bufferSize = (size_t)(hc4->end - hc4->prefixStart);
    size_t newStartingOffset = bufferSize + hc4->dictLimit;
    DEBUGLOG(5, "LZ4HC_init_internal");
    assert(newStartingOffset >= bufferSize);  /* check overflow */
    if (newStartingOffset > 1 GB) {
        LZ4HC_clearTables(hc4);
        newStartingOffset = 0;
    }
    newStartingOffset += 64 KB;
    hc4->nextToUpdate = (U32)newStartingOffset;
    hc4->prefixStart = start;
    hc4->end = start;
    hc4->dictStart = start;
    hc4->dictLimit = (U32)newStartingOffset;
    hc4->lowLimit = (U32)newStartingOffset;
}


/**************************************
*  Encode
**************************************/
#if defined(LZ4_DEBUG) && (LZ4_DEBUG >= 2)
# define RAWLOG(...) fprintf(stderr, __VA_ARGS__)
void LZ4HC_hexOut(const void* src, size_t len)
{
    const BYTE* p = (const BYTE*)src;
    size_t n;
    for (n=0; n<len; n++) {
        RAWLOG("%02X ", p[n]);
    }
    RAWLOG(" \n");
}

# define HEX_CMP(_lev, _ptr, _ref, _len) \
    if (LZ4_DEBUG >= _lev) {            \
        RAWLOG("match bytes: ");        \
        LZ4HC_hexOut(_ptr, _len);       \
        RAWLOG("ref bytes: ");          \
        LZ4HC_hexOut(_ref, _len);       \
    }

#else
# define HEX_CMP(l,p,r,_l)
#endif

/* LZ4HC_encodeSequence() :
 * @return : 0 if ok,
 *           1 if buffer issue detected : @ip, @op and @anchor are then unchanged */
LZ4_FORCE_INLINE int LZ4HC_encodeSequence (
    const BYTE** _ip,
    BYTE** _op,
    const BYTE** _anchor,
    int matchLength,
    int offset,
    limitedOutput_directive limit,
    BYTE* oend)
{
#define ip      (*_ip)
#define op      (*_op)
#define anchor  (*_anchor)

    BYTE* const token = op++;

#if defined(LZ4_DEBUG) && (LZ4_DEBUG >= 6)
    static const BYTE* start = NULL;
    static U32 totalCost = 0;
    U32 const pos = (start==NULL) ? 0 : (U32)(anchor - start); /* only works for single segment */
    U32 const ll = (U32)(ip - anchor);
    U32 const llAdd = (ll>=15) ? ((ll-15) / 255) + 1 : 0;
    U32 const mlAdd = (matchLength>=19) ? ((matchLength-19) / 255) + 1 : 0;
    U32 const cost = 1 + llAdd + ll + 2 + mlAdd;
    if (start==NULL) start = anchor;  /* only works for single segment */
    DEBUGLOG(6, "pos:%7u -- literals:%4u, match:%4i, offset:%5i, cost:%4u + %5u",
                pos,
                (U32)(ip - anchor), matchLength, offset,
                cost, totalCost);
# if 1 /* only works on single segment data */
    HEX_CMP(7, ip, ip-offset, matchLength);
# endif
    totalCost += cost;
#endif

    /* Encode Literal length */
    {   size_t litLen = (size_t)(ip - anchor);
        LZ4_STATIC_ASSERT(notLimited == 0);
        /* Check output limit */
        if (limit && ((op + (litLen / 255) + litLen + (2 + 1 + LASTLITERALS)) > oend)) {
            DEBUGLOG(6, "Not enough room to write %i literals (%i bytes remaining)",
                    (int)litLen, (int)(oend - op));
            op = token;
            return 1;
        }
        if (litLen >= RUN_MASK) {
            size_t len = litLen - RUN_MASK;
            *token = (RUN_MASK << ML_BITS);
            for(; len >= 255 ; len -= 255) *op++ = 255;
            *op++ = (BYTE)len;
        } else {
            *token = (BYTE)(litLen << ML_BITS);
        }

        /* Copy Literals */
        LZ4_wildCopy8(op, anchor, op + litLen);
        op += litLen;
    }

    /* Encode Offset */
    assert(offset <= LZ4_DISTANCE_MAX );
    assert(offset > 0);
    LZ4_writeLE16(op, (U16)(offset)); op += 2;

    /* Encode MatchLength */
    assert(matchLength >= MINMATCH);
    {   size_t mlCode = (size_t)matchLength - MINMATCH;
        if (limit && (op + (mlCode / 255) + (1 + LASTLITERALS) > oend)) {
            DEBUGLOG(6, "Not enough room to write match length");
            op = token;
            return 1;
        }
        if (mlCode >= ML_MASK) {
            *token += ML_MASK;
            mlCode -= ML_MASK;
            for(; mlCode >= 510 ; mlCode -= 510) { *op++ = 255; *op++ = 255; }
            if (mlCode >= 255) { mlCode -= 255; *op++ = 255; }
            *op++ = (BYTE)mlCode;
        } else {
            *token += (BYTE)(mlCode);
    }   }

    /* Prepare next loop */
    ip += matchLength;
    anchor = ip;

    return 0;

#undef ip
#undef op
#undef anchor
}

/* LZ4HC_encodeLastLiterals() :
 * Encode the final run of literals, from @anchor to @iend.
 * In fillOutput mode, the run may be truncated, to fit into dst.
 * @oend : same as LZ4HC_encodeSequence() : end of dst, minus LASTLITERALS in fillOutput mode
 * @return : 0 if ok,
 *           1 if dst is too small (limitedOutput) */
static int LZ4HC_encodeLastLiterals (
    const BYTE** _ip,
    BYTE** _op,
    const BYTE** _anchor,
    const BYTE* iend,
    limitedOutput_directive limit,
    BYTE* oend)
{
#define ip      (*_ip)
#define op      (*_op)
#define anchor  (*_anchor)

    BYTE* const dstEnd = (limit == fillOutput) ? oend + LASTLITERALS : oend;
    size_t lastRunSize = (size_t)(iend - anchor);  /* literals */
    size_t llAdd = (lastRunSize + 255 - RUN_MASK) / 255;
    size_t const totalSize = 1 + llAdd + lastRunSize;
    if (limit && (op + totalSize > dstEnd)) {
        if (limit == limitedOutput) return 1;  /* not enough space in dst */
        /* adapt lastRunSize to fill dst */
        lastRunSize  = (size_t)(dstEnd - op) - 1 /*token*/;
        llAdd = (lastRunSize + 256 - RUN_MASK) / 256;
        lastRunSize -= llAdd;
    }
    DEBUGLOG(6, "Final literal run : %i literals", (int)lastRunSize);
    ip = anchor + lastRunSize;  /* can be != iend if limit==fillOutput */

    if (lastRunSize >= RUN_MASK) {
        size_t accumulator = lastRunSize - RUN_MASK;
        *op++ = (RUN_MASK << ML_BITS);
        for(; accumulator >= 255 ; accumulator -= 255) *op++ = 255;
        *op++ = (BYTE) accumulator;
    } else {
        *op++ = (BYTE)(lastRunSize << ML_BITS);
    }
    assert(lastRunSize <= (size_t)(dstEnd - op));
    LZ4_memcpy(op, anchor, lastRunSize);
    op += lastRunSize;
    return 0;

#undef ip
#undef op
#undef anchor
}

/* LZ4HC_encodeLastSequence_fillOutput() :
 * fillOutput mode only : current sequence doesn't fit into dst.
 * Encode it anyway if all its literals fit, shortening its match if need be,
 * but only if it leaves enough room for the final run of literals (MFLIMIT).
 * @op : start of this sequence (before the failed LZ4HC_encodeSequence())
 * @oend : same as LZ4HC_encodeSequence() : end of dst minus LASTLITERALS */
static void LZ4HC_encodeLastSequence_fillOutput (
    const BYTE** _ip,
    BYTE** _op,
    const BYTE** _anchor,
    int matchLength,
    int offset,
    BYTE* oend)
{
#define ip      (*_ip)
#define op      (*_op)
#define anchor  (*_anchor)

    BYTE* const dstEnd = oend + LASTLITERALS;
    size_t const ll = (size_t)(ip - anchor);
    size_t const ll_addbytes = (ll + 240) / 255;
    size_t const ll_totalCost = 1 + ll_addbytes + ll;
    BYTE* const maxLitPos = oend - 3; /* 2 for offset, 1 for token */
    DEBUGLOG(6, "Last sequence is overflowing : %u literals, %u remaining space",
                (unsigned)ll, (unsigned)(oend - op));
    if (op + ll_totalCost <= maxLitPos) {
        /* ll validated; now adjust match length */
        size_t const bytesLeftForMl = (size_t)(maxLitPos - (op+ll_totalCost));
        size_t const maxMlSize = MINMATCH + (ML_MASK-1) + (bytesLeftForMl * 255);
        assert(maxMlSize < INT_MAX); assert(matchLength >= 0);
        if ((size_t)matchLength > maxMlSize) matchLength = (int)maxMlSize;
        if (dstEnd - (op + ll_totalCost + 2) - 1 + matchLength >= MFLIMIT) {
            DEBUGLOG(6, "Let's encode a last sequence (ll=%u, ml=%i)", (unsigned)ll, matchLength);
            LZ4HC_encodeSequence(UPDATABLE(ip, op, anchor), matchLength, offset, notLimited, oend);
    }   }

#undef ip
#undef op
#undef anchor
}


typedef struct {
    int off;
    int len;
    int back;  /* negative value */
} LZ4HC_match_t;

static LZ4HC_match_t LZ4HC_searchExtDict(const BYTE* ip, U32 ipIndex,
        const BYTE* const iLowLimit, const BYTE* const iHighLimit,
        const LZ4HC_CCtx_internal* dictCtx, U32 gDictEndIndex,
        int currentBestML, int nbAttempts)
{
    size_t const lDictEndIndex = (size_t)(dictCtx->end - dictCtx->prefixStart) + dictCtx->dictLimit;
    U32 lDictMatchIndex = dictCtx->hashTable[LZ4HC_hashPtr(ip)];
    U32 matchIndex = lDictMatchIndex + gDictEndIndex - (U32)lDictEndIndex;
    int offset = 0, sBack = 0;
    assert(lDictEndIndex <= 1 GB);
    if (lDictMatchIndex>0)
        DEBUGLOG(7, "lDictEndIndex = %zu, lDictMatchIndex = %u", lDictEndIndex, lDictMatchIndex);
    while (ipIndex - matchIndex <= LZ4_DISTANCE_MAX && nbAttempts--) {
        const BYTE* const matchPtr = dictCtx->prefixStart - dictCtx->dictLimit + lDictMatchIndex;

        if (LZ4_read32(matchPtr) == LZ4_read32(ip)) {
            int mlt;
            int back = 0;
            const BYTE* vLimit = ip + (lDictEndIndex - lDictMatchIndex);
            if (vLimit > iHighLimit) vLimit = iHighLimit;
            mlt = (int)LZ4_count(ip+MINMATCH, matchPtr+MINMATCH, vLimit) + MINMATCH;
            back = (ip > iLowLimit) ? LZ4HC_countBack(ip, matchPtr, iLowLimit, dictCtx->prefixStart) : 0;
            mlt -= back;
            if (mlt > currentBestML) {
                currentBestML = mlt;
                offset = (int)(ipIndex - matchIndex);
                sBack = back;
                DEBUGLOG(7, "found match of length %i within extDictCtx", currentBestML);
        }   }

        {   U32 const nextOffset = DELTANEXTU16(dictCtx->chainTable, lDictMatchIndex);
            lDictMatchIndex -= nextOffset;
            matchIndex -= nextOffset;
    }   }

    {   LZ4HC_match_t md;
        md.len = currentBestML;
        md.off = offset;
        md.back = sBack;
        return md;
    }
}

typedef LZ4HC_match_t (*LZ4MID_searchIntoDict_f)(const BYTE* ip, U32 ipIndex,
        const BYTE* const iHighLimit,
        const LZ4HC_CCtx_internal* dictCtx, U32 gDictEndIndex);

static LZ4HC_match_t LZ4MID_searchHCDict(const BYTE* ip, U32 ipIndex,
        const BYTE* const iHighLimit,
        const LZ4HC_CCtx_internal* dictCtx, U32 gDictEndIndex)
{
    return LZ4HC_searchExtDict(ip,ipIndex,
                            ip, iHighLimit,
                            dictCtx, gDictEndIndex,
                            MINMATCH-1, 2);
}

static LZ4HC_match_t LZ4MID_searchExtDict(const BYTE* ip, U32 ipIndex,
        const BYTE* const iHighLimit,
        const LZ4HC_CCtx_internal* dictCtx, U32 gDictEndIndex)
{
    size_t const lDictEndIndex = (size_t)(dictCtx->end - dictCtx->prefixStart) + dictCtx->dictLimit;
    const U32* const hash4Table = dictCtx->hashTable;
    const U32* const hash8Table = hash4Table + LZ4MID_HASHTABLESIZE;
    DEBUGLOG(7, "LZ4MID_searchExtDict (ipIdx=%u)", ipIndex);

    /* search long match first */
    {   U32 l8DictMatchIndex = hash8Table[LZ4MID_hash8Ptr(ip)];
        U32 m8Index = l8DictMatchIndex + gDictEndIndex - (U32)lDictEndIndex;
        assert(lDictEndIndex <= 1 GB);
        if (ipIndex - m8Index <= LZ4_DISTANCE_MAX) {
            const BYTE* const matchPtr = dictCtx->prefixStart - dictCtx->dictLimit + l8DictMatchIndex;
            const size_t safeLen = MIN(lDictEndIndex - l8DictMatchIndex, (size_t)(iHighLimit - ip));
            int mlt = (int)LZ4_count(ip, matchPtr, ip + safeLen);
            if (mlt >= MINMATCH) {
                LZ4HC_match_t md;
                DEBUGLOG(7, "Found long ExtDict match of len=%u", mlt);
                md.len = mlt;
                md.off = (int)(ipIndex - m8Index);
                md.back = 0;
                return md;
            }
        }
    }

    /* search for short match second */
    {   U32 l4DictMatchIndex = hash4Table[LZ4MID_hash4Ptr(ip)];
        U32 m4Index = l4DictMatchIndex + gDictEndIndex - (U32)lDictEndIndex;
        if (ipIndex - m4Index <= LZ4_DISTANCE_MAX) {
            const BYTE* const matchPtr = dictCtx->prefixStart - dictCtx->dictLimit + l4DictMatchIndex;
            const size_t safeLen = MIN(lDictEndIndex - l4DictMatchIndex, (size_t)(iHighLimit - ip));
            int mlt = (int)LZ4_count(ip, matchPtr, ip + safeLen);
            if (mlt >= MINMATCH) {
                LZ4HC_match_t md;
                DEBUGLOG(7, "Found short ExtDict match of len=%u", mlt);
                md.len = mlt;
                md.off = (int)(ipIndex - m4Index);
                md.back = 0;
                return md;
            }
        }
    }

    /* nothing found */
    {   LZ4HC_match_t const md = {0, 0, 0 };
        return md;
    }
}

/* LZ4HC_dropPositions() :
 * In fillOutput mode, compression can stop at @start, before positions the parser has already referenced.
 * The next block compresses them : it must not find them as matches.
 * Remove their references from the hash table, up to @end (excluded).
 * Costs one pass on these positions, or on the hash table, whichever is shorter. */
static void
LZ4HC_dropPositions(LZ4HC_CCtx_internal* ctx, const BYTE* start, const BYTE* end, lz4hc_strat_e strat)
{
    U32* const hashTable = ctx->hashTable;
    U32 const startIdx = ctx->dictLimit + (U32)(start - ctx->prefixStart);
    if (end - start > LZ4HC_HASHTABLESIZE) {
        int i;
        for (i = 0; i < LZ4HC_HASHTABLESIZE; i++) {
            /* branchless, so that it can be vectorized */
            hashTable[i] = (hashTable[i] >= startIdx) ? 0 : hashTable[i];
        }
    } else {
        U32 idx = startIdx;
        const BYTE* p;
        for (p = start; p < end; p++, idx++) {
            if (strat == lz4mid) {
                U32 const h4 = LZ4MID_hash4Ptr(p);
                U32 const h8 = LZ4MID_HASHTABLESIZE + LZ4MID_hash8Ptr(p);
                if (hashTable[h4] == idx) hashTable[h4] = 0;
                if (hashTable[h8] == idx) hashTable[h8] = 0;
            } else {
                U32 const h = LZ4HC_hashPtr(p);
                if (hashTable[h] == idx) hashTable[h] = 0;
    }   }   }
}

/**************************************
*  Mid Compression (level 2)
**************************************/

LZ4_FORCE_INLINE void
LZ4MID_addPosition(U32* hTable, U32 hValue, U32 index)
{
    hTable[hValue] = index;
}

#define ADDPOS8(_p, _idx) LZ4MID_addPosition(hash8Table, LZ4MID_hash8Ptr(_p), _idx)
#define ADDPOS4(_p, _idx) LZ4MID_addPosition(hash4Table, LZ4MID_hash4Ptr(_p), _idx)

/* Fill hash tables with references into dictionary.
 * The resulting table is only exploitable by LZ4MID (level 2) */
static void
LZ4MID_fillHTable (LZ4HC_CCtx_internal* cctx, const void* dict, size_t size)
{
    U32* const hash4Table = cctx->hashTable;
    U32* const hash8Table = hash4Table + LZ4MID_HASHTABLESIZE;
    const BYTE* const prefixPtr = (const BYTE*)dict;
    U32 const prefixIdx = cctx->dictLimit;
    U32 const target = prefixIdx + (U32)size - LZ4MID_HASHSIZE;
    U32 idx = cctx->nextToUpdate;
    assert(dict == cctx->prefixStart);
    DEBUGLOG(4, "LZ4MID_fillHTable (size:%zu)", size);
    if (size <= LZ4MID_HASHSIZE)
        return;

    for (; idx < target; idx += 3) {
        ADDPOS4(prefixPtr+idx-prefixIdx, idx);
        ADDPOS8(prefixPtr+idx+1-prefixIdx, idx+1);
    }

    idx = (size > 32 KB + LZ4MID_HASHSIZE) ? target - 32 KB : cctx->nextToUpdate;
    for (; idx < target; idx += 1) {
        ADDPOS8(prefixPtr+idx-prefixIdx, idx);
    }

    cctx->nextToUpdate = target;
}

static LZ4MID_searchIntoDict_f select_searchDict_function(const LZ4HC_CCtx_internal* dictCtx)
{
    if (dictCtx == NULL) return NULL;
    if (LZ4HC_getCLevelParams(dictCtx->compressionLevel).strat == lz4mid)
        return LZ4MID_searchExtDict;
    return LZ4MID_searchHCDict;
}

/* Length of the match between @ip and the candidate at index @pos (in prefix or extDict),
 * or 0 if the candidate is out of reach */
LZ4_FORCE_INLINE unsigned
LZ4MID_countMatch(const BYTE* ip, U32 ipIndex, U32 pos, const BYTE* matchlimit,
                  const BYTE* prefixPtr, U32 prefixIdx,
                  const BYTE* dictStart, U32 dictIdx)
{
    if (ipIndex - pos > LZ4_DISTANCE_MAX) return 0;
    if (pos >= prefixIdx) {
        const BYTE* const matchPtr = prefixPtr + (pos - prefixIdx);
        assert(matchPtr < ip);
        return LZ4_count(ip, matchPtr, matchlimit);
    }
    if (pos >= dictIdx) {
        /* extDict : the match stops at the end of the dictionary */
        const BYTE* const matchPtr = dictStart + (pos - dictIdx);
        size_t const safeLen = MIN(prefixIdx - pos, (size_t)(matchlimit - ip));
        return LZ4_count(ip, matchPtr, ip + safeLen);
    }
    return 0;
}

/* preconditions:
 * - *srcSizePtr within [1, LZ4_MAX_INPUT_SIZE]
 * - src is valid
 * - maxOutputSize >= 1
 * - dst is valid
 */
static int LZ4MID_compress (
    LZ4HC_CCtx_internal* const ctx,
    const char* const src,
    char* const dst,
    int* srcSizePtr,
    int const maxOutputSize,
    const limitedOutput_directive limit,
    const dictCtx_directive dict
    )
{
    U32* const hash4Table = ctx->hashTable;
    U32* const hash8Table = hash4Table + LZ4MID_HASHTABLESIZE;
    const BYTE* ip = (const BYTE*)src;
    const BYTE* anchor = ip;
    const BYTE* const iend = ip + *srcSizePtr;
    const BYTE* mflimit;      /* set after the size check : would precede a small input */
    const BYTE* matchlimit;
    const BYTE* ilimit;
    BYTE* op = (BYTE*)dst;
    /* fillOutput : keep room for the final run of literals (LZ4 format restriction) */
    BYTE* const oend = op + maxOutputSize - ((limit == fillOutput) ? LASTLITERALS : 0);

    const BYTE* const prefixPtr = ctx->prefixStart;
    const U32 prefixIdx = ctx->dictLimit;
    U32 ilimitIdx;
    const BYTE* const dictStart = ctx->dictStart;
    const U32 dictIdx = ctx->lowLimit;
    const U32 gDictEndIndex = ctx->lowLimit;
    const LZ4MID_searchIntoDict_f searchIntoDict = (dict == usingDictCtxHc) ? select_searchDict_function(ctx->dictCtx) : NULL;
    const BYTE* refEnd = ip;   /* fillOutput : the hash tables reference positions before MAX(refEnd, ip) */

    DEBUGLOG(5, "LZ4MID_compress (%i bytes)", *srcSizePtr);

    /* preconditions verifications */
    if (dict == usingDictCtxHc) DEBUGLOG(5, "usingDictCtxHc");
    assert(*srcSizePtr > 0);
    assert(*srcSizePtr <= LZ4_MAX_INPUT_SIZE);
    assert(src != NULL);
    assert(maxOutputSize >= 1);
    assert(dst != NULL);

    if (*srcSizePtr < LZ4_minLength)
        goto _lz4mid_last_literals;  /* Input too small, no compression (all literals) */
    mflimit = iend - MFLIMIT;
    matchlimit = (iend - LASTLITERALS);
    ilimit = (iend - LZ4MID_HASHSIZE);
    ilimitIdx = (U32)(ilimit - prefixPtr) + prefixIdx;

    /* main loop */
    while (ip <= mflimit) {
        const U32 ipIndex = (U32)(ip - prefixPtr) + prefixIdx;
        unsigned matchLength;
        unsigned matchDistance;
        /* search long match */
        {   U32 const h8 = LZ4MID_hash8Ptr(ip);
            U32 const pos8 = hash8Table[h8];
            assert(h8 < LZ4MID_HASHTABLESIZE);
            assert(pos8 < ipIndex);
            LZ4MID_addPosition(hash8Table, h8, ipIndex);
            matchLength = LZ4MID_countMatch(ip, ipIndex, pos8, matchlimit, prefixPtr, prefixIdx, dictStart, dictIdx);
            matchDistance = ipIndex - pos8;
        }
        /* search short match */
        if (matchLength < MINMATCH) {
            U32 const h4 = LZ4MID_hash4Ptr(ip);
            U32 const pos4 = hash4Table[h4];
            assert(h4 < LZ4MID_HASHTABLESIZE);
            assert(pos4 < ipIndex);
            LZ4MID_addPosition(hash4Table, h4, ipIndex);
            matchLength = LZ4MID_countMatch(ip, ipIndex, pos4, matchlimit, prefixPtr, prefixIdx, dictStart, dictIdx);
            matchDistance = ipIndex - pos4;
        }
        if (matchLength >= MINMATCH) {
            if ((matchLength < 8) && likely(ip < mflimit)) {
                /* short match : check ip+1 for longer, except ip itself */
                U32 const h8 = LZ4MID_hash8Ptr(ip+1);
                U32 const pos8 = hash8Table[h8];
                unsigned const ml2 = LZ4MID_countMatch(ip+1, ipIndex+1, pos8, matchlimit, prefixPtr, prefixIdx, dictStart, dictIdx);
                if ((ml2 > matchLength) && (pos8 != ipIndex)) {
                    LZ4MID_addPosition(hash8Table, h8, ipIndex+1);
                    ip++;
                    matchLength = ml2;
                    matchDistance = ipIndex + 1 - pos8;
            }   }
            goto _lz4mid_encode_sequence;
        }
        /* no match found in prefix nor extDict : search into the attached dictionary */
        if ( (dict == usingDictCtxHc)
          && (ipIndex - gDictEndIndex < LZ4_DISTANCE_MAX - 8) ) {
            LZ4HC_match_t const dMatch = searchIntoDict(ip, ipIndex,
                    matchlimit,
                    ctx->dictCtx, gDictEndIndex);
            assert(dMatch.back == 0);
            matchLength = (unsigned)dMatch.len;
            matchDistance = (unsigned)dMatch.off;
            if (matchLength >= MINMATCH) goto _lz4mid_encode_sequence;
        }
        /* no match found */
        ip += 1 + ((ip-anchor) >> 9);  /* skip faster over incompressible data */
        continue;

_lz4mid_encode_sequence:
        /* match found at ip : matchLength, matchDistance */
        DEBUGLOG(7, "found match at pos %u (len=%u, distance=%u)",
                    (U32)(ip - prefixPtr) + prefixIdx, matchLength, matchDistance);

        /* catch back */
        while (((ip > anchor) & ((U32)(ip-prefixPtr) > matchDistance)) && (unlikely(ip[-1] == ip[-(int)matchDistance-1]))) {
            ip--;  matchLength++;
        };

        /* fill table with beginning of match
         * note : ip may have moved since ipIndex (longer match at ip+1, catch back) */
        {   U32 const startMatchIdx = (U32)(ip-prefixPtr) + prefixIdx;
            ADDPOS8(ip+1, startMatchIdx+1);
            ADDPOS8(ip+2, startMatchIdx+2);
            ADDPOS4(ip+1, startMatchIdx+1);
        }

        /* encode */
        if (LZ4HC_encodeSequence(UPDATABLE(ip, op, anchor),
                (int)matchLength, (int)matchDistance,
                limit, oend) ) {
            if (limit != fillOutput) return 0;  /* compression failed */
            refEnd = ip + matchLength;
            LZ4HC_encodeLastSequence_fillOutput(UPDATABLE(ip, op, anchor),
                                (int)matchLength, (int)matchDistance, oend);
            break;
        }

        /* fill table with end of match */
        {   U32 endMatchIdx = (U32)(ip-prefixPtr) + prefixIdx;
            U32 pos_m2 = endMatchIdx - 2;
            if (pos_m2 < ilimitIdx) {
                if (likely(ip - prefixPtr > 5)) {
                    ADDPOS8(ip-5, endMatchIdx - 5);
                }
                ADDPOS8(ip-3, endMatchIdx - 3);
                ADDPOS8(ip-2, endMatchIdx - 2);
                ADDPOS4(ip-2, endMatchIdx - 2);
                ADDPOS4(ip-1, endMatchIdx - 1);
            }
        }
    }

_lz4mid_last_literals:
    if (refEnd < ip) refEnd = ip;
    if (LZ4HC_encodeLastLiterals(UPDATABLE(ip, op, anchor), iend, limit, oend))
        return 0;  /* not enough space in @dst */
    if (ip < refEnd)   /* fillOutput : the rest of input is left to the next block (input >= LZ4_minLength) */
        LZ4HC_dropPositions(ctx, ip, MIN(refEnd, iend - LZ4MID_HASHSIZE), lz4mid);

    /* End */
    DEBUGLOG(5, "compressed %i bytes into %i bytes", *srcSizePtr, (int)((char*)op - dst));
    assert(ip >= (const BYTE*)src);
    assert(ip <= iend);
    *srcSizePtr = (int)(ip - (const BYTE*)src);
    assert((char*)op >= dst);
    assert((char*)op - dst <= maxOutputSize);
    assert((char*)op - dst < INT_MAX);
    return (int)((char*)op - dst);
}


/**************************************
*  HC Compression - Search
**************************************/

/* Update chains up to ip (excluded) */
LZ4_FORCE_INLINE void LZ4HC_Insert (LZ4HC_CCtx_internal* hc4, const BYTE* ip)
{
    U16* const chainTable = hc4->chainTable;
    U32* const hashTable  = hc4->hashTable;
    const BYTE* const prefixPtr = hc4->prefixStart;
    U32 const prefixIdx = hc4->dictLimit;
    U32 const target = (U32)(ip - prefixPtr) + prefixIdx;
    U32 idx = hc4->nextToUpdate;
    assert(ip >= prefixPtr);
    assert(target >= prefixIdx);

    while (idx < target) {
        U32 const h = LZ4HC_hashPtr(prefixPtr+idx-prefixIdx);
        size_t delta = idx - hashTable[h];
        if (delta>LZ4_DISTANCE_MAX) delta = LZ4_DISTANCE_MAX;
        DELTANEXTU16(chainTable, idx) = (U16)delta;
        hashTable[h] = idx;
        idx++;
    }

    hc4->nextToUpdate = target;
}

#if defined(_MSC_VER)
#  define LZ4HC_rotl32(x,r) _rotl(x,r)
#else
#  define LZ4HC_rotl32(x,r) ((x << r) | (x >> (32 - r)))
#endif


static U32 LZ4HC_rotatePattern(size_t const rotate, U32 const pattern)
{
    size_t const bitsToRotate = (rotate & (sizeof(pattern) - 1)) << 3;
    if (bitsToRotate == 0) return pattern;
    return LZ4HC_rotl32(pattern, (int)bitsToRotate);
}

/* LZ4HC_countPattern() :
 * pattern32 must be a sample of repetitive pattern of length 1, 2 or 4 (but not 3!) */
static unsigned
LZ4HC_countPattern(const BYTE* ip, const BYTE* const iEnd, U32 const pattern32)
{
    const BYTE* const iStart = ip;
    reg_t const pattern = (sizeof(pattern)==8) ?
        (reg_t)pattern32 + (((reg_t)pattern32) << (sizeof(pattern)*4)) : pattern32;

    while (likely(ip < iEnd-(sizeof(pattern)-1))) {
        reg_t const diff = LZ4_read_ARCH(ip) ^ pattern;
        if (!diff) { ip+=sizeof(pattern); continue; }
        ip += LZ4_NbCommonBytes(diff);
        return (unsigned)(ip - iStart);
    }

    if (LZ4_isLittleEndian()) {
        reg_t patternByte = pattern;
        while ((ip<iEnd) && (*ip == (BYTE)patternByte)) {
            ip++; patternByte >>= 8;
        }
    } else {  /* big endian */
        U32 bitOffset = (sizeof(pattern)*8) - 8;
        while (ip < iEnd) {
            BYTE const byte = (BYTE)(pattern >> bitOffset);
            if (*ip != byte) break;
            ip ++; bitOffset -= 8;
    }   }

    return (unsigned)(ip - iStart);
}

/* LZ4HC_reverseCountPattern() :
 * pattern must be a sample of repetitive pattern of length 1, 2 or 4 (but not 3!)
 * read using natural platform endianness */
static unsigned
LZ4HC_reverseCountPattern(const BYTE* ip, const BYTE* const iLow, U32 pattern)
{
    const BYTE* const iStart = ip;

    while (likely(ip >= iLow+4)) {
        if (LZ4_read32(ip-4) != pattern) break;
        ip -= 4;
    }
    {   const BYTE* bytePtr = (const BYTE*)(&pattern) + 3; /* works for any endianness */
        while (likely(ip>iLow)) {
            if (ip[-1] != *bytePtr) break;
            ip--; bytePtr--;
    }   }
    return (unsigned)(iStart - ip);
}

/* LZ4HC_protectDictEnd() :
 * Checks if the match is in the last 3 bytes of the dictionary, so reading the
 * 4 byte MINMATCH would overflow.
 * @returns true if the match index is okay.
 */
static int LZ4HC_protectDictEnd(U32 const dictLimit, U32 const matchIndex)
{
    return ((U32)((dictLimit - 1) - matchIndex) >= 3);
}

typedef enum { rep_untested, rep_not, rep_confirmed } repeat_state_e;

/* LZ4HC_sparsestChain() :
 * A longer match must also match at every position of the current one (at @matchIndex, @longest bytes).
 * Finds, among these positions, the chain jumping farthest back (sampled, with acceleration).
 * @return : distance to the next candidate of that chain (1 if none is better),
 *           *matchChainPosPtr is set to its position within the match, if better */
LZ4_FORCE_INLINE U32
LZ4HC_sparsestChain(const U16* chainTable, U32 matchIndex, int longest, U32* matchChainPosPtr)
{
    int const kTrigger = 4;
    U32 distanceToNextMatch = 1;
    int const end = longest - MINMATCH + 1;
    int step = 1;
    int accel = 1 << kTrigger;
    int pos;
    for (pos = 0; pos < end; pos += step) {
        U32 const candidateDist = DELTANEXTU16(chainTable, matchIndex + (U32)pos);
        step = (accel++ >> kTrigger);
        if (candidateDist > distanceToNextMatch) {
            distanceToNextMatch = candidateDist;
            *matchChainPosPtr = (U32)pos;
            accel = 1 << kTrigger;
    }   }
    return distanceToNextMatch;
}

/* LZ4HC_patternSegment() :
 * Measures the run of @pattern (a repeated byte, or 2 alternating bytes) around @candidateIdx,
 * across the external dictionary / prefix boundary, without going below @lowestMatchIndex.
 * @return : 0 if @pattern isn't present at @candidateIdx,
 *           1 otherwise, with *forwardPtr bytes from @candidateIdx (included) and *backPtr bytes before it */
LZ4_FORCE_INLINE int
LZ4HC_patternSegment(const LZ4HC_CCtx_internal* hc4, U32 candidateIdx, U32 pattern,
                     const BYTE* iHighLimit, U32 lowestMatchIndex,
                     size_t* forwardPtr, size_t* backPtr)
{
    const BYTE* const prefixPtr = hc4->prefixStart;
    U32 const prefixIdx = hc4->dictLimit;
    const BYTE* const dictStart = hc4->dictStart;
    U32 const dictIdx = hc4->lowLimit;
    const BYTE* const dictEnd = dictStart + prefixIdx - dictIdx;
    int const extDict = candidateIdx < prefixIdx;
    const BYTE* const matchPtr = extDict ? dictStart + (candidateIdx - dictIdx) : prefixPtr + (candidateIdx - prefixIdx);
    size_t forward, back;
    if (LZ4_read32(matchPtr) != pattern) return 0;

    {   const BYTE* const iLimit = extDict ? dictEnd : iHighLimit;
        forward = LZ4HC_countPattern(matchPtr+sizeof(pattern), iLimit, pattern) + sizeof(pattern);
        if (extDict && matchPtr + forward == iLimit) {   /* continues into the prefix */
            U32 const rotatedPattern = LZ4HC_rotatePattern(forward, pattern);
            forward += LZ4HC_countPattern(prefixPtr, iHighLimit, rotatedPattern);
    }   }

    back = LZ4HC_reverseCountPattern(matchPtr, extDict ? dictStart : prefixPtr, pattern);
    if (!extDict && matchPtr - back == prefixPtr && dictIdx < prefixIdx) {   /* continues into the external dictionary */
        U32 const rotatedPattern = LZ4HC_rotatePattern((U32)(-(int)back), pattern);
        back += LZ4HC_reverseCountPattern(dictEnd, dictStart, rotatedPattern);
    }
    /* don't go below lowestMatchIndex */
    back = candidateIdx - MAX(candidateIdx - (U32)back, lowestMatchIndex);
    assert(candidateIdx - back >= lowestMatchIndex);

    *forwardPtr = forward;
    *backPtr = back;
    return 1;
}
typedef enum { favorCompressionRatio=0, favorDecompressionSpeed } HCfavor_e;


LZ4_FORCE_INLINE LZ4HC_match_t
LZ4HC_InsertAndGetWiderMatch (
        LZ4HC_CCtx_internal* const hc4,
        const BYTE* const ip,
        const BYTE* const iLowLimit, const BYTE* const iHighLimit,
        int longest,
        const int maxNbAttempts,
        const int patternAnalysis, const int chainSwap,
        const dictCtx_directive dict,
        const HCfavor_e favorDecSpeed)
{
    U16* const chainTable = hc4->chainTable;
    U32* const hashTable = hc4->hashTable;
    const LZ4HC_CCtx_internal* const dictCtx = hc4->dictCtx;
    const BYTE* const prefixPtr = hc4->prefixStart;
    const U32 prefixIdx = hc4->dictLimit;
    const U32 ipIndex = (U32)(ip - prefixPtr) + prefixIdx;
    const int withinStartDistance = (hc4->lowLimit + (LZ4_DISTANCE_MAX + 1) > ipIndex);
    const U32 lowestMatchIndex = (withinStartDistance) ? hc4->lowLimit : ipIndex - LZ4_DISTANCE_MAX;
    const BYTE* const dictStart = hc4->dictStart;
    const U32 dictIdx = hc4->lowLimit;
    int const lookBackLength = (int)(ip-iLowLimit);
    int const maxLength = (int)(iHighLimit-iLowLimit);   /* no match can be longer */
    int nbAttempts = maxNbAttempts;
    U32 matchChainPos = 0;
    U32 const pattern = LZ4_read32(ip);
    U32 matchIndex;
    repeat_state_e repeat = rep_untested;
    size_t srcPatternLength = 0;
    int offset = 0, sBack = 0;

    DEBUGLOG(7, "LZ4HC_InsertAndGetWiderMatch");
    /* First Match */
    LZ4HC_Insert(hc4, ip);  /* insert all prior positions up to ip (excluded) */
    matchIndex = hashTable[LZ4HC_hashPtr(ip)];
    DEBUGLOG(7, "First candidate match for pos %u found at index %u / %u (lowestMatchIndex)",
                ipIndex, matchIndex, lowestMatchIndex);

    /* Candidates only replace the current match if strictly longer,
     * so stopping once @longest reaches @maxLength doesn't change the result. */
    while ((matchIndex>=lowestMatchIndex) && (nbAttempts>0) && (longest<maxLength)) {
        int matchLength=0;
        nbAttempts--;
        assert(matchIndex < ipIndex);
        if (favorDecSpeed && (ipIndex - matchIndex < 8)) {
            /* do nothing:
             * favorDecSpeed intentionally skips matches with offset < 8 */
        } else if (matchIndex >= prefixIdx) {   /* within current Prefix */
            const BYTE* const matchPtr = prefixPtr + (matchIndex - prefixIdx);
            assert(matchPtr < ip);
            assert(longest >= 1);
            if (LZ4_read16(iLowLimit + longest - 1) == LZ4_read16(matchPtr - lookBackLength + longest - 1)) {
                if (LZ4_read32(matchPtr) == pattern) {
                    int const back = lookBackLength ? LZ4HC_countBack(ip, matchPtr, iLowLimit, prefixPtr) : 0;
                    matchLength = MINMATCH + (int)LZ4_count(ip+MINMATCH, matchPtr+MINMATCH, iHighLimit);
                    matchLength -= back;
                    if (matchLength > longest) {
                        longest = matchLength;
                        offset = (int)(ipIndex - matchIndex);
                        sBack = back;
                        DEBUGLOG(7, "Found match of len=%i within prefix, offset=%i, back=%i", longest, offset, -back);
                        HEX_CMP(7, ip + back, ip + back - offset, (size_t)matchLength);
            }   }   }
        } else {   /* lowestMatchIndex <= matchIndex < dictLimit : within Ext Dict */
            const BYTE* const matchPtr = dictStart + (matchIndex - dictIdx);
            assert(matchIndex >= dictIdx);
            if ( likely(matchIndex <= prefixIdx - 4)
              && (LZ4_read32(matchPtr) == pattern) ) {
                int back = 0;
                const BYTE* vLimit = ip + (prefixIdx - matchIndex);
                if (vLimit > iHighLimit) vLimit = iHighLimit;
                matchLength = (int)LZ4_count(ip+MINMATCH, matchPtr+MINMATCH, vLimit) + MINMATCH;
                if ((ip+matchLength == vLimit) && (vLimit < iHighLimit))
                    matchLength += LZ4_count(ip+matchLength, prefixPtr, iHighLimit);
                back = lookBackLength ? LZ4HC_countBack(ip, matchPtr, iLowLimit, dictStart) : 0;
                matchLength -= back;
                if (matchLength > longest) {
                    longest = matchLength;
                    offset = (int)(ipIndex - matchIndex);
                    sBack = back;
                    DEBUGLOG(7, "Found match of len=%i within dict, offset=%i, back=%i", longest, offset, -back);
                    HEX_CMP(7, ip + back, matchPtr + back, (size_t)matchLength);
        }   }   }

        if (chainSwap && matchLength==longest && matchIndex + (U32)longest <= ipIndex) {   /* better match => select a better chain */
            U32 const distanceToNextMatch = LZ4HC_sparsestChain(chainTable, matchIndex, longest, &matchChainPos);
            assert(lookBackLength==0);   /* search forward only */
            if (distanceToNextMatch > 1) {
                if (distanceToNextMatch > matchIndex) break;   /* avoid overflow */
                matchIndex -= distanceToNextMatch;
                continue;
        }   }

        {   U32 const distNextMatch = DELTANEXTU16(chainTable, matchIndex);
            if (patternAnalysis && distNextMatch==1 && matchChainPos==0) {
                U32 const matchCandidateIdx = matchIndex-1;
                size_t forwardPatternLength, backLength;
                /* may be a repeated pattern */
                if (repeat == rep_untested) {
                    if ( ((pattern & 0xFFFF) == (pattern >> 16))
                      &  ((pattern & 0xFF)   == (pattern >> 24)) ) {
                        DEBUGLOG(7, "Repeat pattern detected, char %02X", pattern >> 24);
                        repeat = rep_confirmed;
                        srcPatternLength = LZ4HC_countPattern(ip+sizeof(pattern), iHighLimit, pattern) + sizeof(pattern);
                    } else {
                        repeat = rep_not;
                }   }
                if ( (repeat == rep_confirmed) && (matchCandidateIdx >= lowestMatchIndex)
                  && LZ4HC_protectDictEnd(prefixIdx, matchCandidateIdx)
                  && LZ4HC_patternSegment(hc4, matchCandidateIdx, pattern, iHighLimit, lowestMatchIndex,
                                          &forwardPatternLength, &backLength) ) {
                    size_t const currentSegmentLength = backLength + forwardPatternLength;
                    /* if the full source pattern fits (and hasn't been reached yet), jump to its best position :
                     * at the end of the segment, it might be followed by more match.
                     * Otherwise, jump to the farthest position in the segment : the longest match, plus maybe some back */
                    int const fullPatternFits = (currentSegmentLength >= srcPatternLength)
                                             && (forwardPatternLength <= srcPatternLength);
                    U32 const newMatchIndex = fullPatternFits ?
                                              matchCandidateIdx + (U32)forwardPatternLength - (U32)srcPatternLength :
                                              matchCandidateIdx - (U32)backLength;
                    if (!LZ4HC_protectDictEnd(prefixIdx, newMatchIndex)) {
                        /* Can only happen if started in the prefix */
                        assert(newMatchIndex >= prefixIdx - 3 && newMatchIndex < prefixIdx && matchCandidateIdx >= prefixIdx);
                        matchIndex = prefixIdx;
                        continue;
                    }
                    matchIndex = newMatchIndex;
                    if (!fullPatternFits && lookBackLength==0) {  /* no back possible : the match length is known */
                        size_t const maxML = MIN(currentSegmentLength, srcPatternLength);
                        if ((size_t)longest < maxML) {
                            assert(prefixPtr - prefixIdx + matchIndex != ip);
                            if ((size_t)(ip - prefixPtr) + prefixIdx - matchIndex > LZ4_DISTANCE_MAX) break;
                            assert(maxML < 2 GB);
                            longest = (int)maxML;
                            offset = (int)(ipIndex - matchIndex);
                            assert(sBack == 0);
                            DEBUGLOG(7, "Found repeat pattern match of len=%i, offset=%i", longest, offset);
                        }
                        {   U32 const distToNextPattern = DELTANEXTU16(chainTable, matchIndex);
                            if (distToNextPattern > matchIndex) break;  /* avoid overflow */
                            matchIndex -= distToNextPattern;
                    }   }
                    continue;
                }
        }   }   /* PA optimization */

        /* follow current chain */
        matchIndex -= DELTANEXTU16(chainTable, matchIndex + matchChainPos);

    }  /* while ((matchIndex>=lowestMatchIndex) && (nbAttempts)) */

    if ( dict == usingDictCtxHc
      && nbAttempts > 0
      && longest < maxLength
      && withinStartDistance) {
        size_t const dictEndOffset = (size_t)(dictCtx->end - dictCtx->prefixStart) + dictCtx->dictLimit;
        U32 dictMatchIndex = dictCtx->hashTable[LZ4HC_hashPtr(ip)];
        assert(dictEndOffset <= 1 GB);
        matchIndex = dictMatchIndex + lowestMatchIndex - (U32)dictEndOffset;
        if (dictMatchIndex>0) DEBUGLOG(7, "dictEndOffset = %zu, dictMatchIndex = %u => relative matchIndex = %i", dictEndOffset, dictMatchIndex, (int)dictMatchIndex - (int)dictEndOffset);
        while (ipIndex - matchIndex <= LZ4_DISTANCE_MAX && longest < maxLength && nbAttempts--) {
            const BYTE* const matchPtr = dictCtx->prefixStart - dictCtx->dictLimit + dictMatchIndex;

            if (LZ4_read32(matchPtr) == pattern) {
                int mlt;
                int back = 0;
                const BYTE* vLimit = ip + (dictEndOffset - dictMatchIndex);
                if (vLimit > iHighLimit) vLimit = iHighLimit;
                mlt = (int)LZ4_count(ip+MINMATCH, matchPtr+MINMATCH, vLimit) + MINMATCH;
                back = lookBackLength ? LZ4HC_countBack(ip, matchPtr, iLowLimit, dictCtx->prefixStart) : 0;
                mlt -= back;
                if (mlt > longest) {
                    longest = mlt;
                    offset = (int)(ipIndex - matchIndex);
                    sBack = back;
                    DEBUGLOG(7, "found match of length %i within extDictCtx", longest);
            }   }

            {   U32 const nextOffset = DELTANEXTU16(dictCtx->chainTable, dictMatchIndex);
                dictMatchIndex -= nextOffset;
                matchIndex -= nextOffset;
    }   }   }

    {   LZ4HC_match_t md;
        assert(longest >= 0);
        md.len = longest;
        md.off = offset;
        md.back = sBack;
        return md;
    }
}

LZ4_FORCE_INLINE LZ4HC_match_t
LZ4HC_InsertAndFindBestMatch(LZ4HC_CCtx_internal* const hc4,   /* Index table will be updated */
                       const BYTE* const ip, const BYTE* const iLimit,
                       const int maxNbAttempts,
                       const int patternAnalysis,
                       const dictCtx_directive dict)
{
    DEBUGLOG(7, "LZ4HC_InsertAndFindBestMatch");
    /* note : LZ4HC_InsertAndGetWiderMatch() is able to modify the starting position of a match (*startpos),
     * but this won't be the case here, as we define iLowLimit==ip,
     * so LZ4HC_InsertAndGetWiderMatch() won't be allowed to search past ip */
    return LZ4HC_InsertAndGetWiderMatch(hc4, ip, ip, iLimit, MINMATCH-1, maxNbAttempts, patternAnalysis, 0 /*chainSwap*/, dict, favorCompressionRatio);
}


/* preconditions:
 * - *srcSizePtr within [1, LZ4_MAX_INPUT_SIZE]
 * - src is valid
 * - maxOutputSize >= 1
 * - dst is valid
 */
LZ4_FORCE_INLINE int LZ4HC_compress_hashChain (
    LZ4HC_CCtx_internal* const ctx,
    const char* const src,
    char* const dst,
    int* srcSizePtr,
    int const maxOutputSize,
    int maxNbAttempts,
    const limitedOutput_directive limit,
    const dictCtx_directive dict
    )
{
    const int inputSize = *srcSizePtr;
    const int patternAnalysis = (maxNbAttempts > 128);   /* levels 9+ */

    const BYTE* ip = (const BYTE*)src;
    const BYTE* anchor = ip;
    const BYTE* const iend = ip + inputSize;
    const BYTE* mflimit;      /* set after the size check : would precede a small input */
    const BYTE* matchlimit;

    BYTE* op = (BYTE*) dst;
    /* fillOutput : keep room for the final run of literals (LZ4 format restriction) */
    BYTE* const oend = op + maxOutputSize - ((limit == fillOutput) ? LASTLITERALS : 0);

    const BYTE* start0;
    const BYTE* start2 = NULL;
    const BYTE* start3 = NULL;
    LZ4HC_match_t m0, m1, m2, m3;
    const LZ4HC_match_t nomatch = {0, 0, 0};

    /* init */
    DEBUGLOG(5, "LZ4HC_compress_hashChain (dict?=>%i)", dict);

    /* preconditions verifications */
    assert(*srcSizePtr >= 1);
    assert(src != NULL);
    assert(maxOutputSize >= 1);
    assert(dst != NULL);

    *srcSizePtr = 0;
    if (inputSize < LZ4_minLength) goto _last_literals;             /* Input too small, no compression (all literals) */
    mflimit = iend - MFLIMIT;
    matchlimit = (iend - LASTLITERALS);

    /* Main Loop */
    while (ip <= mflimit) {
        m1 = LZ4HC_InsertAndFindBestMatch(ctx, ip, matchlimit, maxNbAttempts, patternAnalysis, dict);
        if (m1.len<MINMATCH) { ip++; continue; }

        /* saved, in case we would skip too much */
        start0 = ip; m0 = m1;

_Search2:
        /* m1 (at ip) is the next match to encode, m0 (at start0 <= ip) its fallback.
         * Search a longer match m2, starting before the end of m1. */
        DEBUGLOG(7, "_Search2 (currently found match of size %i)", m1.len);
        if (ip+m1.len <= mflimit) {
            start2 = ip + m1.len - 2;
            m2 = LZ4HC_InsertAndGetWiderMatch(ctx,
                            start2, ip + 0, matchlimit, m1.len,
                            maxNbAttempts, patternAnalysis, 0, dict, favorCompressionRatio);
            start2 += m2.back;
        } else {
            m2 = nomatch;  /* do not search further */
        }

        if (m2.len <= m1.len) { /* No better match => encode m1 immediately */
            if (LZ4HC_encodeSequence(UPDATABLE(ip, op, anchor),
                    m1.len, m1.off,
                    limit, oend) )
                goto _dest_overflow;
            continue;
        }

        if ((start0 < ip) && (start2 < ip + m0.len)) {
            /* m1 was skipped at least once, and m2 starts early enough : restore m0 */
            ip = start0; m1 = m0;
        }

        if ((start2 - ip) < 3) {  /* m1 too short before m2 : removed */
            ip = start2;
            m1 = m2;
            goto _Search2;
        }

        /* m2 (at start2) is the candidate after m1.
         * Search a longer match m3, starting before the end of m2. */
        while (1) {
            /* m1 will be cut where m2 starts, but keeps up to OPTIMAL_ML bytes (no extra length byte) :
             * m2 is shifted after them, as long as it keeps at least MINMATCH bytes. */
            if ((start2 - ip) < OPTIMAL_ML) {
                int const gap = (int)(start2 - ip);
                int newML = MIN(m1.len, OPTIMAL_ML);
                if (newML > gap + m2.len - MINMATCH)
                    newML = gap + m2.len - MINMATCH;
                if (newML > gap) {   /* shift m2 */
                    start2 += newML - gap;
                    m2.len -= newML - gap;
                }
            }

            if (start2 + m2.len <= mflimit) {
                start3 = start2 + m2.len - 3;
                m3 = LZ4HC_InsertAndGetWiderMatch(ctx,
                                start3, start2, matchlimit, m2.len,
                                maxNbAttempts, patternAnalysis, 0, dict, favorCompressionRatio);
                start3 += m3.back;
            } else {
                m3 = nomatch;  /* do not search further */
            }

            if ((m3.len > m2.len) && (start3 < ip+m1.len+3)) {  /* not enough room for m2 between m1 and m3 */
                if (start3 >= (ip+m1.len)) {
                    /* m3 starts after m1 : encode m1, then m3 becomes m1,
                     * and m2, moved after m1 if needed (replaced by m3 if too short), becomes the fallback m0 */
                    if (start2 < ip+m1.len) {
                        int correction = (int)(ip+m1.len - start2);
                        start2 += correction;
                        m2.len -= correction;
                        if (m2.len < MINMATCH) {
                            start2 = start3;
                            m2 = m3;
                        }
                    }

                    if (LZ4HC_encodeSequence(UPDATABLE(ip, op, anchor),
                            m1.len, m1.off,
                            limit, oend) )
                        goto _dest_overflow;
                    ip  = start3;
                    m1 = m3;

                    start0 = start2;
                    m0 = m2;
                    goto _Search2;
                }

                /* m3 starts within m1 : m3 replaces m2 */
                start2 = start3;
                m2 = m3;
                continue;
            }

            /* encode m1, cut where m2 starts */
            if (start2 < ip+m1.len) m1.len = (int)(start2 - ip);
            if (LZ4HC_encodeSequence(UPDATABLE(ip, op, anchor),
                    m1.len, m1.off,
                    limit, oend) )
                goto _dest_overflow;

            /* m2 becomes m1 */
            ip = start2; m1 = m2;

            if (m3.len <= m1.len) {  /* No better match => encode m1 (former m2) */
                if (LZ4HC_encodeSequence(UPDATABLE(ip, op, anchor),
                        m1.len, m1.off,
                        limit, oend) )
                    goto _dest_overflow;
                break;
            }

            /* m3 becomes m2 */
            start2 = start3; m2 = m3;
        }
    }

_last_literals:
    if (LZ4HC_encodeLastLiterals(UPDATABLE(ip, op, anchor), iend, limit, oend))
        return 0;  /* not enough space in @dst */

    /* End */
    *srcSizePtr = (int) (((const char*)ip) - src);
    return (int) (((char*)op)-dst);

_dest_overflow:
    if (limit != fillOutput) return 0;  /* compression failed */
    LZ4HC_encodeLastSequence_fillOutput(UPDATABLE(ip, op, anchor), m1.len, m1.off, oend);
    goto _last_literals;
}


static int LZ4HC_compress_optimal( LZ4HC_CCtx_internal* ctx,
    const char* const source, char* dst,
    int* srcSizePtr, int dstCapacity,
    int const nbSearches, int const nbSearchesSeq, int const targetLength,
    const limitedOutput_directive limit,
    const dictCtx_directive dict,
    const HCfavor_e favorDecSpeed);

static int
LZ4HC_compress_generic_internal (
            LZ4HC_CCtx_internal* const ctx,
            const char* const src,
            char* const dst,
            int* const srcSizePtr,
            int const dstCapacity,
            int cLevel,
            const limitedOutput_directive limit,
            const dictCtx_directive dict
            )
{
    DEBUGLOG(5, "LZ4HC_compress_generic_internal(src=%p, srcSize=%d, dstCapacity=%d)",
                src, *srcSizePtr, dstCapacity);

    /* input sanitization */
    if ((U32)*srcSizePtr > (U32)LZ4_MAX_INPUT_SIZE) return 0;  /* Unsupported input size (too large or negative) */
    if (dstCapacity < 1) return 0;   /* Invalid: impossible to store anything */
    assert(dst); /* since dstCapacity >= 1, dst must be valid */
    if (*srcSizePtr == 0) { *dst = 0; return 1; }
    assert(src != NULL); /* since *srcSizePtr >= 1, src must be valid */

    ctx->end += *srcSizePtr;
    {   cParams_t const cParam = LZ4HC_getCLevelParams(cLevel);
        HCfavor_e const favor = ctx->favorDecSpeed ? favorDecompressionSpeed : favorCompressionRatio;
        int const srcSize = *srcSizePtr;
        int result;

        if (cParam.strat == lz4mid) {
            result = LZ4MID_compress(ctx,
                                src, dst, srcSizePtr, dstCapacity,
                                limit, dict);
        } else if (cParam.strat == lz4hc) {
            result = LZ4HC_compress_hashChain(ctx,
                                src, dst, srcSizePtr, dstCapacity,
                                cParam.nbSearches, limit, dict);
        } else {
            assert(cParam.strat == lz4opt);
            result = LZ4HC_compress_optimal(ctx,
                                src, dst, srcSizePtr, dstCapacity,
                                cParam.nbSearches, cParam.nbSearchesSeq, (int)cParam.targetLength, limit,
                                dict, favor);
        }
        if ((limit == fillOutput) && (result > 0) && (*srcSizePtr < srcSize)) {
            /* fillOutput : compression stopped before the end of input.
             * The rest of input is left to the next block : it isn't history yet,
             * and the positions already inserted into it are dropped (lz4mid drops its own).
             * Note : a failed compression is different : lz4frame stores its block uncompressed,
             * and the next block still references it. */
            const BYTE* const consumedEnd = (const BYTE*)src + *srcSizePtr;
            U32 const consumedIdx = ctx->dictLimit + (U32)(consumedEnd - ctx->prefixStart);
            if ((cParam.strat != lz4mid) && (ctx->nextToUpdate > consumedIdx)) {
                LZ4HC_dropPositions(ctx, consumedEnd, consumedEnd + (ctx->nextToUpdate - consumedIdx), cParam.strat);
                ctx->nextToUpdate = consumedIdx;
            }
            ctx->end = consumedEnd;
        }
        return result;
    }
}

static void LZ4HC_setExternalDict(LZ4HC_CCtx_internal* ctxPtr, const BYTE* newBlock);

static int
LZ4HC_compress_generic_noDictCtx (
        LZ4HC_CCtx_internal* const ctx,
        const char* const src,
        char* const dst,
        int* const srcSizePtr,
        int const dstCapacity,
        int cLevel,
        limitedOutput_directive limit
        )
{
    assert(ctx->dictCtx == NULL);
    return LZ4HC_compress_generic_internal(ctx, src, dst, srcSizePtr, dstCapacity, cLevel, limit, noDictCtx);
}

static int isStateCompatible(const LZ4HC_CCtx_internal* ctx1, const LZ4HC_CCtx_internal* ctx2)
{
    int const isMid1 = LZ4HC_getCLevelParams(ctx1->compressionLevel).strat == lz4mid;
    int const isMid2 = LZ4HC_getCLevelParams(ctx2->compressionLevel).strat == lz4mid;
    return !(isMid1 ^ isMid2);
}

static int
LZ4HC_compress_generic_dictCtx (
        LZ4HC_CCtx_internal* const ctx,
        const char* const src,
        char* const dst,
        int* const srcSizePtr,
        int const dstCapacity,
        int cLevel,
        limitedOutput_directive limit
        )
{
    const size_t position = (size_t)(ctx->end - ctx->prefixStart) + (ctx->dictLimit - ctx->lowLimit);
    assert(ctx->dictCtx != NULL);
    if (position >= 64 KB) {
        ctx->dictCtx = NULL;
        return LZ4HC_compress_generic_noDictCtx(ctx, src, dst, srcSizePtr, dstCapacity, cLevel, limit);
    } else if (position == 0 && *srcSizePtr >= LZ4HC_getCLevelParams(cLevel).dictCopyMin && isStateCompatible(ctx, ctx->dictCtx)) {
        /* parameters and extension belong to the working context, not to the dictionary */
        LZ4_i8 const favorDecSpeed = ctx->favorDecSpeed;
        LZ4_i8 const hasWorkspace = ctx->hasWorkspace;
        LZ4_memcpy(ctx, ctx->dictCtx, sizeof(LZ4HC_CCtx_internal));
        LZ4HC_setExternalDict(ctx, (const BYTE *)src);
        ctx->compressionLevel = (short)cLevel;
        ctx->favorDecSpeed = favorDecSpeed;
        ctx->hasWorkspace = hasWorkspace;
        return LZ4HC_compress_generic_noDictCtx(ctx, src, dst, srcSizePtr, dstCapacity, cLevel, limit);
    } else {
        return LZ4HC_compress_generic_internal(ctx, src, dst, srcSizePtr, dstCapacity, cLevel, limit, usingDictCtxHc);
    }
}

static int
LZ4HC_compress_generic (
        LZ4HC_CCtx_internal* const ctx,
        const char* const src,
        char* const dst,
        int* const srcSizePtr,
        int const dstCapacity,
        int cLevel,
        limitedOutput_directive limit
        )
{
    if (ctx->dictCtx == NULL) {
        return LZ4HC_compress_generic_noDictCtx(ctx, src, dst, srcSizePtr, dstCapacity, cLevel, limit);
    } else {
        return LZ4HC_compress_generic_dictCtx(ctx, src, dst, srcSizePtr, dstCapacity, cLevel, limit);
    }
}


int LZ4_sizeofStateHC(void) { return (int)sizeof(LZ4_streamHC_t); }

static size_t LZ4_streamHC_t_alignment(void)
{
#if LZ4_ALIGN_TEST
    typedef struct { char c; LZ4_streamHC_t t; } t_a;
    return sizeof(t_a) - sizeof(LZ4_streamHC_t);
#else
    return 1;  /* effectively disabled */
#endif
}

/* state is presumed correctly initialized,
 * in which case its size and alignment have already been validate */
int LZ4_compress_HC_extStateHC_fastReset (void* state, const char* src, char* dst, int srcSize, int dstCapacity, int compressionLevel)
{
    LZ4HC_CCtx_internal* const ctx = &((LZ4_streamHC_t*)state)->internal_donotuse;
    if (!LZ4_isAligned(state, LZ4_streamHC_t_alignment())) return 0;
    LZ4_resetStreamHC_fast((LZ4_streamHC_t*)state, compressionLevel);
    LZ4HC_init_internal (ctx, (const BYTE*)src);
    if (dstCapacity < LZ4_compressBound(srcSize))
        return LZ4HC_compress_generic (ctx, src, dst, &srcSize, dstCapacity, compressionLevel, limitedOutput);
    else
        return LZ4HC_compress_generic (ctx, src, dst, &srcSize, dstCapacity, compressionLevel, notLimited);
}

int LZ4_compress_HC_extStateHC (void* state, const char* src, char* dst, int srcSize, int dstCapacity, int compressionLevel)
{
    LZ4_streamHC_t* const ctx = LZ4_initStreamHC(state, sizeof(*ctx));
    if (ctx==NULL) return 0;   /* init failure */
    return LZ4_compress_HC_extStateHC_fastReset(state, src, dst, srcSize, dstCapacity, compressionLevel);
}

int LZ4_compress_HC(const char* src, char* dst, int srcSize, int dstCapacity, int compressionLevel)
{
    int cSize;
    DEBUGLOG(5, "LZ4_compress_HC")
#if defined(LZ4HC_HEAPMODE) && LZ4HC_HEAPMODE==1
    {   /* extended state : a single allocation, including the temporary buffer of levels >= 10 */
        LZ4_streamHC_t* const statePtr = LZ4_initStreamHC(ALLOC(LZ4_STREAMHC_EXTSIZE), LZ4_STREAMHC_EXTSIZE);
        if (statePtr==NULL) return 0;
        cSize = LZ4_compress_HC_extStateHC_fastReset(statePtr, src, dst, srcSize, dstCapacity, compressionLevel);
        FREEMEM(statePtr);
    }
#else
    {   LZ4_streamHC_t state;
        cSize = LZ4_compress_HC_extStateHC(&state, src, dst, srcSize, dstCapacity, compressionLevel);
    }
#endif
    return cSize;
}

/* state is presumed sized correctly (>= sizeof(LZ4_streamHC_t)) */
int LZ4_compress_HC_destSize(void* state, const char* source, char* dest, int* sourceSizePtr, int targetDestSize, int cLevel)
{
    LZ4_streamHC_t* const ctx = LZ4_initStreamHC(state, sizeof(*ctx));
    if (ctx==NULL) return 0;   /* init failure */
    LZ4HC_init_internal(&ctx->internal_donotuse, (const BYTE*) source);
    LZ4_setCompressionLevel(ctx, cLevel);
    return LZ4HC_compress_generic(&ctx->internal_donotuse, source, dest, sourceSizePtr, targetDestSize, cLevel, fillOutput);
}



/**************************************
*  Streaming Functions
**************************************/
/* allocation */
#if !defined(LZ4_STATIC_LINKING_ONLY_DISABLE_MEMORY_ALLOCATION)
LZ4_streamHC_t* LZ4_createStreamHC(void)
{
    LZ4_streamHC_t* const state =
        (LZ4_streamHC_t*)ALLOC_AND_ZERO(LZ4_STREAMHC_EXTSIZE);   /* zeroed : initialized */
    if (state == NULL) return NULL;
    state->internal_donotuse.hasWorkspace = 1;
    LZ4_setCompressionLevel(state, LZ4HC_CLEVEL_DEFAULT);
    return state;
}

int LZ4_freeStreamHC (LZ4_streamHC_t* LZ4_streamHCPtr)
{
    DEBUGLOG(4, "LZ4_freeStreamHC(%p)", LZ4_streamHCPtr);
    if (!LZ4_streamHCPtr) return 0;  /* support free on NULL */
    FREEMEM(LZ4_streamHCPtr);
    return 0;
}
#endif


LZ4_streamHC_t* LZ4_initStreamHC (void* buffer, size_t size)
{
    LZ4_streamHC_t* const LZ4_streamHCPtr = (LZ4_streamHC_t*)buffer;
    DEBUGLOG(4, "LZ4_initStreamHC(%p, %u)", buffer, (unsigned)size);
    /* check conditions */
    if (buffer == NULL) return NULL;
    if (size < sizeof(LZ4_streamHC_t)) return NULL;
    if (!LZ4_isAligned(buffer, LZ4_streamHC_t_alignment())) return NULL;
    /* init */
    { LZ4HC_CCtx_internal* const hcstate = &(LZ4_streamHCPtr->internal_donotuse);
      MEM_INIT(hcstate, 0, sizeof(*hcstate));
      hcstate->hasWorkspace = (size >= LZ4_STREAMHC_EXTSIZE); }
    LZ4_setCompressionLevel(LZ4_streamHCPtr, LZ4HC_CLEVEL_DEFAULT);
    return LZ4_streamHCPtr;
}

/* size of an initialized state, to initialize it again : extended states are followed by their buffer */
static size_t LZ4HC_sizeofState(const LZ4_streamHC_t* s)
{
    return s->internal_donotuse.hasWorkspace ? LZ4_STREAMHC_EXTSIZE : sizeof(*s);
}

/* just a stub */
void LZ4_resetStreamHC (LZ4_streamHC_t* LZ4_streamHCPtr, int compressionLevel)
{
    LZ4_initStreamHC(LZ4_streamHCPtr, LZ4HC_sizeofState(LZ4_streamHCPtr));
    LZ4_setCompressionLevel(LZ4_streamHCPtr, compressionLevel);
}

void LZ4_resetStreamHC_fast (LZ4_streamHC_t* LZ4_streamHCPtr, int compressionLevel)
{
    LZ4HC_CCtx_internal* const s = &LZ4_streamHCPtr->internal_donotuse;
    DEBUGLOG(5, "LZ4_resetStreamHC_fast(%p, %d)", LZ4_streamHCPtr, compressionLevel);
    /* also after a failed compression : its positions are below @end, hence out of reach of the next stream */
    assert(s->end >= s->prefixStart);
    s->dictLimit += (U32)(s->end - s->prefixStart);
    s->prefixStart = NULL;
    s->end = NULL;
    s->dictCtx = NULL;
    LZ4_setCompressionLevel(LZ4_streamHCPtr, compressionLevel);
}

void LZ4_setCompressionLevel(LZ4_streamHC_t* LZ4_streamHCPtr, int compressionLevel)
{
    DEBUGLOG(5, "LZ4_setCompressionLevel(%p, %d)", LZ4_streamHCPtr, compressionLevel);
    if (compressionLevel < 1) compressionLevel = LZ4HC_CLEVEL_DEFAULT;
    if (compressionLevel > LZ4HC_CLEVEL_MAX) compressionLevel = LZ4HC_CLEVEL_MAX;
    LZ4_streamHCPtr->internal_donotuse.compressionLevel = (short)compressionLevel;
}

void LZ4_favorDecompressionSpeed(LZ4_streamHC_t* LZ4_streamHCPtr, int favor)
{
    LZ4_streamHCPtr->internal_donotuse.favorDecSpeed = (favor!=0);
}

/* LZ4_loadDictHC() :
 * LZ4_streamHCPtr is presumed properly initialized */
int LZ4_loadDictHC (LZ4_streamHC_t* LZ4_streamHCPtr,
              const char* dictionary, int dictSize)
{
    LZ4HC_CCtx_internal* const ctxPtr = &LZ4_streamHCPtr->internal_donotuse;
    cParams_t cp;
    DEBUGLOG(4, "LZ4_loadDictHC(ctx:%p, dict:%p, dictSize:%d, clevel=%d)", LZ4_streamHCPtr, dictionary, dictSize, ctxPtr->compressionLevel);
    assert(LZ4_streamHCPtr != NULL);
    if (dictSize < 0) dictSize = 0;   /* invalid size : no dictionary */
    if (dictSize > 64 KB) {
        dictionary += (size_t)dictSize - 64 KB;
        dictSize = 64 KB;
    }
    /* need a full initialization, there are bad side-effects when using resetFast(),
     * but preserve parameters */
    {   int const cLevel = ctxPtr->compressionLevel;
        LZ4_i8 const favorDecSpeed = ctxPtr->favorDecSpeed;
        LZ4_initStreamHC(LZ4_streamHCPtr, LZ4HC_sizeofState(LZ4_streamHCPtr));
        LZ4_setCompressionLevel(LZ4_streamHCPtr, cLevel);
        ctxPtr->favorDecSpeed = favorDecSpeed;
        cp = LZ4HC_getCLevelParams(cLevel);
    }
    LZ4HC_init_internal (ctxPtr, (const BYTE*)dictionary);
    ctxPtr->end = (const BYTE*)dictionary + dictSize;
    if (cp.strat == lz4mid) {
        LZ4MID_fillHTable (ctxPtr, dictionary, (size_t)dictSize);
    } else {
        if (dictSize >= LZ4HC_HASHSIZE) LZ4HC_Insert (ctxPtr, ctxPtr->end-3);
    }
    return dictSize;
}

void LZ4_attach_HC_dictionary(LZ4_streamHC_t *working_stream, const LZ4_streamHC_t *dictionary_stream) {
    working_stream->internal_donotuse.dictCtx = dictionary_stream != NULL ? &(dictionary_stream->internal_donotuse) : NULL;
}

/* compression */

static void LZ4HC_setExternalDict(LZ4HC_CCtx_internal* ctxPtr, const BYTE* newBlock)
{
    DEBUGLOG(4, "LZ4HC_setExternalDict(%p, %p)", ctxPtr, newBlock);
    if (LZ4HC_getCLevelParams(ctxPtr->compressionLevel).strat != lz4mid) {
        U32 const endIdx = ctxPtr->dictLimit + (U32)(ctxPtr->end - ctxPtr->prefixStart);
        U32 idx;
        if (ctxPtr->end >= ctxPtr->prefixStart + 4)
            LZ4HC_Insert (ctxPtr, ctxPtr->end-3);  /* Referencing remaining dictionary content */
        /* last positions can't be inserted : don't leave stale chains from previous history */
        for (idx = ctxPtr->nextToUpdate; idx < endIdx; idx++)
            DELTANEXTU16(ctxPtr->chainTable, idx) = 0;
    }

    /* Only one memory segment for extDict, so any previous extDict is lost at this stage */
    ctxPtr->lowLimit  = ctxPtr->dictLimit;
    ctxPtr->dictStart  = ctxPtr->prefixStart;
    ctxPtr->dictLimit += (U32)(ctxPtr->end - ctxPtr->prefixStart);
    ctxPtr->prefixStart = newBlock;
    ctxPtr->end  = newBlock;
    ctxPtr->nextToUpdate = ctxPtr->dictLimit;   /* match referencing will resume from there */

    /* cannot reference an extDict and a dictCtx at the same time */
    ctxPtr->dictCtx = NULL;
}

static int
LZ4_compressHC_continue_generic (LZ4_streamHC_t* LZ4_streamHCPtr,
                                 const char* src, char* dst,
                                 int* srcSizePtr, int dstCapacity,
                                 limitedOutput_directive limit)
{
    LZ4HC_CCtx_internal* const ctxPtr = &LZ4_streamHCPtr->internal_donotuse;
    DEBUGLOG(5, "LZ4_compressHC_continue_generic(ctx=%p, src=%p, srcSize=%d, limit=%d)",
                LZ4_streamHCPtr, src, *srcSizePtr, limit);
    assert(ctxPtr != NULL);
    /* auto-init if forgotten */
    if (ctxPtr->prefixStart == NULL)
        LZ4HC_init_internal (ctxPtr, (const BYTE*) src);

    /* Check overflow */
    if ((size_t)(ctxPtr->end - ctxPtr->prefixStart) + ctxPtr->dictLimit > 2 GB) {
        size_t dictSize = (size_t)(ctxPtr->end - ctxPtr->prefixStart);
        if (dictSize > 64 KB) dictSize = 64 KB;
        LZ4_loadDictHC(LZ4_streamHCPtr, (const char*)(ctxPtr->end) - dictSize, (int)dictSize);
    }

    /* Check if blocks follow each other */
    if ((const BYTE*)src != ctxPtr->end)
        LZ4HC_setExternalDict(ctxPtr, (const BYTE*)src);

    /* Check overlapping input/dictionary space */
    {   const BYTE* sourceEnd = (const BYTE*) src + *srcSizePtr;
        const BYTE* const dictBegin = ctxPtr->dictStart;
        const BYTE* const dictEnd   = ctxPtr->dictStart + (ctxPtr->dictLimit - ctxPtr->lowLimit);
        if ((sourceEnd > dictBegin) && ((const BYTE*)src < dictEnd)) {
            if (sourceEnd > dictEnd) sourceEnd = dictEnd;
            ctxPtr->lowLimit += (U32)(sourceEnd - ctxPtr->dictStart);
            ctxPtr->dictStart += (U32)(sourceEnd - ctxPtr->dictStart);
            /* invalidate dictionary is it's too small */
            if (ctxPtr->dictLimit - ctxPtr->lowLimit < LZ4HC_HASHSIZE) {
                ctxPtr->lowLimit = ctxPtr->dictLimit;
                ctxPtr->dictStart = ctxPtr->prefixStart;
    }   }   }

    return LZ4HC_compress_generic (ctxPtr, src, dst, srcSizePtr, dstCapacity, ctxPtr->compressionLevel, limit);
}

int LZ4_compress_HC_continue (LZ4_streamHC_t* LZ4_streamHCPtr, const char* src, char* dst, int srcSize, int dstCapacity)
{
    DEBUGLOG(5, "LZ4_compress_HC_continue");
    if (dstCapacity < LZ4_compressBound(srcSize))
        return LZ4_compressHC_continue_generic (LZ4_streamHCPtr, src, dst, &srcSize, dstCapacity, limitedOutput);
    else
        return LZ4_compressHC_continue_generic (LZ4_streamHCPtr, src, dst, &srcSize, dstCapacity, notLimited);
}

int LZ4_compress_HC_continue_destSize (LZ4_streamHC_t* LZ4_streamHCPtr, const char* src, char* dst, int* srcSizePtr, int targetDestSize)
{
    return LZ4_compressHC_continue_generic(LZ4_streamHCPtr, src, dst, srcSizePtr, targetDestSize, fillOutput);
}


/* LZ4_saveDictHC :
 * save history content
 * into a user-provided buffer
 * which is then used to continue compression
 */
int LZ4_saveDictHC (LZ4_streamHC_t* LZ4_streamHCPtr, char* safeBuffer, int dictSize)
{
    LZ4HC_CCtx_internal* const streamPtr = &LZ4_streamHCPtr->internal_donotuse;
    int const prefixSize = (int)(streamPtr->end - streamPtr->prefixStart);
    DEBUGLOG(5, "LZ4_saveDictHC(%p, %p, %d)", LZ4_streamHCPtr, safeBuffer, dictSize);
    /* nothing compressed yet (new or reset stream) : nothing to save,
     * the stream remains to be initialized by next compression (attached dictionary included) */
    if (streamPtr->prefixStart == NULL) return 0;
    assert(prefixSize >= 0);
    if (dictSize > 64 KB) dictSize = 64 KB;
    if (dictSize < 4) dictSize = 0;
    if (dictSize > prefixSize) dictSize = prefixSize;
    if (safeBuffer == NULL) assert(dictSize == 0); /* a NULL buffer with !0 size is invalid */
    if (dictSize > 0)
        LZ4_memmove(safeBuffer, streamPtr->end - dictSize, (size_t)dictSize);
    {   U32 const endIndex = (U32)(streamPtr->end - streamPtr->prefixStart) + streamPtr->dictLimit;
        streamPtr->end = (safeBuffer == NULL) ? NULL : (const BYTE*)safeBuffer + dictSize;
        streamPtr->prefixStart = (const BYTE*)safeBuffer;
        streamPtr->dictLimit = endIndex - (U32)dictSize;
        streamPtr->lowLimit = endIndex - (U32)dictSize;
        streamPtr->dictStart = streamPtr->prefixStart;
        if (streamPtr->nextToUpdate < streamPtr->dictLimit)
            streamPtr->nextToUpdate = streamPtr->dictLimit;
    }
    return dictSize;
}


/* ================================================
 *  LZ4 Optimal parser (levels [LZ4HC_CLEVEL_OPT_MIN - LZ4HC_CLEVEL_MAX])
 * ===============================================*/
typedef struct {
    int price;
    int off;
    int mlen;   /* 1 means literal */
    int litlen;
} LZ4HC_optimal_t;

#define TRAILING_LITERALS 3

/* Prices are in 1/LZ4HC_PRICE_SCALE byte,
 * leaving room for a price per sequence, lower than a byte. */
#define LZ4HC_PRICE_SCALE 4

/* favorDecSpeed : each sequence costs decoding time, so it also costs LZ4HC_SEQ_PRICE_FDS.
 * Removing a sequence almost always costs at least one byte,
 * so this price, lower than a byte, mostly acts as a tie-breaker :
 * among solutions of the same size, the one with fewer sequences is preferred.
 * They are found at positions only worth searching to save a sequence,
 * which are searched if at most LZ4HC_SEQ_SEARCH_DIST before the end of the furthest match. */
#define LZ4HC_SEQ_PRICE_FDS    1
#define LZ4HC_SEQ_SEARCH_DIST  4

LZ4_FORCE_INLINE int LZ4HC_literalsPrice(int const litlen)
{
    int price = litlen;
    assert(litlen >= 0);
    if (litlen >= (int)RUN_MASK)
        price += 1 + ((litlen-(int)RUN_MASK) / 255);
    return price * LZ4HC_PRICE_SCALE;
}

/* requires mlen >= MINMATCH */
LZ4_FORCE_INLINE int LZ4HC_sequencePrice(int litlen, int mlen)
{
    int price = 1 + 2 ; /* token + 16-bit offset */
    assert(litlen >= 0);
    assert(mlen >= MINMATCH);

    if (mlen >= (int)(ML_MASK+MINMATCH))
        price += 1 + ((mlen-(int)(ML_MASK+MINMATCH)) / 255);

    return price * LZ4HC_PRICE_SCALE + LZ4HC_literalsPrice(litlen);
}

/* LZ4HC_pricedLitlen() :
 * All solutions of a window start with the same run of @llen literals,
 * so only price differences matter, and they depend on @llen
 * only through its position relative to the 255-steps of the literal length field.
 * Reduce it accordingly : scaled prices of long runs would overflow. */
LZ4_FORCE_INLINE int LZ4HC_pricedLitlen(int const llen)
{
    int const reduceFrom = (int)RUN_MASK + 255;
    assert(llen >= 0);
    if (llen < reduceFrom) return llen;
    return reduceFrom + ((llen - (int)RUN_MASK) % 255);
}

LZ4_FORCE_INLINE LZ4HC_match_t
LZ4HC_FindLongestMatch(LZ4HC_CCtx_internal* const ctx,
                       const BYTE* ip, const BYTE* const iHighLimit,
                       int nbSearches,
                       const dictCtx_directive dict,
                       const HCfavor_e favorDecSpeed)
{
    LZ4HC_match_t const match0 = { 0 , 0, 0 };
    /* note : LZ4HC_InsertAndGetWiderMatch() can extend a match backward (md.back < 0),
     * but not here, since iLowLimit == ip */
    LZ4HC_match_t md = LZ4HC_InsertAndGetWiderMatch(ctx, ip, ip, iHighLimit, MINMATCH-1, nbSearches, 1 /*patternAnalysis*/, 1 /*chainSwap*/, dict, favorDecSpeed);
    assert(md.back == 0);
    if (md.len < MINMATCH) return match0;
    if (favorDecSpeed) {
        if ((md.len>18) & (md.len<=36)) md.len=18;   /* favor dec.speed (shortcut) */
    }
    return md;
}

LZ4_FORCE_INLINE void
LZ4HC_setLiteral(LZ4HC_optimal_t* opt, int pos, int litlen, int price)
{
    opt[pos].mlen = 1;
    opt[pos].off = 0;
    opt[pos].litlen = litlen;
    opt[pos].price = price;
    DEBUGLOG(7, "rPos:%3i => price:%3i (litlen=%i)", pos, price, litlen);
}

LZ4_FORCE_INLINE void
LZ4HC_setMatch(LZ4HC_optimal_t* opt, int pos, int mlen, int off, int price)
{
    opt[pos].mlen = mlen;
    opt[pos].off = off;
    opt[pos].litlen = 0;
    opt[pos].price = price;
    DEBUGLOG(7, "rPos:%3i => price:%3i (matchlen=%i)", pos, price, mlen);
}

/* price at the start of the literal run ending at @pos
 * (0 if this run started before position 0, i.e. it includes literals since anchor) */
LZ4_FORCE_INLINE int LZ4HC_runStartPrice(const LZ4HC_optimal_t* opt, int pos)
{
    int const ll = opt[pos].litlen;
    return (ll <= pos) ? opt[pos - ll].price : 0;
}

/* LZ4HC_addMatch() :
 * Update prices of positions reachable from @cur using @match.
 * Positions beyond @lastPos + TRAILING_LITERALS are not reached yet.
 * @return : updated @lastPos (end of the furthest match) */
LZ4_FORCE_INLINE int
LZ4HC_addMatch(LZ4HC_optimal_t* opt, int cur, LZ4HC_match_t match,
               int lastPos, const HCfavor_e favorDecSpeed)
{
    int const ll = opt[cur].litlen;
    int const basePrice = LZ4HC_runStartPrice(opt, cur) + (favorDecSpeed ? LZ4HC_SEQ_PRICE_FDS : 0);
    int ml;
    assert(cur + match.len < LZ4_OPT_NUM);
    assert((U32)favorDecSpeed <= 1);
    for (ml = MINMATCH; ml <= match.len; ml++) {
        int const pos = cur + ml;
        int const price = basePrice + LZ4HC_sequencePrice(ll, ml);
        /* on equal price, favorDecSpeed keeps the existing solution */
        if ( pos > lastPos + TRAILING_LITERALS
          || price <= opt[pos].price - (int)favorDecSpeed) {
            LZ4HC_setMatch(opt, pos, ml, match.off, price);
            if ((ml == match.len) && (lastPos < pos)) lastPos = pos;
    }   }

    /* complete following positions with literals */
    {   int addLit;
        assert(opt[lastPos].mlen >= MINMATCH);
        for (addLit = 1; addLit <= TRAILING_LITERALS; addLit++)
            LZ4HC_setLiteral(opt, lastPos + addLit, addLit,
                             opt[lastPos].price + LZ4HC_literalsPrice(addLit));
    }
    return lastPos;
}


/* preconditions:
 * - *srcSizePtr within [1, LZ4_MAX_INPUT_SIZE]
 * - src is valid
 * - maxOutputSize >= 1
 * - dst is valid
 * - @opt : table of LZ4_OPT_NUM + TRAILING_LITERALS cells
 */
LZ4_FORCE_INLINE int
LZ4HC_compress_optimal_internal(LZ4HC_CCtx_internal* ctx,
                                const char* const source,
                                char* dst,
                                int* srcSizePtr,
                                int dstCapacity,
                                int const nbSearches,
                                int const nbSearchesSeq,
                                int const targetLength,
                                const limitedOutput_directive limit,
                                const dictCtx_directive dict,
                                const HCfavor_e favorDecSpeed,
                                LZ4HC_optimal_t* const opt)
{
    const BYTE* ip = (const BYTE*) source;
    const BYTE* anchor = ip;
    const int inputSize = *srcSizePtr;
    const BYTE* const iend = ip + inputSize;
    const BYTE* mflimit;      /* set after the size check : would precede a small input */
    const BYTE* matchlimit;
    BYTE* op = (BYTE*) dst;
    /* fillOutput : keep room for the final run of literals (LZ4 format restriction) */
    BYTE* const oend = op + dstCapacity - ((limit == fillOutput) ? LASTLITERALS : 0);
    int const sufficientLen = MIN(targetLength, LZ4_OPT_NUM-1);

    DEBUGLOG(5, "LZ4HC_compress_optimal(dst=%p, dstCapa=%u)", dst, (unsigned)dstCapacity);

    /* preconditions verifications */
    assert(dstCapacity > 0);
    assert(dst != NULL);
    assert(*srcSizePtr > 0);
    assert(source != NULL);
    assert(opt != NULL);
    assert(nbSearchesSeq >= 1);

    *srcSizePtr = 0;
    if (inputSize < LZ4_minLength) goto _last_literals;
    mflimit = iend - MFLIMIT;
    matchlimit = iend - LASTLITERALS;

    /* Main Loop */
    while (ip <= mflimit) {
        int const llen = LZ4HC_pricedLitlen((int)(ip - anchor));
        int cur, lastPos;
        int lastSeqPos;         /* position of the last sequence to encode */
        LZ4HC_match_t lastSeq;

        LZ4HC_match_t const firstMatch = LZ4HC_FindLongestMatch(ctx, ip, matchlimit, nbSearches, dict, favorDecSpeed);
        if (firstMatch.len==0) { ip++; continue; }

        if (firstMatch.len > sufficientLen) {
            /* good enough solution : immediate encoding */
            lastSeqPos = 0;
            lastSeq = firstMatch;
            goto encode;
        }

        /* set prices for first positions (literals) */
        {   int rPos;
            for (rPos = 0 ; rPos < MINMATCH ; rPos++)
                LZ4HC_setLiteral(opt, rPos, llen + rPos, LZ4HC_literalsPrice(llen + rPos));
        }
        lastPos = LZ4HC_addMatch(opt, 0, firstMatch, 0, favorDecSpeed);

        /* check further positions */
        for (cur = 1; cur < lastPos; cur++) {
            const BYTE* const curPtr = ip + cur;
            LZ4HC_match_t newMatch;
            int nbS = nbSearches;

            if (curPtr > mflimit) break;
            DEBUGLOG(7, "rPos:%u[%u] vs [%u]%u",
                    cur, opt[cur].price, opt[cur+1].price, cur+1);
            /* not useful to search here if next position has same (or lower) cost */
            if (opt[cur+1].price <= opt[cur].price) continue;
            /* favorDecSpeed : next position costs less than one more byte, the difference comes from sequences.
             * A match starting here might save some : worth a cheaper search, if close to lastPos */
            if (favorDecSpeed && (opt[cur+1].price < opt[cur].price + LZ4HC_PRICE_SCALE)) {
                if (lastPos - cur > LZ4HC_SEQ_SEARCH_DIST) continue;
                nbS = nbSearchesSeq;
            }

            newMatch = LZ4HC_FindLongestMatch(ctx, curPtr, matchlimit, nbS, dict, favorDecSpeed);
            if (!newMatch.len) continue;

            if ( (newMatch.len > sufficientLen)
              || (newMatch.len + cur >= LZ4_OPT_NUM) ) {
                /* immediate encoding */
                lastSeqPos = cur;
                lastSeq = newMatch;
                goto encode;
            }

            lastPos = LZ4HC_addMatch(opt, cur, newMatch, lastPos, favorDecSpeed);
        }  /* for (cur = 1; cur < lastPos; cur++) */

        assert(lastPos < LZ4_OPT_NUM + TRAILING_LITERALS);
        lastSeq.len = opt[lastPos].mlen;
        lastSeq.off = opt[lastPos].off;
        lastSeqPos = lastPos - lastSeq.len;

encode: /* lastSeqPos and lastSeq must be set */
        assert(0 <= lastSeqPos && lastSeqPos < LZ4_OPT_NUM);
        DEBUGLOG(6, "reverse traversal, looking for shortest path (lastSeqPos=%i)", lastSeqPos);
        /* opt[pos] describes the step ending at pos.
         * Walk the path backward, moving each step to its starting position instead */
        {   int pos = lastSeqPos;
            int mlen = lastSeq.len;
            int off = lastSeq.off;
            while (pos > 0) {
                int const prevMlen = opt[pos].mlen;
                int const prevOff = opt[pos].off;
                opt[pos].mlen = mlen;
                opt[pos].off = off;
                mlen = prevMlen;
                off = prevOff;
                assert(0 < mlen && mlen <= pos);
                pos -= mlen;
            }
            /* first step of the path; note : opt[0] isn't necessarily initialized */
            opt[0].mlen = mlen;
            opt[0].off = off;
        }

        /* encode all recorded sequences in order */
        {   int rPos = 0;  /* relative position (to ip) */
            while (rPos <= lastSeqPos) {
                int const ml = opt[rPos].mlen;
                int const offset = opt[rPos].off;
                if (ml == 1) { ip++; rPos++; continue; }  /* literal */
                rPos += ml;
                assert(ml >= MINMATCH);
                assert((offset >= 1) && (offset <= LZ4_DISTANCE_MAX));
                if ( LZ4HC_encodeSequence(UPDATABLE(ip, op, anchor), ml, offset, limit, oend) ) {  /* updates ip, op and anchor */
                    if (limit != fillOutput) return 0;  /* compression failed */
                    LZ4HC_encodeLastSequence_fillOutput(UPDATABLE(ip, op, anchor), ml, offset, oend);
                    goto _last_literals;
        }   }   }
    }  /* while (ip <= mflimit) */

_last_literals:
    if (LZ4HC_encodeLastLiterals(UPDATABLE(ip, op, anchor), iend, limit, oend))
        return 0;  /* not enough space in @dst */

    /* End */
    *srcSizePtr = (int) (((const char*)ip) - source);
    return (int) ((char*)op-dst);
}

static int LZ4HC_compress_optimal ( LZ4HC_CCtx_internal* ctx,
                                    const char* const source,
                                    char* dst,
                                    int* srcSizePtr,
                                    int dstCapacity,
                                    int const nbSearches,
                                    int const nbSearchesSeq,
                                    int const targetLength,
                                    const limitedOutput_directive limit,
                                    const dictCtx_directive dict,
                                    const HCfavor_e favorDecSpeed)
{
    LZ4_STATIC_ASSERT(LZ4_STREAMHC_EXTSIZE == sizeof(LZ4_streamHC_t) + sizeof(LZ4HC_optimal_t) * (LZ4_OPT_NUM + TRAILING_LITERALS));
    if (ctx->hasWorkspace) {   /* extended state : the buffer follows it */
        LZ4HC_optimal_t* const opt = (LZ4HC_optimal_t*)(void*)((BYTE*)ctx + sizeof(LZ4_streamHC_t));
        return LZ4HC_compress_optimal_internal(ctx, source, dst, srcSizePtr, dstCapacity,
                    nbSearches, nbSearchesSeq, targetLength, limit, dict, favorDecSpeed, opt);
    }
  { /* plain state */
#if defined(LZ4HC_HEAPMODE) && LZ4HC_HEAPMODE==1
    LZ4HC_optimal_t* const opt = (LZ4HC_optimal_t*)ALLOC(sizeof(LZ4HC_optimal_t) * (LZ4_OPT_NUM + TRAILING_LITERALS));
    int result;
    if (opt == NULL) return 0;
    result = LZ4HC_compress_optimal_internal(ctx, source, dst, srcSizePtr, dstCapacity,
                    nbSearches, nbSearchesSeq, targetLength, limit, dict, favorDecSpeed, opt);
    FREEMEM(opt);
    return result;
#else
    LZ4HC_optimal_t opt[LZ4_OPT_NUM + TRAILING_LITERALS];   /* ~64 KB, which can be a bit large for some stacks... */
    return LZ4HC_compress_optimal_internal(ctx, source, dst, srcSizePtr, dstCapacity,
                    nbSearches, nbSearchesSeq, targetLength, limit, dict, favorDecSpeed, opt);
#endif
  }
}


/***************************************************
*  Obsolete functions, removed from lz4hc.h (v1.11.0)
*  still exported, for programs linked to previous versions
***************************************************/

LZ4LIB_API int LZ4_compressHC (const char* source, char* dest, int inputSize);
LZ4LIB_API int LZ4_compressHC_limitedOutput (const char* source, char* dest, int inputSize, int maxOutputSize);
LZ4LIB_API int LZ4_compressHC2 (const char* source, char* dest, int inputSize, int compressionLevel);
LZ4LIB_API int LZ4_compressHC2_limitedOutput (const char* source, char* dest, int inputSize, int maxOutputSize, int compressionLevel);
LZ4LIB_API int LZ4_compressHC_withStateHC (void* state, const char* source, char* dest, int inputSize);
LZ4LIB_API int LZ4_compressHC_limitedOutput_withStateHC (void* state, const char* source, char* dest, int inputSize, int maxOutputSize);
LZ4LIB_API int LZ4_compressHC2_withStateHC (void* state, const char* source, char* dest, int inputSize, int compressionLevel);
LZ4LIB_API int LZ4_compressHC2_limitedOutput_withStateHC (void* state, const char* source, char* dest, int inputSize, int maxOutputSize, int compressionLevel);
LZ4LIB_API int LZ4_compressHC_continue (LZ4_streamHC_t* LZ4_streamHCPtr, const char* source, char* dest, int inputSize);
LZ4LIB_API int LZ4_compressHC_limitedOutput_continue (LZ4_streamHC_t* LZ4_streamHCPtr, const char* source, char* dest, int inputSize, int maxOutputSize);
LZ4LIB_API void* LZ4_createHC (const char* inputBuffer);
LZ4LIB_API int   LZ4_freeHC (void* LZ4HC_Data);
LZ4LIB_API char* LZ4_slideInputBufferHC (void* LZ4HC_Data);
LZ4LIB_API int LZ4_compressHC2_continue (void* LZ4HC_Data, const char* source, char* dest, int inputSize, int compressionLevel);
LZ4LIB_API int LZ4_compressHC2_limitedOutput_continue (void* LZ4HC_Data, const char* source, char* dest, int inputSize, int maxOutputSize, int compressionLevel);
LZ4LIB_API int   LZ4_sizeofStreamStateHC(void);
LZ4LIB_API int   LZ4_resetStreamStateHC(void* state, char* inputBuffer);

/* Wrappers for deprecated compression functions */
int LZ4_compressHC(const char* src, char* dst, int srcSize) { return LZ4_compress_HC (src, dst, srcSize, LZ4_compressBound(srcSize), 0); }
int LZ4_compressHC_limitedOutput(const char* src, char* dst, int srcSize, int maxDstSize) { return LZ4_compress_HC(src, dst, srcSize, maxDstSize, 0); }
int LZ4_compressHC2(const char* src, char* dst, int srcSize, int cLevel) { return LZ4_compress_HC (src, dst, srcSize, LZ4_compressBound(srcSize), cLevel); }
int LZ4_compressHC2_limitedOutput(const char* src, char* dst, int srcSize, int maxDstSize, int cLevel) { return LZ4_compress_HC(src, dst, srcSize, maxDstSize, cLevel); }
int LZ4_compressHC_withStateHC (void* state, const char* src, char* dst, int srcSize) { return LZ4_compress_HC_extStateHC (state, src, dst, srcSize, LZ4_compressBound(srcSize), 0); }
int LZ4_compressHC_limitedOutput_withStateHC (void* state, const char* src, char* dst, int srcSize, int maxDstSize) { return LZ4_compress_HC_extStateHC (state, src, dst, srcSize, maxDstSize, 0); }
int LZ4_compressHC2_withStateHC (void* state, const char* src, char* dst, int srcSize, int cLevel) { return LZ4_compress_HC_extStateHC(state, src, dst, srcSize, LZ4_compressBound(srcSize), cLevel); }
int LZ4_compressHC2_limitedOutput_withStateHC (void* state, const char* src, char* dst, int srcSize, int maxDstSize, int cLevel) { return LZ4_compress_HC_extStateHC(state, src, dst, srcSize, maxDstSize, cLevel); }
int LZ4_compressHC_continue (LZ4_streamHC_t* ctx, const char* src, char* dst, int srcSize) { return LZ4_compress_HC_continue (ctx, src, dst, srcSize, LZ4_compressBound(srcSize)); }
int LZ4_compressHC_limitedOutput_continue (LZ4_streamHC_t* ctx, const char* src, char* dst, int srcSize, int maxDstSize) { return LZ4_compress_HC_continue (ctx, src, dst, srcSize, maxDstSize); }


/* Deprecated streaming functions */
int LZ4_sizeofStreamStateHC(void) { return sizeof(LZ4_streamHC_t); }

/* state is presumed correctly sized, aka >= sizeof(LZ4_streamHC_t)
 * @return : 0 on success, !=0 if error */
int LZ4_resetStreamStateHC(void* state, char* inputBuffer)
{
    LZ4_streamHC_t* const hc4 = LZ4_initStreamHC(state, sizeof(*hc4));
    if (hc4 == NULL) return 1;   /* init failed */
    LZ4HC_init_internal (&hc4->internal_donotuse, (const BYTE*)inputBuffer);
    return 0;
}

#if !defined(LZ4_STATIC_LINKING_ONLY_DISABLE_MEMORY_ALLOCATION)
void* LZ4_createHC (const char* inputBuffer)
{
    LZ4_streamHC_t* const hc4 = LZ4_createStreamHC();
    if (hc4 == NULL) return NULL;   /* not enough memory */
    LZ4HC_init_internal (&hc4->internal_donotuse, (const BYTE*)inputBuffer);
    return hc4;
}

int LZ4_freeHC (void* LZ4HC_Data)
{
    if (!LZ4HC_Data) return 0;  /* support free on NULL */
    FREEMEM(LZ4HC_Data);
    return 0;
}
#endif

/* LZ4_compress_HC_continue() at level @cLevel : notably, restarts the stream after LZ4_slideInputBufferHC() */
int LZ4_compressHC2_continue (void* LZ4HC_Data, const char* src, char* dst, int srcSize, int cLevel)
{
    LZ4_setCompressionLevel((LZ4_streamHC_t*)LZ4HC_Data, cLevel);
    return LZ4_compress_HC_continue((LZ4_streamHC_t*)LZ4HC_Data, src, dst, srcSize, LZ4_compressBound(srcSize));
}

int LZ4_compressHC2_limitedOutput_continue (void* LZ4HC_Data, const char* src, char* dst, int srcSize, int dstCapacity, int cLevel)
{
    LZ4_setCompressionLevel((LZ4_streamHC_t*)LZ4HC_Data, cLevel);
    return LZ4_compress_HC_continue((LZ4_streamHC_t*)LZ4HC_Data, src, dst, srcSize, dstCapacity);
}

char* LZ4_slideInputBufferHC(void* LZ4HC_Data)
{
    LZ4HC_CCtx_internal* const s = &((LZ4_streamHC_t*)LZ4HC_Data)->internal_donotuse;
    const BYTE* const bufferStart = s->prefixStart - s->dictLimit + s->lowLimit;
    LZ4_resetStreamHC_fast((LZ4_streamHC_t*)LZ4HC_Data, s->compressionLevel);
    /* ugly conversion trick, required to evade (const char*) -> (char*) cast-qual warning :( */
    return (char*)(uptrval)bufferStart;
}

}
