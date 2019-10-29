#pragma once

#if defined(_MSC_VER)
#define VM_INLINE __forceinline
#else
#define VM_INLINE __attribute__((unused, always_inline, nodebug)) inline
#endif

#define kSimdWidth 4

#if !defined(__arm__) && !defined(__arm64__) && !defined(__EMSCRIPTEN__)

// ---- SSE implementation

#include <xmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>

#define SHUFFLE4(V, X,Y,Z,W) float4(_mm_shuffle_ps((V).m, (V).m, _MM_SHUFFLE(W,Z,Y,X)))

struct float4
{
    VM_INLINE float4() {}
    VM_INLINE explicit float4(const float *p) { m = _mm_loadu_ps(p); }
    VM_INLINE explicit float4(float x, float y, float z, float w) { m = _mm_set_ps(w, z, y, x); }
    VM_INLINE explicit float4(float v) { m = _mm_set_ps1(v); }
    VM_INLINE explicit float4(__m128 v) { m = v; }
    
    VM_INLINE float getX() const { return _mm_cvtss_f32(m); }
    VM_INLINE float getY() const { return _mm_cvtss_f32(_mm_shuffle_ps(m, m, _MM_SHUFFLE(1, 1, 1, 1))); }
    VM_INLINE float getZ() const { return _mm_cvtss_f32(_mm_shuffle_ps(m, m, _MM_SHUFFLE(2, 2, 2, 2))); }
    VM_INLINE float getW() const { return _mm_cvtss_f32(_mm_shuffle_ps(m, m, _MM_SHUFFLE(3, 3, 3, 3))); }
    
    __m128 m;
};

typedef float4 bool4;

VM_INLINE float4 operator+ (float4 a, float4 b) { a.m = _mm_add_ps(a.m, b.m); return a; }
VM_INLINE float4 operator- (float4 a, float4 b) { a.m = _mm_sub_ps(a.m, b.m); return a; }
VM_INLINE float4 operator* (float4 a, float4 b) { a.m = _mm_mul_ps(a.m, b.m); return a; }
VM_INLINE bool4 operator==(float4 a, float4 b) { a.m = _mm_cmpeq_ps(a.m, b.m); return a; }
VM_INLINE bool4 operator!=(float4 a, float4 b) { a.m = _mm_cmpneq_ps(a.m, b.m); return a; }
VM_INLINE bool4 operator< (float4 a, float4 b) { a.m = _mm_cmplt_ps(a.m, b.m); return a; }
VM_INLINE bool4 operator> (float4 a, float4 b) { a.m = _mm_cmpgt_ps(a.m, b.m); return a; }
VM_INLINE bool4 operator<=(float4 a, float4 b) { a.m = _mm_cmple_ps(a.m, b.m); return a; }
VM_INLINE bool4 operator>=(float4 a, float4 b) { a.m = _mm_cmpge_ps(a.m, b.m); return a; }
VM_INLINE bool4 operator&(bool4 a, bool4 b) { a.m = _mm_and_ps(a.m, b.m); return a; }
VM_INLINE bool4 operator|(bool4 a, bool4 b) { a.m = _mm_or_ps(a.m, b.m); return a; }
VM_INLINE float4 operator- (float4 a) { a.m = _mm_xor_ps(a.m, _mm_set1_ps(-0.0f)); return a; }
VM_INLINE float4 min(float4 a, float4 b) { a.m = _mm_min_ps(a.m, b.m); return a; }
VM_INLINE float4 max(float4 a, float4 b) { a.m = _mm_max_ps(a.m, b.m); return a; }

VM_INLINE float hmin(float4 v)
{
    v = min(v, SHUFFLE4(v, 2, 3, 0, 0));
    v = min(v, SHUFFLE4(v, 1, 0, 0, 0));
    return v.getX();
}

// Returns a 4-bit code where bit0..bit3 is X..W
VM_INLINE unsigned mask(float4 v) { return _mm_movemask_ps(v.m); }
// Once we have a comparison, we can branch based on its results:
VM_INLINE bool any(bool4 v) { return mask(v) != 0; }
VM_INLINE bool all(bool4 v) { return mask(v) == 15; }

// "select", i.e. hibit(cond) ? b : a
// on SSE4.1 and up this can be done easily via "blend" instruction;
// on older SSEs has to do a bunch of hoops, see
// https://fgiesen.wordpress.com/2016/04/03/sse-mind-the-gap/

VM_INLINE float4 select(float4 a, float4 b, bool4 cond)
{
#if defined(__SSE4_1__) || defined(_MSC_VER) // on windows assume we always have SSE4.1
    a.m = _mm_blendv_ps(a.m, b.m, cond.m);
#else
    __m128 d = _mm_castsi128_ps(_mm_srai_epi32(_mm_castps_si128(cond.m), 31));
    a.m = _mm_or_ps(_mm_and_ps(d, b.m), _mm_andnot_ps(d, a.m));
#endif
    return a;
}
VM_INLINE __m128i select(__m128i a, __m128i b, bool4 cond)
{
#if defined(__SSE4_1__) || defined(_MSC_VER) // on windows assume we always have SSE4.1
    return _mm_blendv_epi8(a, b, _mm_castps_si128(cond.m));
#else
    __m128i d = _mm_srai_epi32(_mm_castps_si128(cond.m), 31);
    return _mm_or_si128(_mm_and_si128(d, b), _mm_andnot_si128(d, a));
#endif
}

VM_INLINE float4 sqrtf(float4 v) { return float4(_mm_sqrt_ps(v.m)); }

#elif !defined(__EMSCRIPTEN__)

// ---- NEON implementation

#define USE_NEON 1
#include <arm_neon.h>

struct float4
{
    VM_INLINE float4() {}
    VM_INLINE explicit float4(const float *p) { m = vld1q_f32(p); }
    VM_INLINE explicit float4(float x, float y, float z, float w) { float v[4] = {x, y, z, w}; m = vld1q_f32(v); }
    VM_INLINE explicit float4(float v) { m = vdupq_n_f32(v); }
    VM_INLINE explicit float4(float32x4_t v) { m = v; }
    
    VM_INLINE float getX() const { return vgetq_lane_f32(m, 0); }
    VM_INLINE float getY() const { return vgetq_lane_f32(m, 1); }
    VM_INLINE float getZ() const { return vgetq_lane_f32(m, 2); }
    VM_INLINE float getW() const { return vgetq_lane_f32(m, 3); }
    
    float32x4_t m;
};

typedef float4 bool4;

VM_INLINE float4 operator+ (float4 a, float4 b) { a.m = vaddq_f32(a.m, b.m); return a; }
VM_INLINE float4 operator- (float4 a, float4 b) { a.m = vsubq_f32(a.m, b.m); return a; }
VM_INLINE float4 operator* (float4 a, float4 b) { a.m = vmulq_f32(a.m, b.m); return a; }
VM_INLINE bool4 operator==(float4 a, float4 b) { a.m = vceqq_f32(a.m, b.m); return a; }
VM_INLINE bool4 operator!=(float4 a, float4 b) { a.m = a.m = vmvnq_u32(vceqq_f32(a.m, b.m)); return a; }
VM_INLINE bool4 operator< (float4 a, float4 b) { a.m = vcltq_f32(a.m, b.m); return a; }
VM_INLINE bool4 operator> (float4 a, float4 b) { a.m = vcgtq_f32(a.m, b.m); return a; }
VM_INLINE bool4 operator<=(float4 a, float4 b) { a.m = vcleq_f32(a.m, b.m); return a; }
VM_INLINE bool4 operator>=(float4 a, float4 b) { a.m = vcgeq_f32(a.m, b.m); return a; }
VM_INLINE bool4 operator&(bool4 a, bool4 b) { a.m = vandq_u32(a.m, b.m); return a; }
VM_INLINE bool4 operator|(bool4 a, bool4 b) { a.m = vorrq_u32(a.m, b.m); return a; }
VM_INLINE float4 operator- (float4 a) { a.m = vnegq_f32(a.m); return a; }
VM_INLINE float4 min(float4 a, float4 b) { a.m = vminq_f32(a.m, b.m); return a; }
VM_INLINE float4 max(float4 a, float4 b) { a.m = vmaxq_f32(a.m, b.m); return a; }

VM_INLINE float hmin(float4 v)
{
    float32x2_t minOfHalfs = vpmin_f32(vget_low_f32(v.m), vget_high_f32(v.m));
    float32x2_t minOfMinOfHalfs = vpmin_f32(minOfHalfs, minOfHalfs);
    return vget_lane_f32(minOfMinOfHalfs, 0);
}

// Returns a 4-bit code where bit0..bit3 is X..W
VM_INLINE unsigned mask(float4 v)
{
    static const uint32x4_t movemask = { 1, 2, 4, 8 };
    static const uint32x4_t highbit = { 0x80000000, 0x80000000, 0x80000000, 0x80000000 };
    uint32x4_t t0 = vreinterpretq_u32_f32(v.m);
    uint32x4_t t1 = vtstq_u32(t0, highbit);
    uint32x4_t t2 = vandq_u32(t1, movemask);
    uint32x2_t t3 = vorr_u32(vget_low_u32(t2), vget_high_u32(t2));
    return vget_lane_u32(t3, 0) | vget_lane_u32(t3, 1);
}
// Once we have a comparison, we can branch based on its results:
VM_INLINE bool any(bool4 v) { return mask(v) != 0; }
VM_INLINE bool all(bool4 v) { return mask(v) == 15; }

// "select", i.e. hibit(cond) ? b : a
// on SSE4.1 and up this can be done easily via "blend" instruction;
// on older SSEs has to do a bunch of hoops, see
// https://fgiesen.wordpress.com/2016/04/03/sse-mind-the-gap/

VM_INLINE float4 select(float4 a, float4 b, bool4 cond)
{
    a.m = vbslq_f32(cond.m, b.m, a.m);
    return a;
}
VM_INLINE int32x4_t select(int32x4_t a, int32x4_t b, bool4 cond)
{
    return vbslq_f32(cond.m, b, a);
}

VM_INLINE float4 sqrtf(float4 v)
{
    float32x4_t V = v.m;
    float32x4_t S0 = vrsqrteq_f32(V);
    float32x4_t P0 = vmulq_f32( V, S0 );
    float32x4_t R0 = vrsqrtsq_f32( P0, S0 );
    float32x4_t S1 = vmulq_f32( S0, R0 );
    float32x4_t P1 = vmulq_f32( V, S1 );
    float32x4_t R1 = vrsqrtsq_f32( P1, S1 );
    float32x4_t S2 = vmulq_f32( S1, R1 );
    float32x4_t P2 = vmulq_f32( V, S2 );
    float32x4_t R2 = vrsqrtsq_f32( P2, S2 );
    float32x4_t S3 = vmulq_f32( S2, R2 );
    return float4(vmulq_f32(V, S3));
}

VM_INLINE float4 splatX(float32x4_t v) { return float4(vdupq_lane_f32(vget_low_f32(v), 0)); }
VM_INLINE float4 splatY(float32x4_t v) { return float4(vdupq_lane_f32(vget_low_f32(v), 1)); }
VM_INLINE float4 splatZ(float32x4_t v) { return float4(vdupq_lane_f32(vget_high_f32(v), 0)); }
VM_INLINE float4 splatW(float32x4_t v) { return float4(vdupq_lane_f32(vget_high_f32(v), 1)); }

#endif
