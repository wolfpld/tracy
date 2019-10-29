#pragma once

#include <math.h>
#include <assert.h>
#include <stdint.h>
#include "Config.h"
#include "MathSimd.h"

#define kPI 3.1415926f

// SSE/SIMD vector largely based on http://www.codersnotes.com/notes/maths-lib-2016/
#if DO_FLOAT3_WITH_SIMD


#if !defined(__arm__) && !defined(__arm64__)

// ---- SSE implementation

// SHUFFLE3(v, 0,1,2) leaves the vector unchanged (v.xyz).
// SHUFFLE3(v, 0,0,0) splats the X (v.xxx).
#define SHUFFLE3(V, X,Y,Z) float3(_mm_shuffle_ps((V).m, (V).m, _MM_SHUFFLE(Z,Z,Y,X)))

struct float3
{
    VM_INLINE float3() {}
    VM_INLINE explicit float3(const float *p) { m = _mm_set_ps(p[2], p[2], p[1], p[0]); }
    VM_INLINE explicit float3(float x, float y, float z) { m = _mm_set_ps(z, z, y, x); }
    VM_INLINE explicit float3(float v) { m = _mm_set1_ps(v); }
    VM_INLINE explicit float3(__m128 v) { m = v; }

    VM_INLINE float getX() const { return _mm_cvtss_f32(m); }
    VM_INLINE float getY() const { return _mm_cvtss_f32(_mm_shuffle_ps(m, m, _MM_SHUFFLE(1, 1, 1, 1))); }
    VM_INLINE float getZ() const { return _mm_cvtss_f32(_mm_shuffle_ps(m, m, _MM_SHUFFLE(2, 2, 2, 2))); }

    VM_INLINE float3 yzx() const { return SHUFFLE3(*this, 1, 2, 0); }
    VM_INLINE float3 zxy() const { return SHUFFLE3(*this, 2, 0, 1); }

    VM_INLINE void store(float *p) const { p[0] = getX(); p[1] = getY(); p[2] = getZ(); }

    void setX(float x)
    {
        m = _mm_move_ss(m, _mm_set_ss(x));
    }
    void setY(float y)
    {
        __m128 t = _mm_move_ss(m, _mm_set_ss(y));
        t = _mm_shuffle_ps(t, t, _MM_SHUFFLE(3, 2, 0, 0));
        m = _mm_move_ss(t, m);
    }
    void setZ(float z)
    {
        __m128 t = _mm_move_ss(m, _mm_set_ss(z));
        t = _mm_shuffle_ps(t, t, _MM_SHUFFLE(3, 0, 1, 0));
        m = _mm_move_ss(t, m);
    }

    __m128 m;
};

typedef float3 bool3;

VM_INLINE float3 operator+ (float3 a, float3 b) { a.m = _mm_add_ps(a.m, b.m); return a; }
VM_INLINE float3 operator- (float3 a, float3 b) { a.m = _mm_sub_ps(a.m, b.m); return a; }
VM_INLINE float3 operator* (float3 a, float3 b) { a.m = _mm_mul_ps(a.m, b.m); return a; }
VM_INLINE float3 operator/ (float3 a, float3 b) { a.m = _mm_div_ps(a.m, b.m); return a; }
VM_INLINE float3 operator* (float3 a, float b) { a.m = _mm_mul_ps(a.m, _mm_set1_ps(b)); return a; }
VM_INLINE float3 operator/ (float3 a, float b) { a.m = _mm_div_ps(a.m, _mm_set1_ps(b)); return a; }
VM_INLINE float3 operator* (float a, float3 b) { b.m = _mm_mul_ps(_mm_set1_ps(a), b.m); return b; }
VM_INLINE float3 operator/ (float a, float3 b) { b.m = _mm_div_ps(_mm_set1_ps(a), b.m); return b; }
VM_INLINE float3& operator+= (float3 &a, float3 b) { a = a + b; return a; }
VM_INLINE float3& operator-= (float3 &a, float3 b) { a = a - b; return a; }
VM_INLINE float3& operator*= (float3 &a, float3 b) { a = a * b; return a; }
VM_INLINE float3& operator/= (float3 &a, float3 b) { a = a / b; return a; }
VM_INLINE float3& operator*= (float3 &a, float b) { a = a * b; return a; }
VM_INLINE float3& operator/= (float3 &a, float b) { a = a / b; return a; }
VM_INLINE bool3 operator==(float3 a, float3 b) { a.m = _mm_cmpeq_ps(a.m, b.m); return a; }
VM_INLINE bool3 operator!=(float3 a, float3 b) { a.m = _mm_cmpneq_ps(a.m, b.m); return a; }
VM_INLINE bool3 operator< (float3 a, float3 b) { a.m = _mm_cmplt_ps(a.m, b.m); return a; }
VM_INLINE bool3 operator> (float3 a, float3 b) { a.m = _mm_cmpgt_ps(a.m, b.m); return a; }
VM_INLINE bool3 operator<=(float3 a, float3 b) { a.m = _mm_cmple_ps(a.m, b.m); return a; }
VM_INLINE bool3 operator>=(float3 a, float3 b) { a.m = _mm_cmpge_ps(a.m, b.m); return a; }
VM_INLINE float3 min(float3 a, float3 b) { a.m = _mm_min_ps(a.m, b.m); return a; }
VM_INLINE float3 max(float3 a, float3 b) { a.m = _mm_max_ps(a.m, b.m); return a; }

VM_INLINE float3 operator- (float3 a) { return float3(_mm_setzero_ps()) - a; }

VM_INLINE float hmin(float3 v)
{
    v = min(v, SHUFFLE3(v, 1, 0, 2));
    return min(v, SHUFFLE3(v, 2, 0, 1)).getX();
}
VM_INLINE float hmax(float3 v)
{
    v = max(v, SHUFFLE3(v, 1, 0, 2));
    return max(v, SHUFFLE3(v, 2, 0, 1)).getX();
}

VM_INLINE float3 cross(float3 a, float3 b)
{
    // x  <-  a.y*b.z - a.z*b.y
    // y  <-  a.z*b.x - a.x*b.z
    // z  <-  a.x*b.y - a.y*b.x
    // We can save a shuffle by grouping it in this wacky order:
    return (a.zxy()*b - a*b.zxy()).zxy();
}

// Returns a 3-bit code where bit0..bit2 is X..Z
VM_INLINE unsigned mask(float3 v) { return _mm_movemask_ps(v.m) & 7; }
// Once we have a comparison, we can branch based on its results:
VM_INLINE bool any(bool3 v) { return mask(v) != 0; }
VM_INLINE bool all(bool3 v) { return mask(v) == 7; }

VM_INLINE float3 clamp(float3 t, float3 a, float3 b) { return min(max(t, a), b); }
VM_INLINE float sum(float3 v) { return v.getX() + v.getY() + v.getZ(); }
VM_INLINE float dot(float3 a, float3 b) { return sum(a*b); }

#else // #if !defined(__arm__) && !defined(__arm64__)

// ---- NEON implementation

#include <arm_neon.h>

struct float3
{
    VM_INLINE float3() {}
    VM_INLINE explicit float3(const float *p) { float v[4] = {p[0], p[1], p[2], 0}; m = vld1q_f32(v); }
    VM_INLINE explicit float3(float x, float y, float z) { float v[4] = {x, y, z, 0}; m = vld1q_f32(v); }
    VM_INLINE explicit float3(float v) { m = vdupq_n_f32(v); }
    VM_INLINE explicit float3(float32x4_t v) { m = v; }
    
    VM_INLINE float getX() const { return vgetq_lane_f32(m, 0); }
    VM_INLINE float getY() const { return vgetq_lane_f32(m, 1); }
    VM_INLINE float getZ() const { return vgetq_lane_f32(m, 2); }
    
    VM_INLINE float3 yzx() const
    {
        float32x2_t low = vget_low_f32(m);
        float32x4_t yzx = vcombine_f32(vext_f32(low, vget_high_f32(m), 1), low);
        return float3(yzx);
    }
    VM_INLINE float3 zxy() const
    {
        float32x4_t p = m;
        p = vuzpq_f32(vreinterpretq_f32_s32(vextq_s32(vreinterpretq_s32_f32(p), vreinterpretq_s32_f32(p), 1)), p).val[1];
        return float3(p);
    }
    
    VM_INLINE void store(float *p) const { p[0] = getX(); p[1] = getY(); p[2] = getZ(); }
    
    void setX(float x)
    {
        m = vsetq_lane_f32(x, m, 0);
    }
    void setY(float y)
    {
        m = vsetq_lane_f32(y, m, 1);
    }
    void setZ(float z)
    {
        m = vsetq_lane_f32(z, m, 2);
    }
    
    float32x4_t m;
};

typedef float3 bool3;

VM_INLINE float32x4_t rcp_2(float32x4_t v)
{
    float32x4_t e = vrecpeq_f32(v);
    e = vmulq_f32(vrecpsq_f32(e, v), e);
    e = vmulq_f32(vrecpsq_f32(e, v), e);
    return e;
}

VM_INLINE float3 operator+ (float3 a, float3 b) { a.m = vaddq_f32(a.m, b.m); return a; }
VM_INLINE float3 operator- (float3 a, float3 b) { a.m = vsubq_f32(a.m, b.m); return a; }
VM_INLINE float3 operator* (float3 a, float3 b) { a.m = vmulq_f32(a.m, b.m); return a; }
VM_INLINE float3 operator/ (float3 a, float3 b) { float32x4_t recip = rcp_2(b.m); a.m = vmulq_f32(a.m, recip); return a; }
VM_INLINE float3 operator* (float3 a, float b) { a.m = vmulq_f32(a.m, vdupq_n_f32(b)); return a; }
VM_INLINE float3 operator/ (float3 a, float b) { float32x4_t recip = rcp_2(vdupq_n_f32(b)); a.m = vmulq_f32(a.m, recip); return a; }
VM_INLINE float3 operator* (float a, float3 b) { b.m = vmulq_f32(vdupq_n_f32(a), b.m); return b; }
VM_INLINE float3 operator/ (float a, float3 b) { float32x4_t recip = rcp_2(b.m); b.m = vmulq_f32(vdupq_n_f32(a), recip); return b; }
VM_INLINE float3& operator+= (float3 &a, float3 b) { a = a + b; return a; }
VM_INLINE float3& operator-= (float3 &a, float3 b) { a = a - b; return a; }
VM_INLINE float3& operator*= (float3 &a, float3 b) { a = a * b; return a; }
VM_INLINE float3& operator/= (float3 &a, float3 b) { a = a / b; return a; }
VM_INLINE float3& operator*= (float3 &a, float b) { a = a * b; return a; }
VM_INLINE float3& operator/= (float3 &a, float b) { a = a / b; return a; }
VM_INLINE bool3 operator==(float3 a, float3 b) { a.m = vceqq_f32(a.m, b.m); return a; }
VM_INLINE bool3 operator!=(float3 a, float3 b) { a.m = vmvnq_u32(vceqq_f32(a.m, b.m)); return a; }
VM_INLINE bool3 operator< (float3 a, float3 b) { a.m = vcltq_f32(a.m, b.m); return a; }
VM_INLINE bool3 operator> (float3 a, float3 b) { a.m = vcgtq_f32(a.m, b.m); return a; }
VM_INLINE bool3 operator<=(float3 a, float3 b) { a.m = vcleq_f32(a.m, b.m); return a; }
VM_INLINE bool3 operator>=(float3 a, float3 b) { a.m = vcgeq_f32(a.m, b.m); return a; }
VM_INLINE float3 min(float3 a, float3 b) { a.m = vminq_f32(a.m, b.m); return a; }
VM_INLINE float3 max(float3 a, float3 b) { a.m = vmaxq_f32(a.m, b.m); return a; }

VM_INLINE float3 operator- (float3 a) { a.m = vnegq_f32(a.m); return a; }

VM_INLINE float hmin(float3 v)
{
    float32x2_t minOfHalfs = vpmin_f32(vget_low_f32(v.m), vget_high_f32(v.m));
    float32x2_t minOfMinOfHalfs = vpmin_f32(minOfHalfs, minOfHalfs);
    return vget_lane_f32(minOfMinOfHalfs, 0);
}
VM_INLINE float hmax(float3 v)
{
    float32x2_t maxOfHalfs = vpmax_f32(vget_low_f32(v.m), vget_high_f32(v.m));
    float32x2_t maxOfMaxOfHalfs = vpmax_f32(maxOfHalfs, maxOfHalfs);
    return vget_lane_f32(maxOfMaxOfHalfs, 0);
}

VM_INLINE float3 cross(float3 a, float3 b)
{
    // x  <-  a.y*b.z - a.z*b.y
    // y  <-  a.z*b.x - a.x*b.z
    // z  <-  a.x*b.y - a.y*b.x
    // We can save a shuffle by grouping it in this wacky order:
    return (a.zxy()*b - a*b.zxy()).zxy();
}

// Returns a 3-bit code where bit0..bit2 is X..Z
VM_INLINE unsigned mask(float3 v)
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
VM_INLINE bool any(bool3 v) { return mask(v) != 0; }
VM_INLINE bool all(bool3 v) { return mask(v) == 7; }

VM_INLINE float3 clamp(float3 t, float3 a, float3 b) { return min(max(t, a), b); }
VM_INLINE float sum(float3 v) { return v.getX() + v.getY() + v.getZ(); }
VM_INLINE float dot(float3 a, float3 b) { return sum(a*b); }


#endif // #else of #if !defined(__arm__) && !defined(__arm64__)

#else // #if DO_FLOAT3_WITH_SIMD

// ---- Simple scalar C implementation


struct float3
{
    float3() : x(0), y(0), z(0) {}
    float3(float x_, float y_, float z_) : x(x_), y(y_), z(z_) {}

    float3 operator-() const { return float3(-x, -y, -z); }
    float3& operator+=(const float3& o) { x+=o.x; y+=o.y; z+=o.z; return *this; }
    float3& operator-=(const float3& o) { x-=o.x; y-=o.y; z-=o.z; return *this; }
    float3& operator*=(const float3& o) { x*=o.x; y*=o.y; z*=o.z; return *this; }
    float3& operator*=(float o) { x*=o; y*=o; z*=o; return *this; }

    VM_INLINE float getX() const { return x; }
    VM_INLINE float getY() const { return y; }
    VM_INLINE float getZ() const { return z; }
    VM_INLINE void setX(float x_) { x = x_; }
    VM_INLINE void setY(float y_) { y = y_; }
    VM_INLINE void setZ(float z_) { z = z_; }
    VM_INLINE void store(float *p) const { p[0] = getX(); p[1] = getY(); p[2] = getZ(); }

    float x, y, z;
};

VM_INLINE float3 operator+(const float3& a, const float3& b) { return float3(a.x+b.x,a.y+b.y,a.z+b.z); }
VM_INLINE float3 operator-(const float3& a, const float3& b) { return float3(a.x-b.x,a.y-b.y,a.z-b.z); }
VM_INLINE float3 operator*(const float3& a, const float3& b) { return float3(a.x*b.x,a.y*b.y,a.z*b.z); }
VM_INLINE float3 operator*(const float3& a, float b) { return float3(a.x*b,a.y*b,a.z*b); }
VM_INLINE float3 operator*(float a, const float3& b) { return float3(a*b.x,a*b.y,a*b.z); }
VM_INLINE float dot(const float3& a, const float3& b) { return a.x*b.x+a.y*b.y+a.z*b.z; }
VM_INLINE float3 cross(const float3& a, const float3& b)
{
    return float3(
                  a.y*b.z - a.z*b.y,
                  -(a.x*b.z - a.z*b.x),
                  a.x*b.y - a.y*b.x
                  );
}
#endif // #else of #if DO_FLOAT3_WITH_SIMD

VM_INLINE float length(float3 v) { return sqrtf(dot(v, v)); }
VM_INLINE float sqLength(float3 v) { return dot(v, v); }
VM_INLINE float3 normalize(float3 v) { return v * (1.0f / length(v)); }
VM_INLINE float3 lerp(float3 a, float3 b, float t) { return a + (b-a)*t; }


inline void AssertUnit(float3 v)
{
    assert(fabsf(sqLength(v) - 1.0f) < 0.01f);
}

inline float3 reflect(float3 v, float3 n)
{
    return v - 2*dot(v,n)*n;
}

inline bool refract(float3 v, float3 n, float nint, float3& outRefracted)
{
    AssertUnit(v);
    float dt = dot(v, n);
    float discr = 1.0f - nint*nint*(1-dt*dt);
    if (discr > 0)
    {
        outRefracted = nint * (v - n*dt) - n*sqrtf(discr);
        return true;
    }
    return false;
}
inline float schlick(float cosine, float ri)
{
    float r0 = (1-ri) / (1+ri);
    r0 = r0*r0;
    return r0 + (1-r0)*powf(1-cosine, 5);
}

struct Ray
{
    Ray() {}
    Ray(float3 orig_, float3 dir_) : orig(orig_), dir(dir_) { AssertUnit(dir); }

    float3 pointAt(float t) const { return orig + dir * t; }

    float3 orig;
    float3 dir;
};


struct Hit
{
    float3 pos;
    float3 normal;
    float t;
};


struct Sphere
{
    Sphere() : radius(1.0f), invRadius(0.0f) {}
    Sphere(float3 center_, float radius_) : center(center_), radius(radius_), invRadius(0.0f) {}

    void UpdateDerivedData() { invRadius = 1.0f/radius; }

    float3 center;
    float radius;
    float invRadius;
};


// data for all spheres in a "structure of arrays" layout
struct SpheresSoA
{
    SpheresSoA(int c)
    {
        count = c;
        // we'll be processing spheres in kSimdWidth chunks, so make sure to allocate
        // enough space
        simdCount = (c + (kSimdWidth - 1)) / kSimdWidth * kSimdWidth;
        centerX = new float[simdCount];
        centerY = new float[simdCount];
        centerZ = new float[simdCount];
        sqRadius = new float[simdCount];
        invRadius = new float[simdCount];
        // set all data to "impossible sphere" state
        for (int i = count; i < simdCount; ++i)
        {
            centerX[i] = centerY[i] = centerZ[i] = 10000.0f;
            sqRadius[i] = 0.0f;
            invRadius[i] = 0.0f;
        }
    }
    ~SpheresSoA()
    {
        delete[] centerX;
        delete[] centerY;
        delete[] centerZ;
        delete[] sqRadius;
        delete[] invRadius;
    }
    float* centerX;
    float* centerY;
    float* centerZ;
    float* sqRadius;
    float* invRadius;
    int simdCount;
    int count;
};


int HitSpheres(const Ray& r, const SpheresSoA& spheres, float tMin, float tMax, Hit& outHit);

float RandomFloat01(uint32_t& state);
float3 RandomInUnitDisk(uint32_t& state);
float3 RandomInUnitSphere(uint32_t& state);
float3 RandomUnitVector(uint32_t& state);

struct Camera
{
    Camera() {}
    // vfov is top to bottom in degrees
    Camera(const float3& lookFrom, const float3& lookAt, const float3& vup, float vfov, float aspect, float aperture, float focusDist)
    {
        lensRadius = aperture / 2;
        float theta = vfov*kPI/180;
        float halfHeight = tanf(theta/2);
        float halfWidth = aspect * halfHeight;
        origin = lookFrom;
        w = normalize(lookFrom - lookAt);
        u = normalize(cross(vup, w));
        v = cross(w, u);
        lowerLeftCorner = origin - halfWidth*focusDist*u - halfHeight*focusDist*v - focusDist*w;
        horizontal = 2*halfWidth*focusDist*u;
        vertical = 2*halfHeight*focusDist*v;
    }

    Ray GetRay(float s, float t, uint32_t& state) const
    {
        float3 rd = lensRadius * RandomInUnitDisk(state);
        float3 offset = u * rd.getX() + v * rd.getY();
        return Ray(origin + offset, normalize(lowerLeftCorner + s*horizontal + t*vertical - origin - offset));
    }

    float3 origin;
    float3 lowerLeftCorner;
    float3 horizontal;
    float3 vertical;
    float3 u, v, w;
    float lensRadius;
};

