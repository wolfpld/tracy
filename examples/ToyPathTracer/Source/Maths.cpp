#include "Maths.h"
#include <stdlib.h>
#include <stdint.h>

static uint32_t XorShift32(uint32_t& state)
{
    uint32_t x = state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 15;
    state = x;
    return x;
}

float RandomFloat01(uint32_t& state)
{
    return (XorShift32(state) & 0xFFFFFF) / 16777216.0f;
}

float3 RandomInUnitDisk(uint32_t& state)
{
    float3 p;
    do
    {
        p = 2.0 * float3(RandomFloat01(state),RandomFloat01(state),0) - float3(1,1,0);
    } while (dot(p,p) >= 1.0);
    return p;
}

float3 RandomInUnitSphere(uint32_t& state)
{
    float3 p;
    do {
        p = 2.0*float3(RandomFloat01(state),RandomFloat01(state),RandomFloat01(state)) - float3(1,1,1);
    } while (sqLength(p) >= 1.0);
    return p;
}

float3 RandomUnitVector(uint32_t& state)
{
    float z = RandomFloat01(state) * 2.0f - 1.0f;
    float a = RandomFloat01(state) * 2.0f * kPI;
    float r = sqrtf(1.0f - z * z);
    float x = r * cosf(a);
    float y = r * sinf(a);
    return float3(x, y, z);
}


int HitSpheres(const Ray& r, const SpheresSoA& spheres, float tMin, float tMax, Hit& outHit)
{
#if DO_HIT_SPHERES_SIMD
    float4 hitT = float4(tMax);
#if USE_NEON
    int32x4_t id = vdupq_n_s32(-1);
#else
    __m128i id = _mm_set1_epi32(-1);
#endif

#if DO_FLOAT3_WITH_SIMD && !USE_NEON
    float4 rOrigX = SHUFFLE4(r.orig, 0, 0, 0, 0);
    float4 rOrigY = SHUFFLE4(r.orig, 1, 1, 1, 1);
    float4 rOrigZ = SHUFFLE4(r.orig, 2, 2, 2, 2);
    float4 rDirX = SHUFFLE4(r.dir, 0, 0, 0, 0);
    float4 rDirY = SHUFFLE4(r.dir, 1, 1, 1, 1);
    float4 rDirZ = SHUFFLE4(r.dir, 2, 2, 2, 2);
#elif DO_FLOAT3_WITH_SIMD
    float4 rOrigX = splatX(r.orig.m);
    float4 rOrigY = splatY(r.orig.m);
    float4 rOrigZ = splatZ(r.orig.m);
    float4 rDirX = splatX(r.dir.m);
    float4 rDirY = splatY(r.dir.m);
    float4 rDirZ = splatZ(r.dir.m);
#else
    float4 rOrigX = float4(r.orig.x);
    float4 rOrigY = float4(r.orig.y);
    float4 rOrigZ = float4(r.orig.z);
    float4 rDirX = float4(r.dir.x);
    float4 rDirY = float4(r.dir.y);
    float4 rDirZ = float4(r.dir.z);
#endif
    float4 tMin4 = float4(tMin);
#if USE_NEON
    int32x4_t curId = vcombine_u32(vcreate_u32(0ULL | (1ULL<<32)), vcreate_u32(2ULL | (3ULL<<32)));
#else
    __m128i curId = _mm_set_epi32(3, 2, 1, 0);
#endif
    // process 4 spheres at once
    for (int i = 0; i < spheres.simdCount; i += kSimdWidth)
    {
        // load data for 4 spheres
        float4 sCenterX = float4(spheres.centerX + i);
        float4 sCenterY = float4(spheres.centerY + i);
        float4 sCenterZ = float4(spheres.centerZ + i);
        float4 sSqRadius = float4(spheres.sqRadius + i);
        // note: we flip this vector and calculate -b (nb) since that happens to be slightly preferable computationally
        float4 coX = sCenterX - rOrigX;
        float4 coY = sCenterY - rOrigY;
        float4 coZ = sCenterZ - rOrigZ;
        float4 nb = coX * rDirX + coY * rDirY + coZ * rDirZ;
        float4 c = coX * coX + coY * coY + coZ * coZ - sSqRadius;
        float4 discr = nb * nb - c;
        bool4 discrPos = discr > float4(0.0f);
        // if ray hits any of the 4 spheres
        if (any(discrPos))
        {
            float4 discrSq = sqrtf(discr);

            // ray could hit spheres at t0 & t1
            float4 t0 = nb - discrSq;
            float4 t1 = nb + discrSq;

            float4 t = select(t1, t0, t0 > tMin4); // if t0 is above min, take it (since it's the earlier hit); else try t1.
            bool4 msk = discrPos & (t > tMin4) & (t < hitT);
            // if hit, take it
            id = select(id, curId, msk);
            hitT = select(hitT, t, msk);
        }
#if USE_NEON
        curId = vaddq_s32(curId, vdupq_n_s32(kSimdWidth));
#else
        curId = _mm_add_epi32(curId, _mm_set1_epi32(kSimdWidth));
#endif
    }
    // now we have up to 4 hits, find and return closest one
    float minT = hmin(hitT);
    if (minT < tMax) // any actual hits?
    {
        int minMask = mask(hitT == float4(minT));
        if (minMask != 0)
        {
            int id_scalar[4];
            float hitT_scalar[4];
#if USE_NEON
            vst1q_s32(id_scalar, id);
            vst1q_f32(hitT_scalar, hitT.m);
#else
            _mm_storeu_si128((__m128i *)id_scalar, id);
            _mm_storeu_ps(hitT_scalar, hitT.m);
#endif

            // In general, you would do this with a bit scan (first set/trailing zero count).
            // But who cares, it's only 16 options.
            static const int laneId[16] =
            {
                0, 0, 1, 0, // 00xx
                2, 0, 1, 0, // 01xx
                3, 0, 1, 0, // 10xx
                2, 0, 1, 0, // 11xx
            };

            int lane = laneId[minMask];
            int hitId = id_scalar[lane];
            float finalHitT = hitT_scalar[lane];

            outHit.pos = r.pointAt(finalHitT);
            outHit.normal = (outHit.pos - float3(spheres.centerX[hitId], spheres.centerY[hitId], spheres.centerZ[hitId])) * spheres.invRadius[hitId];
            outHit.t = finalHitT;
            return hitId;
        }
    }

    return -1;

#else // #if DO_HIT_SPHERES_SIMD

    float hitT = tMax;
    int id = -1;
    for (int i = 0; i < spheres.count; ++i)
    {
        float coX = spheres.centerX[i] - r.orig.getX();
        float coY = spheres.centerY[i] - r.orig.getY();
        float coZ = spheres.centerZ[i] - r.orig.getZ();
        float nb = coX * r.dir.getX() + coY * r.dir.getY() + coZ * r.dir.getZ();
        float c = coX * coX + coY * coY + coZ * coZ - spheres.sqRadius[i];
        float discr = nb * nb - c;
        if (discr > 0)
        {
            float discrSq = sqrtf(discr);

            // Try earlier t
            float t = nb - discrSq;
            if (t <= tMin) // before min, try later t!
                t = nb + discrSq;

            if (t > tMin && t < hitT)
            {
                id = i;
                hitT = t;
            }
        }
    }
    if (id != -1)
    {
        outHit.pos = r.pointAt(hitT);
        outHit.normal = (outHit.pos - float3(spheres.centerX[id], spheres.centerY[id], spheres.centerZ[id])) * spheres.invRadius[id];
        outHit.t = hitT;
        return id;
    }
    else
        return -1;
#endif // #else of #if DO_HIT_SPHERES_SIMD
}
