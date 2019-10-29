#include "../Source/Config.h"

inline uint RNG(inout uint state)
{
    uint x = state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 15;
    state = x;
    return x;
}

float RandomFloat01(inout uint state)
{
    return (RNG(state) & 0xFFFFFF) / 16777216.0f;
}

float3 RandomInUnitDisk(inout uint state)
{
    float a = RandomFloat01(state) * 2.0f * 3.1415926f;
    float2 xy = float2(cos(a), sin(a));
    xy *= sqrt(RandomFloat01(state));
    return float3(xy, 0);
}
float3 RandomInUnitSphere(inout uint state)
{
    float z = RandomFloat01(state) * 2.0f - 1.0f;
    float t = RandomFloat01(state) * 2.0f * 3.1415926f;
    float r = sqrt(max(0.0, 1.0f - z * z));
    float x = r * cos(t);
    float y = r * sin(t);
    float3 res = float3(x, y, z);
    res *= pow(RandomFloat01(state), 1.0 / 3.0);
    return res;
}
float3 RandomUnitVector(inout uint state)
{
    float z = RandomFloat01(state) * 2.0f - 1.0f;
    float a = RandomFloat01(state) * 2.0f * 3.1415926f;
    float r = sqrt(1.0f - z * z);
    float x = r * cos(a);
    float y = r * sin(a);
    return float3(x, y, z);
}



struct Ray
{
    float3 orig;
    float3 dir;
};
Ray MakeRay(float3 orig_, float3 dir_) { Ray r; r.orig = orig_; r.dir = dir_; return r; }
float3 RayPointAt(Ray r, float t) { return r.orig + r.dir * t; }


inline bool refract(float3 v, float3 n, float nint, out float3 outRefracted)
{
    float dt = dot(v, n);
    float discr = 1.0f - nint * nint*(1 - dt * dt);
    if (discr > 0)
    {
        outRefracted = nint * (v - n * dt) - n * sqrt(discr);
        return true;
    }
    return false;
}
inline float schlick(float cosine, float ri)
{
    float r0 = (1 - ri) / (1 + ri);
    r0 = r0 * r0;
    // note: saturate to guard against possible tiny negative numbers
    return r0 + (1 - r0)*pow(saturate(1 - cosine), 5);
}

struct Hit
{
    float3 pos;
    float3 normal;
    float t;
};

struct Sphere
{
    float3 center;
    float radius;
    float invRadius;
};

#define MatLambert 0
#define MatMetal 1
#define MatDielectric 2

struct Material
{
    int type;
    float3 albedo;
    float3 emissive;
    float roughness;
    float ri;
};

groupshared Sphere s_GroupSpheres[kCSMaxObjects];
groupshared Material s_GroupMaterials[kCSMaxObjects];
groupshared int s_GroupEmissives[kCSMaxObjects];


struct Camera
{
    float3 origin;
    float3 lowerLeftCorner;
    float3 horizontal;
    float3 vertical;
    float3 u, v, w;
    float lensRadius;
};

Ray CameraGetRay(Camera cam, float s, float t, inout uint state)
{
    float3 rd = cam.lensRadius * RandomInUnitDisk(state);
    float3 offset = cam.u * rd.x + cam.v * rd.y;
    return MakeRay(cam.origin + offset, normalize(cam.lowerLeftCorner + s * cam.horizontal + t * cam.vertical - cam.origin - offset));
}


int HitSpheres(Ray r, int sphereCount, float tMin, float tMax, inout Hit outHit)
{
    float hitT = tMax;
    int id = -1;
    for (int i = 0; i < sphereCount; ++i)
    {
        Sphere s = s_GroupSpheres[i];
        float3 co = s.center - r.orig;
        float nb = dot(co, r.dir);
        float c = dot(co, co) - s.radius*s.radius;
        float discr = nb * nb - c;
        if (discr > 0)
        {
            float discrSq = sqrt(discr);

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
        outHit.pos = RayPointAt(r, hitT);
        outHit.normal = (outHit.pos - s_GroupSpheres[id].center) * s_GroupSpheres[id].invRadius;
        outHit.t = hitT;
    }
    return id;
}

struct Params
{
    Camera cam;
    int sphereCount;
    int screenWidth;
    int screenHeight;
    int frames;
    float invWidth;
    float invHeight;
    float lerpFac;
    int emissiveCount;
};


#define kMinT 0.001f
#define kMaxT 1.0e7f
#define kMaxDepth 10


static int HitWorld(int sphereCount, Ray r, float tMin, float tMax, inout Hit outHit)
{
    return HitSpheres(r, sphereCount, tMin, tMax, outHit);
}


static bool Scatter(int sphereCount, int emissiveCount, int matID, Ray r_in, Hit rec, out float3 attenuation, out Ray scattered, out float3 outLightE, inout int inoutRayCount, inout uint state)
{
    outLightE = float3(0, 0, 0);
    Material mat = s_GroupMaterials[matID];
    if (mat.type == MatLambert)
    {
        // random point on unit sphere that is tangent to the hit point
        float3 target = rec.pos + rec.normal + RandomUnitVector(state);
        scattered = MakeRay(rec.pos, normalize(target - rec.pos));
        attenuation = mat.albedo;

        // sample lights
#if DO_LIGHT_SAMPLING
        for (int j = 0; j < emissiveCount; ++j)
        {
            int i = s_GroupEmissives[j];
            if (matID == i)
                continue; // skip self
            Material smat = s_GroupMaterials[i];
            Sphere s = s_GroupSpheres[i];

            // create a random direction towards sphere
            // coord system for sampling: sw, su, sv
            float3 sw = normalize(s.center - rec.pos);
            float3 su = normalize(cross(abs(sw.x)>0.01f ? float3(0, 1, 0) : float3(1, 0, 0), sw));
            float3 sv = cross(sw, su);
            // sample sphere by solid angle
            float cosAMax = sqrt(1.0f - s.radius*s.radius / dot(rec.pos - s.center, rec.pos - s.center));
            float eps1 = RandomFloat01(state), eps2 = RandomFloat01(state);
            float cosA = 1.0f - eps1 + eps1 * cosAMax;
            float sinA = sqrt(1.0f - cosA * cosA);
            float phi = 2 * 3.1415926 * eps2;
            float3 l = su * cos(phi) * sinA + sv * sin(phi) * sinA + sw * cosA;

            // shoot shadow ray
            Hit lightHit;
            ++inoutRayCount;
            int hitID = HitWorld(sphereCount, MakeRay(rec.pos, l), kMinT, kMaxT, lightHit);
            if (hitID == i)
            {
                float omega = 2 * 3.1415926 * (1 - cosAMax);

                float3 rdir = r_in.dir;
                float3 nl = dot(rec.normal, rdir) < 0 ? rec.normal : -rec.normal;
                outLightE += (mat.albedo * smat.emissive) * (max(0.0f, dot(l, nl)) * omega / 3.1415926);
            }
        }
#endif
        return true;
    }
    else if (mat.type == MatMetal)
    {
        float3 refl = reflect(r_in.dir, rec.normal);
        // reflected ray, and random inside of sphere based on roughness
        float roughness = mat.roughness;
#if DO_MITSUBA_COMPARE
        roughness = 0; // until we get better BRDF for metals
#endif
        scattered = MakeRay(rec.pos, normalize(refl + roughness*RandomInUnitSphere(state)));
        attenuation = mat.albedo;
        return dot(scattered.dir, rec.normal) > 0;
    }
    else if (mat.type == MatDielectric)
    {
        float3 outwardN;
        float3 rdir = r_in.dir;
        float3 refl = reflect(rdir, rec.normal);
        float nint;
        attenuation = float3(1, 1, 1);
        float3 refr;
        float reflProb;
        float cosine;
        if (dot(rdir, rec.normal) > 0)
        {
            outwardN = -rec.normal;
            nint = mat.ri;
            cosine = mat.ri * dot(rdir, rec.normal);
        }
        else
        {
            outwardN = rec.normal;
            nint = 1.0f / mat.ri;
            cosine = -dot(rdir, rec.normal);
        }
        if (refract(rdir, outwardN, nint, refr))
        {
            reflProb = schlick(cosine, mat.ri);
        }
        else
        {
            reflProb = 1;
        }
        if (RandomFloat01(state) < reflProb)
            scattered = MakeRay(rec.pos, normalize(refl));
        else
            scattered = MakeRay(rec.pos, normalize(refr));
    }
    else
    {
        attenuation = float3(1, 0, 1);
        scattered = MakeRay(float3(0,0,0), float3(0, 0, 1));
        return false;
    }
    return true;
}

static float3 Trace(int sphereCount, int emissiveCount, Ray r, inout int inoutRayCount, inout uint state)
{
    float3 col = 0;
    float3 curAtten = 1;
    bool doMaterialE = true;
    // GPUs don't support recursion, so do tracing iterations in a loop up to max depth
    for (int depth = 0; depth < kMaxDepth; ++depth)
    {
        Hit rec;
        ++inoutRayCount;
        int id = HitWorld(sphereCount, r, kMinT, kMaxT, rec);
        if (id >= 0)
        {
            Ray scattered;
            float3 attenuation;
            float3 lightE;
            Material mat = s_GroupMaterials[id];
            float3 matE = mat.emissive;
            if (Scatter(sphereCount, emissiveCount, id, r, rec, attenuation, scattered, lightE, inoutRayCount, state))
            {
#if DO_LIGHT_SAMPLING
                if (!doMaterialE) matE = 0;
                doMaterialE = (mat.type != MatLambert);
#endif
                col += curAtten * (matE + lightE);
                curAtten *= attenuation;
                r = scattered;
            }
            else
            {
                col += curAtten * matE;
                break;
            }
        }
        else
        {
            // sky
#if DO_MITSUBA_COMPARE
            col += curAtten * float3(0.15f, 0.21f, 0.3f); // easier compare with Mitsuba's constant environment light
#else
            float3 unitDir = r.dir;
            float t = 0.5f*(unitDir.y + 1.0f);
            float3 skyCol = ((1.0f - t)*float3(1.0f, 1.0f, 1.0f) + t * float3(0.5f, 0.7f, 1.0f)) * 0.3f;
            col += curAtten * skyCol;
#endif
            break;
        }
    }
    return col;
}

Texture2D srcImage : register(t0);
RWTexture2D<float4> dstImage : register(u0);
StructuredBuffer<Sphere> g_Spheres : register(t1);
StructuredBuffer<Material> g_Materials : register(t2);
StructuredBuffer<Params> g_Params : register(t3);
StructuredBuffer<int> g_Emissives : register(t4);
RWByteAddressBuffer g_OutRayCount : register(u1);

[numthreads(kCSGroupSizeX, kCSGroupSizeY, 1)]
void main(uint3 gid : SV_DispatchThreadID, uint3 tid : SV_GroupThreadID)
{
    // First, move scene data (spheres, materials, emissive indices) into group shared
    // memory. Do this in parallel; each thread in group copies its own chunk of data.
    uint threadID = tid.y * kCSGroupSizeX + tid.x;
    uint groupSize = kCSGroupSizeX * kCSGroupSizeY;
    uint objCount = g_Params[0].sphereCount;
    uint myObjCount = (objCount + groupSize - 1) / groupSize;
    uint myObjStart = threadID * myObjCount;
    for (uint io = myObjStart; io < myObjStart + myObjCount; ++io)
    {
        if (io < objCount)
        {
            s_GroupSpheres[io] = g_Spheres[io];
            s_GroupMaterials[io] = g_Materials[io];
        }
        if (io < g_Params[0].emissiveCount)
        {
            s_GroupEmissives[io] = g_Emissives[io];
        }
    }
    GroupMemoryBarrierWithGroupSync();

    int rayCount = 0;
    float3 col = 0;
    Params params = g_Params[0];
    uint rngState = (gid.x * 1973 + gid.y * 9277 + params.frames * 26699) | 1;
    for (int s = 0; s < DO_SAMPLES_PER_PIXEL; s++)
    {
        float u = float(gid.x + RandomFloat01(rngState)) * params.invWidth;
        float v = float(gid.y + RandomFloat01(rngState)) * params.invHeight;
        Ray r = CameraGetRay(params.cam, u, v, rngState);
        col += Trace(params.sphereCount, params.emissiveCount, r, rayCount, rngState);
    }
    col *= 1.0f / float(DO_SAMPLES_PER_PIXEL);

    float3 prev = srcImage.Load(int3(gid.xy,0)).rgb;
    col = lerp(col, prev, params.lerpFac);
    dstImage[gid.xy] = float4(col, 1);

    g_OutRayCount.InterlockedAdd(0, rayCount);
}
