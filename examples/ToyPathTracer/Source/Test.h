#pragma once
#include <stdint.h>

enum TestFlags
{
    kFlagAnimate = (1 << 0),
    kFlagProgressive = (1 << 1),
};

void InitializeTest();
void ShutdownTest();

void UpdateTest(float time, int frameCount, int screenWidth, int screenHeight, unsigned testFlags);
void DrawTest(float time, int frameCount, int screenWidth, int screenHeight, float* backbuffer, int& outRayCount, unsigned testFlags);

void GetObjectCount(int& outCount, int& outObjectSize, int& outMaterialSize, int& outCamSize);
void GetSceneDesc(void* outObjects, void* outMaterials, void* outCam, void* outEmissives, int* outEmissiveCount);
