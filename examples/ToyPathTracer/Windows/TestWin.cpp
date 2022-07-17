#include <stdint.h>
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <d3d11_1.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <algorithm>

#include "../Source/Config.h"
#include "../Source/Maths.h"
#include "../Source/Test.h"
#include "CompiledVertexShader.h"
#include "CompiledPixelShader.h"

#include "../../../public/tracy/Tracy.hpp"
#include "../../../public/tracy/TracyD3D11.hpp"

static HINSTANCE g_HInstance;
static HWND g_Wnd;

ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

static HRESULT InitD3DDevice();
static void ShutdownD3DDevice();
static void RenderFrame();

static float* g_Backbuffer;

static D3D_FEATURE_LEVEL g_D3D11FeatureLevel = D3D_FEATURE_LEVEL_11_0;
static ID3D11Device* g_D3D11Device = nullptr;
static ID3D11DeviceContext* g_D3D11Ctx = nullptr;
static IDXGISwapChain* g_D3D11SwapChain = nullptr;
static ID3D11RenderTargetView* g_D3D11RenderTarget = nullptr;
static ID3D11VertexShader* g_VertexShader;
static ID3D11PixelShader* g_PixelShader;
static ID3D11Texture2D *g_BackbufferTexture, *g_BackbufferTexture2;
static ID3D11ShaderResourceView *g_BackbufferSRV, *g_BackbufferSRV2;
static ID3D11UnorderedAccessView *g_BackbufferUAV, *g_BackbufferUAV2;
static ID3D11SamplerState* g_SamplerLinear;
static ID3D11RasterizerState* g_RasterState;
static int g_BackbufferIndex;
static tracy::D3D11Ctx *g_tracyCtx;


#if DO_COMPUTE_GPU
#include "CompiledComputeShader.h"
struct ComputeParams
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
static ID3D11ComputeShader* g_ComputeShader;
static ID3D11Buffer* g_DataSpheres;     static ID3D11ShaderResourceView* g_SRVSpheres;
static ID3D11Buffer* g_DataMaterials;   static ID3D11ShaderResourceView* g_SRVMaterials;
static ID3D11Buffer* g_DataParams;      static ID3D11ShaderResourceView* g_SRVParams;
static ID3D11Buffer* g_DataEmissives;   static ID3D11ShaderResourceView* g_SRVEmissives;
static ID3D11Buffer* g_DataCounter;     static ID3D11UnorderedAccessView* g_UAVCounter;
static int g_SphereCount, g_ObjSize, g_MatSize;
static ID3D11Query *g_QueryBegin, *g_QueryEnd, *g_QueryDisjoint;
#endif // #if DO_COMPUTE_GPU

int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE, _In_ LPWSTR, _In_ int nCmdShow)
{
    g_Backbuffer = new float[kBackbufferWidth * kBackbufferHeight * 4];
    memset(g_Backbuffer, 0, kBackbufferWidth * kBackbufferHeight * 4 * sizeof(g_Backbuffer[0]));

    InitializeTest();

    MyRegisterClass(hInstance);
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    if (FAILED(InitD3DDevice()))
    {
        ShutdownD3DDevice();
        return 0;
    }

    g_D3D11Device->CreateVertexShader(g_VSBytecode, ARRAYSIZE(g_VSBytecode), NULL, &g_VertexShader);
    g_D3D11Device->CreatePixelShader(g_PSBytecode, ARRAYSIZE(g_PSBytecode), NULL, &g_PixelShader);
#if DO_COMPUTE_GPU
    g_D3D11Device->CreateComputeShader(g_CSBytecode, ARRAYSIZE(g_CSBytecode), NULL, &g_ComputeShader);
#endif

    D3D11_TEXTURE2D_DESC texDesc = {};
    texDesc.Width = kBackbufferWidth;
    texDesc.Height = kBackbufferHeight;
    texDesc.MipLevels = 1;
    texDesc.ArraySize = 1;
    texDesc.Format = DXGI_FORMAT_R32G32B32A32_FLOAT;
    texDesc.SampleDesc.Count = 1;
    texDesc.SampleDesc.Quality = 0;
#if DO_COMPUTE_GPU
    texDesc.Usage = D3D11_USAGE_DEFAULT;
    texDesc.BindFlags = D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_UNORDERED_ACCESS;
    texDesc.CPUAccessFlags = 0;
#else
    texDesc.Usage = D3D11_USAGE_DYNAMIC;
    texDesc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    texDesc.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
#endif
    texDesc.MiscFlags = 0;
    g_D3D11Device->CreateTexture2D(&texDesc, NULL, &g_BackbufferTexture);
    g_D3D11Device->CreateTexture2D(&texDesc, NULL, &g_BackbufferTexture2);

    D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
    srvDesc.Format = texDesc.Format;
    srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
    srvDesc.Texture2D.MipLevels = 1;
    srvDesc.Texture2D.MostDetailedMip = 0;
    g_D3D11Device->CreateShaderResourceView(g_BackbufferTexture, &srvDesc, &g_BackbufferSRV);
    g_D3D11Device->CreateShaderResourceView(g_BackbufferTexture2, &srvDesc, &g_BackbufferSRV2);

    D3D11_SAMPLER_DESC smpDesc = {};
    smpDesc.Filter = D3D11_FILTER_MIN_MAG_LINEAR_MIP_POINT;
    smpDesc.AddressU = smpDesc.AddressV = smpDesc.AddressW = D3D11_TEXTURE_ADDRESS_CLAMP;
    g_D3D11Device->CreateSamplerState(&smpDesc, &g_SamplerLinear);

    D3D11_RASTERIZER_DESC rasterDesc = {};
    rasterDesc.FillMode = D3D11_FILL_SOLID;
    rasterDesc.CullMode = D3D11_CULL_NONE;
    g_D3D11Device->CreateRasterizerState(&rasterDesc, &g_RasterState);

#if DO_COMPUTE_GPU
    D3D11_UNORDERED_ACCESS_VIEW_DESC uavDesc = {};

    int camSize;
    GetObjectCount(g_SphereCount, g_ObjSize, g_MatSize, camSize);
    assert(g_ObjSize == 20);
    assert(g_MatSize == 36);
    assert(camSize == 88);
    D3D11_BUFFER_DESC bdesc = {};
    bdesc.ByteWidth = g_SphereCount * g_ObjSize;
    bdesc.Usage = D3D11_USAGE_DEFAULT;
    bdesc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    bdesc.CPUAccessFlags = 0;
    bdesc.MiscFlags = D3D11_RESOURCE_MISC_BUFFER_STRUCTURED;
    bdesc.StructureByteStride = g_ObjSize;
    g_D3D11Device->CreateBuffer(&bdesc, NULL, &g_DataSpheres);
    srvDesc.Format = DXGI_FORMAT_UNKNOWN;
    srvDesc.ViewDimension = D3D11_SRV_DIMENSION_BUFFER;
    srvDesc.Buffer.FirstElement = 0;
    srvDesc.Buffer.NumElements = g_SphereCount;
    g_D3D11Device->CreateShaderResourceView(g_DataSpheres, &srvDesc, &g_SRVSpheres);

    bdesc.ByteWidth = g_SphereCount * g_MatSize;
    bdesc.StructureByteStride = g_MatSize;
    g_D3D11Device->CreateBuffer(&bdesc, NULL, &g_DataMaterials);
    srvDesc.Buffer.NumElements = g_SphereCount;
    g_D3D11Device->CreateShaderResourceView(g_DataMaterials, &srvDesc, &g_SRVMaterials);

    bdesc.ByteWidth = sizeof(ComputeParams);
    bdesc.StructureByteStride = sizeof(ComputeParams);
    g_D3D11Device->CreateBuffer(&bdesc, NULL, &g_DataParams);
    srvDesc.Buffer.NumElements = 1;
    g_D3D11Device->CreateShaderResourceView(g_DataParams, &srvDesc, &g_SRVParams);

    bdesc.ByteWidth = g_SphereCount * 4;
    bdesc.StructureByteStride = 4;
    g_D3D11Device->CreateBuffer(&bdesc, NULL, &g_DataEmissives);
    srvDesc.Buffer.NumElements = g_SphereCount;
    g_D3D11Device->CreateShaderResourceView(g_DataEmissives, &srvDesc, &g_SRVEmissives);

    bdesc.ByteWidth = 4;
    bdesc.BindFlags |= D3D11_BIND_UNORDERED_ACCESS;
    bdesc.MiscFlags = D3D11_RESOURCE_MISC_BUFFER_ALLOW_RAW_VIEWS;
    bdesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    g_D3D11Device->CreateBuffer(&bdesc, NULL, &g_DataCounter);
    uavDesc.Format = DXGI_FORMAT_R32_TYPELESS;
    uavDesc.ViewDimension = D3D11_UAV_DIMENSION_BUFFER;
    uavDesc.Buffer.FirstElement = 0;
    uavDesc.Buffer.NumElements = 1;
    uavDesc.Buffer.Flags = D3D11_BUFFER_UAV_FLAG_RAW;
    g_D3D11Device->CreateUnorderedAccessView(g_DataCounter, &uavDesc, &g_UAVCounter);

    uavDesc.Format = DXGI_FORMAT_R32G32B32A32_FLOAT;
    uavDesc.ViewDimension = D3D11_UAV_DIMENSION_TEXTURE2D;
    uavDesc.Texture2D.MipSlice = 0;
    g_D3D11Device->CreateUnorderedAccessView(g_BackbufferTexture, &uavDesc, &g_BackbufferUAV);
    g_D3D11Device->CreateUnorderedAccessView(g_BackbufferTexture2, &uavDesc, &g_BackbufferUAV2);

    D3D11_QUERY_DESC qDesc = {};
    qDesc.Query = D3D11_QUERY_TIMESTAMP;
    g_D3D11Device->CreateQuery(&qDesc, &g_QueryBegin);
    g_D3D11Device->CreateQuery(&qDesc, &g_QueryEnd);
    qDesc.Query = D3D11_QUERY_TIMESTAMP_DISJOINT;
    g_D3D11Device->CreateQuery(&qDesc, &g_QueryDisjoint);
#endif // #if DO_COMPUTE_GPU


    static int framesLeft = 10;

    // Main message loop
    MSG msg = { 0 };
    while (msg.message != WM_QUIT)
    {
        if (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        else
        {
            RenderFrame();
            TracyD3D11Collect(g_tracyCtx);
            if( --framesLeft == 0 ) break;
        }
    }

    ShutdownTest();
    ShutdownD3DDevice();

    return (int) msg.wParam;
}


ATOM MyRegisterClass(HINSTANCE hInstance)
{
    ZoneScoped;

    WNDCLASSEXW wcex;
    memset(&wcex, 0, sizeof(wcex));
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszClassName  = L"TestClass";
    return RegisterClassExW(&wcex);
}

BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
    ZoneScoped;

    g_HInstance = hInstance;
    RECT rc = { 0, 0, kBackbufferWidth, kBackbufferHeight };
    DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    AdjustWindowRect(&rc, style, FALSE);
    HWND hWnd = CreateWindowW(L"TestClass", L"Test", style, CW_USEDEFAULT, CW_USEDEFAULT, rc.right-rc.left, rc.bottom-rc.top, nullptr, nullptr, hInstance, nullptr);
    if (!hWnd)
        return FALSE;
    g_Wnd = hWnd;
    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);
    return TRUE;
}

static uint64_t s_Time;
static int s_Count;
static char s_Buffer[200];
static unsigned s_Flags = kFlagProgressive;
static int s_FrameCount = 0;


static void RenderFrame()
{
    ZoneScoped;
    TracyD3D11Zone(g_tracyCtx, "RenderFrame");

    LARGE_INTEGER time1;

#if DO_COMPUTE_GPU
    QueryPerformanceCounter(&time1);
    float t = float(clock()) / CLOCKS_PER_SEC;
    UpdateTest(t, s_FrameCount, kBackbufferWidth, kBackbufferHeight, s_Flags);

    g_BackbufferIndex = 1 - g_BackbufferIndex;
    void* dataSpheres = alloca(g_SphereCount * g_ObjSize);
    void* dataMaterials = alloca(g_SphereCount * g_MatSize);
    void* dataEmissives = alloca(g_SphereCount * 4);
    ComputeParams dataParams;
    GetSceneDesc(dataSpheres, dataMaterials, &dataParams.cam, dataEmissives, &dataParams.emissiveCount);

    dataParams.sphereCount = g_SphereCount;
    dataParams.screenWidth = kBackbufferWidth;
    dataParams.screenHeight = kBackbufferHeight;
    dataParams.frames = s_FrameCount;
    dataParams.invWidth = 1.0f / kBackbufferWidth;
    dataParams.invHeight = 1.0f / kBackbufferHeight;
    float lerpFac = float(s_FrameCount) / float(s_FrameCount + 1);
    if (s_Flags & kFlagAnimate)
        lerpFac *= DO_ANIMATE_SMOOTHING;
    if (!(s_Flags & kFlagProgressive))
        lerpFac = 0;
    dataParams.lerpFac = lerpFac;

    g_D3D11Ctx->UpdateSubresource(g_DataSpheres, 0, NULL, dataSpheres, 0, 0);
    g_D3D11Ctx->UpdateSubresource(g_DataMaterials, 0, NULL, dataMaterials, 0, 0);
    g_D3D11Ctx->UpdateSubresource(g_DataParams, 0, NULL, &dataParams, 0, 0);
    g_D3D11Ctx->UpdateSubresource(g_DataEmissives, 0, NULL, dataEmissives, 0, 0);

    ID3D11ShaderResourceView* srvs[] = {
        g_BackbufferIndex == 0 ? g_BackbufferSRV2 : g_BackbufferSRV,
        g_SRVSpheres,
        g_SRVMaterials,
        g_SRVParams,
        g_SRVEmissives
    };
    g_D3D11Ctx->CSSetShaderResources(0, ARRAYSIZE(srvs), srvs);
    ID3D11UnorderedAccessView* uavs[] = {
        g_BackbufferIndex == 0 ? g_BackbufferUAV : g_BackbufferUAV2,
        g_UAVCounter
    };
    g_D3D11Ctx->CSSetUnorderedAccessViews(0, ARRAYSIZE(uavs), uavs, NULL);
    g_D3D11Ctx->CSSetShader(g_ComputeShader, NULL, 0);
    g_D3D11Ctx->Begin(g_QueryDisjoint);
    g_D3D11Ctx->End(g_QueryBegin);
    g_D3D11Ctx->Dispatch(kBackbufferWidth/kCSGroupSizeX, kBackbufferHeight/kCSGroupSizeY, 1);
    g_D3D11Ctx->End(g_QueryEnd);
    uavs[0] = NULL;
    g_D3D11Ctx->CSSetUnorderedAccessViews(0, ARRAYSIZE(uavs), uavs, NULL);
    ++s_FrameCount;

#else
    QueryPerformanceCounter(&time1);
    float t = float(clock()) / CLOCKS_PER_SEC;
    static size_t s_RayCounter = 0;
    int rayCount;
    UpdateTest(t, s_FrameCount, kBackbufferWidth, kBackbufferHeight, s_Flags);
    DrawTest(t, s_FrameCount, kBackbufferWidth, kBackbufferHeight, g_Backbuffer, rayCount, s_Flags);
    s_FrameCount++;
    s_RayCounter += rayCount;
    LARGE_INTEGER time2;
    QueryPerformanceCounter(&time2);
    uint64_t dt = time2.QuadPart - time1.QuadPart;
    ++s_Count;
    s_Time += dt;
    if (s_Count > 10)
    {
        LARGE_INTEGER frequency;
        QueryPerformanceFrequency(&frequency);

        double s = double(s_Time) / double(frequency.QuadPart) / s_Count;
        sprintf_s(s_Buffer, sizeof(s_Buffer), "%.2fms (%.1f FPS) %.1fMrays/s %.2fMrays/frame frames %i\n", s * 1000.0f, 1.f / s, s_RayCounter / s_Count / s * 1.0e-6f, s_RayCounter / s_Count * 1.0e-6f, s_FrameCount);
        SetWindowTextA(g_Wnd, s_Buffer);
        OutputDebugStringA(s_Buffer);
        s_Count = 0;
        s_Time = 0;
        s_RayCounter = 0;
    }

    D3D11_MAPPED_SUBRESOURCE mapped;
    g_D3D11Ctx->Map(g_BackbufferTexture, 0, D3D11_MAP_WRITE_DISCARD, 0, &mapped);
    const uint8_t* src = (const uint8_t*)g_Backbuffer;
    uint8_t* dst = (uint8_t*)mapped.pData;
    for (int y = 0; y < kBackbufferHeight; ++y)
    {
        memcpy(dst, src, kBackbufferWidth * 16);
        src += kBackbufferWidth * 16;
        dst += mapped.RowPitch;
    }
    g_D3D11Ctx->Unmap(g_BackbufferTexture, 0);
#endif

    g_D3D11Ctx->VSSetShader(g_VertexShader, NULL, 0);
    g_D3D11Ctx->PSSetShader(g_PixelShader, NULL, 0);
    g_D3D11Ctx->PSSetShaderResources(0, 1, g_BackbufferIndex == 0 ? &g_BackbufferSRV : &g_BackbufferSRV2);
    g_D3D11Ctx->PSSetSamplers(0, 1, &g_SamplerLinear);
    g_D3D11Ctx->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    g_D3D11Ctx->RSSetState(g_RasterState);
    g_D3D11Ctx->Draw(3, 0);
    g_D3D11SwapChain->Present(0, 0);

    FrameMark;

#if DO_COMPUTE_GPU
    g_D3D11Ctx->End(g_QueryDisjoint);

    // get GPU times
    while (g_D3D11Ctx->GetData(g_QueryDisjoint, NULL, 0, 0) == S_FALSE) { Sleep(0); }
    D3D10_QUERY_DATA_TIMESTAMP_DISJOINT tsDisjoint;
    g_D3D11Ctx->GetData(g_QueryDisjoint, &tsDisjoint, sizeof(tsDisjoint), 0);
    if (!tsDisjoint.Disjoint)
    {
        UINT64 tsBegin, tsEnd;
        // Note: on some GPUs/drivers, even when the disjoint query above already said "yeah I have data",
        // might still not return "I have data" for timestamp queries before it.
        while (g_D3D11Ctx->GetData(g_QueryBegin, &tsBegin, sizeof(tsBegin), 0) == S_FALSE) { Sleep(0); }
        while (g_D3D11Ctx->GetData(g_QueryEnd, &tsEnd, sizeof(tsEnd), 0) == S_FALSE) { Sleep(0); }

        float s = float(tsEnd - tsBegin) / float(tsDisjoint.Frequency);

        static uint64_t s_RayCounter;
        D3D11_MAPPED_SUBRESOURCE mapped;
        g_D3D11Ctx->Map(g_DataCounter, 0, D3D11_MAP_READ, 0, &mapped);
        s_RayCounter += *(const int*)mapped.pData;
        g_D3D11Ctx->Unmap(g_DataCounter, 0);
        int zeroCount = 0;
        g_D3D11Ctx->UpdateSubresource(g_DataCounter, 0, NULL, &zeroCount, 0, 0);

        static float s_Time;
        ++s_Count;
        s_Time += s;
        if (s_Count > 150)
        {
            s = s_Time / s_Count;
            sprintf_s(s_Buffer, sizeof(s_Buffer), "%.2fms (%.1f FPS) %.1fMrays/s %.2fMrays/frame frames %i\n", s * 1000.0f, 1.f / s, s_RayCounter / s_Count / s * 1.0e-6f, s_RayCounter / s_Count * 1.0e-6f, s_FrameCount);
            SetWindowTextA(g_Wnd, s_Buffer);
            s_Count = 0;
            s_Time = 0;
            s_RayCounter = 0;
        }

    }
#endif // #if DO_COMPUTE_GPU
}


LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            EndPaint(hWnd, &ps);
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    case WM_CHAR:
        if (wParam == 'a')
            s_Flags = s_Flags ^ kFlagAnimate;
        if (wParam == 'p')
        {
            s_Flags = s_Flags ^ kFlagProgressive;
            s_FrameCount = 0;
        }
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}


static HRESULT InitD3DDevice()
{
    ZoneScoped;

    HRESULT hr = S_OK;

    RECT rc;
    GetClientRect(g_Wnd, &rc);
    UINT width = rc.right - rc.left;
    UINT height = rc.bottom - rc.top;

    UINT createDeviceFlags = 0;
#ifdef _DEBUG
    createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
#endif

    D3D_FEATURE_LEVEL featureLevels[] =
    {
        D3D_FEATURE_LEVEL_11_0,
    };
    UINT numFeatureLevels = ARRAYSIZE(featureLevels);
    hr = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags, featureLevels, numFeatureLevels, D3D11_SDK_VERSION, &g_D3D11Device, &g_D3D11FeatureLevel, &g_D3D11Ctx);
    if (FAILED(hr))
        return hr;

    // Get DXGI factory
    IDXGIFactory1* dxgiFactory = nullptr;
    {
        IDXGIDevice* dxgiDevice = nullptr;
        hr = g_D3D11Device->QueryInterface(__uuidof(IDXGIDevice), reinterpret_cast<void**>(&dxgiDevice));
        if (SUCCEEDED(hr))
        {
            IDXGIAdapter* adapter = nullptr;
            hr = dxgiDevice->GetAdapter(&adapter);
            if (SUCCEEDED(hr))
            {
                hr = adapter->GetParent(__uuidof(IDXGIFactory1), reinterpret_cast<void**>(&dxgiFactory));
                adapter->Release();
            }
            dxgiDevice->Release();
        }
    }
    if (FAILED(hr))
        return hr;

    // Create swap chain
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 1;
    sd.BufferDesc.Width = width;
    sd.BufferDesc.Height = height;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = g_Wnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    hr = dxgiFactory->CreateSwapChain(g_D3D11Device, &sd, &g_D3D11SwapChain);

    // Prevent Alt-Enter
    dxgiFactory->MakeWindowAssociation(g_Wnd, DXGI_MWA_NO_ALT_ENTER);
    dxgiFactory->Release();

    if (FAILED(hr))
        return hr;

    // RTV
    ID3D11Texture2D* pBackBuffer = nullptr;
    hr = g_D3D11SwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), reinterpret_cast<void**>(&pBackBuffer));
    if (FAILED(hr))
        return hr;
    hr = g_D3D11Device->CreateRenderTargetView(pBackBuffer, nullptr, &g_D3D11RenderTarget);
    pBackBuffer->Release();
    if (FAILED(hr))
        return hr;

    g_D3D11Ctx->OMSetRenderTargets(1, &g_D3D11RenderTarget, nullptr);

    // Viewport
    D3D11_VIEWPORT vp;
    vp.Width = (float)width;
    vp.Height = (float)height;
    vp.MinDepth = 0.0f;
    vp.MaxDepth = 1.0f;
    vp.TopLeftX = 0;
    vp.TopLeftY = 0;
    g_D3D11Ctx->RSSetViewports(1, &vp);

    g_tracyCtx = TracyD3D11Context(g_D3D11Device, g_D3D11Ctx);
    const char* tracyD3D11CtxName = "D3D11";
    TracyD3D11ContextName(g_tracyCtx, tracyD3D11CtxName, (uint16_t)strlen(tracyD3D11CtxName));

    return S_OK;
}

static void ShutdownD3DDevice()
{
    ZoneScoped;

    if (g_tracyCtx) TracyD3D11Destroy(g_tracyCtx);

    if (g_D3D11Ctx) g_D3D11Ctx->ClearState();

    if (g_D3D11RenderTarget) g_D3D11RenderTarget->Release();
    if (g_D3D11SwapChain) g_D3D11SwapChain->Release();
    if (g_D3D11Ctx) g_D3D11Ctx->Release();
    if (g_D3D11Device) g_D3D11Device->Release();
}
