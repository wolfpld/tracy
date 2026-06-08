#ifndef __TRACY_ETW_COMPAT_H__
#define __TRACY_ETW_COMPAT_H__

// Compatibility definitions for older Windows SDKs and MinGW-w64 which lacks some ETW types
// present in Microsoft's Windows SDK

#ifdef __MINGW32__

// CONTROLTRACE_ID - ETW trace session handle type
typedef ULONG64 CONTROLTRACE_ID;

// PROCESSTRACE_HANDLE - ETW process trace handle type
// MinGW defines INVALID_PROCESSTRACE_HANDLE but not the type itself
#ifndef PROCESSTRACE_HANDLE
#define PROCESSTRACE_HANDLE TRACEHANDLE
#endif

// EVENT_FILTER_EVENT_ID struct for event filtering
typedef struct _EVENT_FILTER_EVENT_ID {
    BOOLEAN FilterIn;
    UCHAR Reserved;
    USHORT Count;
    USHORT Events[ANYSIZE_ARRAY];
} EVENT_FILTER_EVENT_ID, *PEVENT_FILTER_EVENT_ID;

// Event filter type constants
#define EVENT_FILTER_TYPE_EVENT_ID (0x80000200) // Event IDs.

// Enable property constants
#define EVENT_ENABLE_PROPERTY_IGNORE_KEYWORD_0 (0x00000010)

// System provider GUIDs
// MinGW's DEFINE_GUID only declares the GUID, we need to define it with actual storage
// Using GUID format: {l, w1, w2, d1, d2, d3, d4, d5, d6, d7, d8} where d1-d8 are bytes
static const GUID SystemProcessProviderGuid = { 0x151f55dc, 0x467d, 0x471f, { 0x83, 0xb5, 0x5f, 0x88, 0x9d, 0x46, 0xff, 0x66 } };
static const GUID SystemProfileProviderGuid = { 0xbfeb0324, 0x1cee, 0x496f, { 0xa4, 0x9, 0x2a, 0xc2, 0xb4, 0x8a, 0x63, 0x22 } };
static const GUID SystemSchedulerProviderGuid = { 0x599a2a76, 0x4d91, 0x4910, { 0x9a, 0xc7, 0x7d, 0x33, 0xf2, 0xe9, 0x7a, 0x6c } };

// System provider keyword constants
#define SYSTEM_PROCESS_KW_THREAD (0x0000000000000800)
#define SYSTEM_SCHEDULER_KW_DISPATCHER (0x0000000000000002)
#define SYSTEM_SCHEDULER_KW_CONTEXT_SWITCH (0x0000000000000200)

#else // __MINGW32__

// Backcompat with older sdk versions
// SDK 10.0.26100 introduced those two and marked TRACEHANDLE obsolete
// SDK 10.0.26100 is the first one to define NTDDI_VERSION and WDK_NTDDI_VERSION to NTDDI_WIN11_GE, while older ones will have lower versions and NTDDI_WIN11_GE undefined.
// Just in case we check both definition and value.
#if !(defined NTDDI_WIN11_GE && WDK_NTDDI_VERSION >= NTDDI_WIN11_GE)
typedef ULONG64 PROCESSTRACE_HANDLE;
typedef ULONG64 CONTROLTRACE_ID;
#endif

#endif // __MINGW32__

#endif // __TRACY_ETW_COMPAT_H__
