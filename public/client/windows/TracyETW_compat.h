#ifndef __TRACY_ETW_COMPAT_H__
#define __TRACY_ETW_COMPAT_H__

// Compatibility definitions for MinGW-w64 which lacks some ETW types
// present in Microsoft's Windows SDK

#ifdef __MINGW32__

// CONTROLTRACE_ID - ETW trace session handle type
typedef ULONGLONG CONTROLTRACE_ID;

// PROCESSTRACE_HANDLE - ETW process trace handle type
// MinGW defines INVALID_PROCESSTRACE_HANDLE but not the type itself
#ifndef PROCESSTRACE_HANDLE
#define PROCESSTRACE_HANDLE TRACEHANDLE
#endif

// EVENT_FILTER_EVENT_ID struct for event filtering
typedef struct _EVENT_FILTER_EVENT_ID {
    BOOLEAN FilterIn;
    ULONG Reserved;
    ULONG Count;
    USHORT Events[ANYSIZE_ARRAY];
} EVENT_FILTER_EVENT_ID, *PEVENT_FILTER_EVENT_ID;

// Event filter type constants
#define EVENT_FILTER_TYPE_EVENT_ID (3)

// Enable property constants
#define EVENT_ENABLE_PROPERTY_IGNORE_KEYWORD_0 (0x1)

// System provider GUIDs
// MinGW's DEFINE_GUID only declares the GUID, we need to define it with actual storage
// Using GUID format: {l, w1, w2, d1, d2, d3, d4, d5, d6, d7, d8} where d1-d8 are bytes
static const GUID SystemProcessProviderGuid = {0x22d6d368, 0x560a, 0x4a9b, {0x81, 0x4e, 0xd3, 0x6b, 0x5e, 0x88, 0x8c, 0x4e}};
static const GUID SystemProfileProviderGuid = {0xb6d70bbb, 0x4867, 0x4c13, {0x81, 0x93, 0x1d, 0x25, 0x2e, 0x5d, 0x5c, 0x7b}};
static const GUID SystemSchedulerProviderGuid = {0x69ff631b, 0xf8b7, 0x41f8, {0xb0, 0x5f, 0xf9, 0x2e, 0x7e, 0x8d, 0x29, 0x3d}};

// System provider keyword constants
#define SYSTEM_PROCESS_KW_THREAD (0x0000000400000000ULL)
#define SYSTEM_SCHEDULER_KW_CONTEXT_SWITCH (0x0000000000000001ULL)
#define SYSTEM_SCHEDULER_KW_DISPATCHER (0x0000000000000002ULL)

#endif // __MINGW32__

#endif // __TRACY_ETW_COMPAT_H__
