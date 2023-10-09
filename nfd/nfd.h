/*
  Native File Dialog Extended
  Repository: https://github.com/btzy/nativefiledialog-extended
  License: Zlib
  Authors: Bernard Teo, Michael Labbe

  This header contains the functions that can be called by user code.
 */

#ifndef _NFD_H
#define _NFD_H

#if defined(_WIN32)
#if defined(NFD_EXPORT)
#define NFD_API __declspec(dllexport)
#elif defined(NFD_SHARED)
#define NFD_API __declspec(dllimport)
#endif
#else
#if defined(NFD_EXPORT) || defined(NFD_SHARED)
#if defined(__GNUC__) || defined(__clang__)
#define NFD_API __attribute__((visibility("default")))
#endif
#endif
#endif
#ifndef NFD_API
#define NFD_API
#endif

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stddef.h>

#ifdef _WIN32
/* denotes UTF-16 char */
typedef wchar_t nfdnchar_t;
#else
/* denotes UTF-8 char */
typedef char nfdnchar_t;
#endif  // _WIN32

/* opaque data structure -- see NFD_PathSet_* */
typedef void nfdpathset_t;
#ifndef NFD_PORTAL
typedef struct {
    void* ptr;
} nfdpathsetenum_t;
#else
typedef struct {
    void* d1;
    void* d2;
    unsigned int d3;
    int d4;
    int d5;
    int d6;
    int d7;
    int d8;
    int d9;
    int d10;
    int d11;
    int p1;
    void* p2;
    void* p3;
} nfdpathsetenum_t;
#endif

typedef unsigned int nfdfiltersize_t;

typedef enum {
    NFD_ERROR, /* programmatic error */
    NFD_OKAY,  /* user pressed okay, or successful return */
    NFD_CANCEL /* user pressed cancel */
} nfdresult_t;

typedef struct {
    const nfdnchar_t* name;
    const nfdnchar_t* spec;
} nfdnfilteritem_t;

/* free a file path that was returned by the dialogs */
/* Note: use NFD_PathSet_FreePath to free path from pathset instead of this function */
NFD_API void NFD_FreePathN(nfdnchar_t* filePath);

/* initialize NFD - call this for every thread that might use NFD, before calling any other NFD
 * functions on that thread */
NFD_API nfdresult_t NFD_Init(void);

/* call this to de-initialize NFD, if NFD_Init returned NFD_OKAY */
NFD_API void NFD_Quit(void);

/* single file open dialog */
/* It is the caller's responsibility to free `outPath` via NFD_FreePathN() if this function returns
 * NFD_OKAY */
/* If filterCount is zero, filterList is ignored (you can use NULL) */
/* If defaultPath is NULL, the operating system will decide */
NFD_API nfdresult_t NFD_OpenDialogN(nfdnchar_t** outPath,
                                    const nfdnfilteritem_t* filterList,
                                    nfdfiltersize_t filterCount,
                                    const nfdnchar_t* defaultPath);

/* multiple file open dialog */
/* It is the caller's responsibility to free `outPaths` via NFD_PathSet_Free() if this function
 * returns NFD_OKAY */
/* If filterCount is zero, filterList is ignored (you can use NULL) */
/* If defaultPath is NULL, the operating system will decide */
NFD_API nfdresult_t NFD_OpenDialogMultipleN(const nfdpathset_t** outPaths,
                                            const nfdnfilteritem_t* filterList,
                                            nfdfiltersize_t filterCount,
                                            const nfdnchar_t* defaultPath);

/* save dialog */
/* It is the caller's responsibility to free `outPath` via NFD_FreePathN() if this function returns
 * NFD_OKAY */
/* If filterCount is zero, filterList is ignored (you can use NULL) */
/* If defaultPath is NULL, the operating system will decide */
NFD_API nfdresult_t NFD_SaveDialogN(nfdnchar_t** outPath,
                                    const nfdnfilteritem_t* filterList,
                                    nfdfiltersize_t filterCount,
                                    const nfdnchar_t* defaultPath,
                                    const nfdnchar_t* defaultName);

/* select folder dialog */
/* It is the caller's responsibility to free `outPath` via NFD_FreePathN() if this function returns
 * NFD_OKAY */
/* If defaultPath is NULL, the operating system will decide */
NFD_API nfdresult_t NFD_PickFolderN(nfdnchar_t** outPath, const nfdnchar_t* defaultPath);

/* Get last error -- set when nfdresult_t returns NFD_ERROR */
/* Returns the last error that was set, or NULL if there is no error. */
/* The memory is owned by NFD and should not be freed by user code. */
/* This is *always* ASCII printable characters, so it can be interpreted as UTF-8 without any
 * conversion. */
NFD_API const char* NFD_GetError(void);
/* clear the error */
NFD_API void NFD_ClearError(void);

/* path set operations */
#ifdef _WIN32
typedef unsigned long nfdpathsetsize_t;
#elif __APPLE__
typedef unsigned long nfdpathsetsize_t;
#else
typedef unsigned int nfdpathsetsize_t;
#endif  // _WIN32, __APPLE__

/* Gets the number of entries stored in pathSet */
/* note that some paths might be invalid (NFD_ERROR will be returned by NFD_PathSet_GetPath), so we
 * might not actually have this number of usable paths */
NFD_API nfdresult_t NFD_PathSet_GetCount(const nfdpathset_t* pathSet, nfdpathsetsize_t* count);
/* Gets the UTF-8 path at offset index */
/* It is the caller's responsibility to free `outPath` via NFD_PathSet_FreePathN() if this function
 * returns NFD_OKAY */
NFD_API nfdresult_t NFD_PathSet_GetPathN(const nfdpathset_t* pathSet,
                                         nfdpathsetsize_t index,
                                         nfdnchar_t** outPath);
/* Free the path gotten by NFD_PathSet_GetPathN */
#ifdef _WIN32
#define NFD_PathSet_FreePathN NFD_FreePathN
#elif __APPLE__
#define NFD_PathSet_FreePathN NFD_FreePathN
#else
NFD_API void NFD_PathSet_FreePathN(const nfdnchar_t* filePath);
#endif  // _WIN32, __APPLE__

/* Gets an enumerator of the path set. */
/* It is the caller's responsibility to free `enumerator` via NFD_PathSet_FreeEnum() if this
 * function returns NFD_OKAY, and it should be freed before freeing the pathset. */
NFD_API nfdresult_t NFD_PathSet_GetEnum(const nfdpathset_t* pathSet,
                                        nfdpathsetenum_t* outEnumerator);
/* Frees an enumerator of the path set. */
NFD_API void NFD_PathSet_FreeEnum(nfdpathsetenum_t* enumerator);
/* Gets the next item from the path set enumerator.
 * If there are no more items, then *outPaths will be set to NULL. */
/* It is the caller's responsibility to free `*outPath` via NFD_PathSet_FreePath() if this
 * function returns NFD_OKAY and `*outPath` is not null */
NFD_API nfdresult_t NFD_PathSet_EnumNextN(nfdpathsetenum_t* enumerator, nfdnchar_t** outPath);

/* Free the pathSet */
NFD_API void NFD_PathSet_Free(const nfdpathset_t* pathSet);

#ifdef _WIN32

/* say that the U8 versions of functions are not just #defined to be the native versions */
#define NFD_DIFFERENT_NATIVE_FUNCTIONS

typedef char nfdu8char_t;

typedef struct {
    const nfdu8char_t* name;
    const nfdu8char_t* spec;
} nfdu8filteritem_t;

/* UTF-8 compatibility functions */

/* free a file path that was returned */
NFD_API void NFD_FreePathU8(nfdu8char_t* outPath);

/* single file open dialog */
/* It is the caller's responsibility to free `outPath` via NFD_FreePathU8() if this function returns
 * NFD_OKAY */
NFD_API nfdresult_t NFD_OpenDialogU8(nfdu8char_t** outPath,
                                     const nfdu8filteritem_t* filterList,
                                     nfdfiltersize_t count,
                                     const nfdu8char_t* defaultPath);

/* multiple file open dialog */
/* It is the caller's responsibility to free `outPaths` via NFD_PathSet_Free() if this function
 * returns NFD_OKAY */
NFD_API nfdresult_t NFD_OpenDialogMultipleU8(const nfdpathset_t** outPaths,
                                             const nfdu8filteritem_t* filterList,
                                             nfdfiltersize_t count,
                                             const nfdu8char_t* defaultPath);

/* save dialog */
/* It is the caller's responsibility to free `outPath` via NFD_FreePathU8() if this function returns
 * NFD_OKAY */
NFD_API nfdresult_t NFD_SaveDialogU8(nfdu8char_t** outPath,
                                     const nfdu8filteritem_t* filterList,
                                     nfdfiltersize_t count,
                                     const nfdu8char_t* defaultPath,
                                     const nfdu8char_t* defaultName);

/* select folder dialog */
/* It is the caller's responsibility to free `outPath` via NFD_FreePathU8() if this function returns
 * NFD_OKAY */
NFD_API nfdresult_t NFD_PickFolderU8(nfdu8char_t** outPath, const nfdu8char_t* defaultPath);

/* Get the UTF-8 path at offset index */
/* It is the caller's responsibility to free `outPath` via NFD_FreePathU8() if this function returns
 * NFD_OKAY */
NFD_API nfdresult_t NFD_PathSet_GetPathU8(const nfdpathset_t* pathSet,
                                          nfdpathsetsize_t index,
                                          nfdu8char_t** outPath);

/* Gets the next item from the path set enumerator.
 * If there are no more items, then *outPaths will be set to NULL. */
/* It is the caller's responsibility to free `*outPath` via NFD_PathSet_FreePathU8() if this
 * function returns NFD_OKAY and `*outPath` is not null */
NFD_API nfdresult_t NFD_PathSet_EnumNextU8(nfdpathsetenum_t* enumerator, nfdu8char_t** outPath);

#define NFD_PathSet_FreePathU8 NFD_FreePathU8

#ifdef NFD_NATIVE
typedef nfdnchar_t nfdchar_t;
typedef nfdnfilteritem_t nfdfilteritem_t;
#define NFD_FreePath NFD_FreePathN
#define NFD_OpenDialog NFD_OpenDialogN
#define NFD_OpenDialogMultiple NFD_OpenDialogMultipleN
#define NFD_SaveDialog NFD_SaveDialogN
#define NFD_PickFolder NFD_PickFolderN
#define NFD_PathSet_GetPath NFD_PathSet_GetPathN
#define NFD_PathSet_FreePath NFD_PathSet_FreePathN
#define NFD_PathSet_EnumNext NFD_PathSet_EnumNextN
#else
typedef nfdu8char_t nfdchar_t;
typedef nfdu8filteritem_t nfdfilteritem_t;
#define NFD_FreePath NFD_FreePathU8
#define NFD_OpenDialog NFD_OpenDialogU8
#define NFD_OpenDialogMultiple NFD_OpenDialogMultipleU8
#define NFD_SaveDialog NFD_SaveDialogU8
#define NFD_PickFolder NFD_PickFolderU8
#define NFD_PathSet_GetPath NFD_PathSet_GetPathU8
#define NFD_PathSet_FreePath NFD_PathSet_FreePathU8
#define NFD_PathSet_EnumNext NFD_PathSet_EnumNextU8
#endif  // NFD_NATIVE

#else  // _WIN32

/* the native charset is already UTF-8 */
typedef nfdnchar_t nfdchar_t;
typedef nfdnfilteritem_t nfdfilteritem_t;
#define NFD_FreePath NFD_FreePathN
#define NFD_OpenDialog NFD_OpenDialogN
#define NFD_OpenDialogMultiple NFD_OpenDialogMultipleN
#define NFD_SaveDialog NFD_SaveDialogN
#define NFD_PickFolder NFD_PickFolderN
#define NFD_PathSet_GetPath NFD_PathSet_GetPathN
#define NFD_PathSet_FreePath NFD_PathSet_FreePathN
#define NFD_PathSet_EnumNext NFD_PathSet_EnumNextN
typedef nfdnchar_t nfdu8char_t;
typedef nfdnfilteritem_t nfdu8filteritem_t;
#define NFD_FreePathU8 NFD_FreePathN
#define NFD_OpenDialogU8 NFD_OpenDialogN
#define NFD_OpenDialogMultipleU8 NFD_OpenDialogMultipleN
#define NFD_SaveDialogU8 NFD_SaveDialogN
#define NFD_PickFolderU8 NFD_PickFolderN
#define NFD_PathSet_GetPathU8 NFD_PathSet_GetPathN
#define NFD_PathSet_FreePathU8 NFD_PathSet_FreePathN
#define NFD_PathSet_EnumNextU8 NFD_PathSet_EnumNextN

#endif  // _WIN32

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // _NFD_H
