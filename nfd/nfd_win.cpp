/*
  Native File Dialog Extended
  Repository: https://github.com/btzy/nativefiledialog-extended
  License: Zlib
  Author: Bernard Teo
 */

/* only locally define UNICODE in this compilation unit */
#ifndef UNICODE
#define UNICODE
#endif

#ifdef __MINGW32__
// Explicitly setting NTDDI version, this is necessary for the MinGW compiler
#define NTDDI_VERSION NTDDI_VISTA
#define _WIN32_WINNT _WIN32_WINNT_VISTA
#endif

#if _MSC_VER
// see
// https://developercommunity.visualstudio.com/content/problem/185399/error-c2760-in-combaseapih-with-windows-sdk-81-and.html
struct IUnknown;  // Workaround for "combaseapi.h(229): error C2187: syntax error: 'identifier' was
                  // unexpected here" when using /permissive-
#endif

#include <assert.h>
#include <shobjidl.h>
#include <stdio.h>
#include <wchar.h>
#include <windows.h>
#include "nfd.h"

namespace {

/* current error */
const char* g_errorstr = nullptr;

void NFDi_SetError(const char* msg) {
    g_errorstr = msg;
}

template <typename T = void>
T* NFDi_Malloc(size_t bytes) {
    void* ptr = malloc(bytes);
    if (!ptr) NFDi_SetError("NFDi_Malloc failed.");

    return static_cast<T*>(ptr);
}

template <typename T>
void NFDi_Free(T* ptr) {
    assert(ptr);
    free(static_cast<void*>(ptr));
}

/* guard objects */
template <typename T>
struct Release_Guard {
    T* data;
    Release_Guard(T* releasable) noexcept : data(releasable) {}
    ~Release_Guard() { data->Release(); }
};

template <typename T>
struct Free_Guard {
    T* data;
    Free_Guard(T* freeable) noexcept : data(freeable) {}
    ~Free_Guard() { NFDi_Free(data); }
};

template <typename T>
struct FreeCheck_Guard {
    T* data;
    FreeCheck_Guard(T* freeable = nullptr) noexcept : data(freeable) {}
    ~FreeCheck_Guard() {
        if (data) NFDi_Free(data);
    }
};

/* helper functions */
nfdresult_t AddFiltersToDialog(::IFileDialog* fileOpenDialog,
                               const nfdnfilteritem_t* filterList,
                               nfdfiltersize_t filterCount) {
    /* filterCount plus 1 because we hardcode the *.* wildcard after the while loop */
    COMDLG_FILTERSPEC* specList =
        NFDi_Malloc<COMDLG_FILTERSPEC>(sizeof(COMDLG_FILTERSPEC) * (filterCount + 1));
    if (!specList) {
        return NFD_ERROR;
    }

    /* ad-hoc RAII object to free memory when destructing */
    struct COMDLG_FILTERSPEC_Guard {
        COMDLG_FILTERSPEC* _specList;
        nfdfiltersize_t index;
        COMDLG_FILTERSPEC_Guard(COMDLG_FILTERSPEC* specList) noexcept
            : _specList(specList), index(0) {}
        ~COMDLG_FILTERSPEC_Guard() {
            for (--index; index != static_cast<nfdfiltersize_t>(-1); --index) {
                NFDi_Free(const_cast<nfdnchar_t*>(_specList[index].pszSpec));
            }
            NFDi_Free(_specList);
        }
    };

    COMDLG_FILTERSPEC_Guard specListGuard(specList);

    if (filterCount) {
        assert(filterList);

        // we have filters to add ... format and add them

        // use the index that comes from the RAII object (instead of making a copy), so the RAII
        // object will know which memory to free
        nfdfiltersize_t& index = specListGuard.index;

        for (; index != filterCount; ++index) {
            // set the friendly name of this filter
            specList[index].pszName = filterList[index].name;

            // set the specification of this filter...

            // count number of file extensions
            size_t sep = 1;
            for (const nfdnchar_t* p_spec = filterList[index].spec; *p_spec; ++p_spec) {
                if (*p_spec == L',') {
                    ++sep;
                }
            }

            // calculate space needed (including the trailing '\0')
            size_t specSize = sep * 2 + wcslen(filterList[index].spec) + 1;

            // malloc the required memory and populate it
            nfdnchar_t* specBuf = NFDi_Malloc<nfdnchar_t>(sizeof(nfdnchar_t) * specSize);

            if (!specBuf) {
                // automatic freeing of memory via COMDLG_FILTERSPEC_Guard
                return NFD_ERROR;
            }

            // convert "png,jpg" to "*.png;*.jpg" as required by Windows ...
            nfdnchar_t* p_specBuf = specBuf;
            *p_specBuf++ = L'*';
            *p_specBuf++ = L'.';
            for (const nfdnchar_t* p_spec = filterList[index].spec; *p_spec; ++p_spec) {
                if (*p_spec == L',') {
                    *p_specBuf++ = L';';
                    *p_specBuf++ = L'*';
                    *p_specBuf++ = L'.';
                } else {
                    *p_specBuf++ = *p_spec;
                }
            }
            *p_specBuf++ = L'\0';

            // assert that we had allocated exactly the correct amount of memory that we used
            assert(static_cast<size_t>(p_specBuf - specBuf) == specSize);

            // save the buffer to the guard object
            specList[index].pszSpec = specBuf;
        }
    }

    /* Add wildcard */
    specList[filterCount].pszName = L"All files";
    specList[filterCount].pszSpec = L"*.*";

    // add the filter to the dialog
    if (!SUCCEEDED(fileOpenDialog->SetFileTypes(filterCount + 1, specList))) {
        NFDi_SetError("Failed to set the allowable file types for the drop-down menu.");
        return NFD_ERROR;
    }

    // automatic freeing of memory via COMDLG_FILTERSPEC_Guard
    return NFD_OKAY;
}

/* call after AddFiltersToDialog */
nfdresult_t SetDefaultExtension(::IFileDialog* fileOpenDialog,
                                const nfdnfilteritem_t* filterList,
                                nfdfiltersize_t filterCount) {
    // if there are no filters, then don't set default extensions
    if (!filterCount) {
        return NFD_OKAY;
    }

    assert(filterList);

    // set the first item as the default index, and set the default extension
    if (!SUCCEEDED(fileOpenDialog->SetFileTypeIndex(1))) {
        NFDi_SetError("Failed to set the selected file type index.");
        return NFD_ERROR;
    }

    // set the first item as the default file extension
    const nfdnchar_t* p_spec = filterList[0].spec;
    for (; *p_spec; ++p_spec) {
        if (*p_spec == ',') {
            break;
        }
    }
    if (*p_spec) {
        // multiple file extensions for this type (need to allocate memory)
        size_t numChars = p_spec - filterList[0].spec;
        // allocate one more char space for the '\0'
        nfdnchar_t* extnBuf = NFDi_Malloc<nfdnchar_t>(sizeof(nfdnchar_t) * (numChars + 1));
        if (!extnBuf) {
            return NFD_ERROR;
        }
        Free_Guard<nfdnchar_t> extnBufGuard(extnBuf);

        // copy the extension
        for (size_t i = 0; i != numChars; ++i) {
            extnBuf[i] = filterList[0].spec[i];
        }
        // pad with trailing '\0'
        extnBuf[numChars] = L'\0';

        if (!SUCCEEDED(fileOpenDialog->SetDefaultExtension(extnBuf))) {
            NFDi_SetError("Failed to set default extension.");
            return NFD_ERROR;
        }
    } else {
        // single file extension for this type (no need to allocate memory)
        if (!SUCCEEDED(fileOpenDialog->SetDefaultExtension(filterList[0].spec))) {
            NFDi_SetError("Failed to set default extension.");
            return NFD_ERROR;
        }
    }

    return NFD_OKAY;
}

nfdresult_t SetDefaultPath(IFileDialog* dialog, const nfdnchar_t* defaultPath) {
    if (!defaultPath || !*defaultPath) return NFD_OKAY;

    IShellItem* folder;
    HRESULT result = SHCreateItemFromParsingName(defaultPath, nullptr, IID_PPV_ARGS(&folder));

    // Valid non results.
    if (result == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) ||
        result == HRESULT_FROM_WIN32(ERROR_INVALID_DRIVE)) {
        return NFD_OKAY;
    }

    if (!SUCCEEDED(result)) {
        NFDi_SetError("Failed to create ShellItem for setting the default path.");
        return NFD_ERROR;
    }

    Release_Guard<IShellItem> folderGuard(folder);

    // SetDefaultFolder() might use another recently used folder if available, so the user doesn't
    // need to keep navigating back to the default folder (recommended by Windows). change to
    // SetFolder() if you always want to use the default folder
    if (!SUCCEEDED(dialog->SetDefaultFolder(folder))) {
        NFDi_SetError("Failed to set default path.");
        return NFD_ERROR;
    }

    return NFD_OKAY;
}

nfdresult_t SetDefaultName(IFileDialog* dialog, const nfdnchar_t* defaultName) {
    if (!defaultName || !*defaultName) return NFD_OKAY;

    if (!SUCCEEDED(dialog->SetFileName(defaultName))) {
        NFDi_SetError("Failed to set default file name.");
        return NFD_ERROR;
    }

    return NFD_OKAY;
}

nfdresult_t AddOptions(IFileDialog* dialog, FILEOPENDIALOGOPTIONS options) {
    FILEOPENDIALOGOPTIONS existingOptions;
    if (!SUCCEEDED(dialog->GetOptions(&existingOptions))) {
        NFDi_SetError("Failed to get options.");
        return NFD_ERROR;
    }
    if (!SUCCEEDED(dialog->SetOptions(existingOptions | options))) {
        NFDi_SetError("Failed to set options.");
        return NFD_ERROR;
    }
    return NFD_OKAY;
}
}  // namespace

const char* NFD_GetError(void) {
    return g_errorstr;
}

void NFD_ClearError(void) {
    NFDi_SetError(nullptr);
}

/* public */

namespace {
// The user might have initialized with COINIT_MULTITHREADED before,
// in which case we will fail to do CoInitializeEx(), but file dialogs will still work.
// See https://github.com/mlabbe/nativefiledialog/issues/72 for more information.
bool needs_uninitialize;
}  // namespace

nfdresult_t NFD_Init(void) {
    // Init COM library.
    HRESULT result =
        ::CoInitializeEx(nullptr, ::COINIT_APARTMENTTHREADED | ::COINIT_DISABLE_OLE1DDE);

    if (SUCCEEDED(result)) {
        needs_uninitialize = true;
        return NFD_OKAY;
    } else if (result == RPC_E_CHANGED_MODE) {
        // If this happens, the user already initialized COM using COINIT_MULTITHREADED,
        // so COM will still work, but we shouldn't uninitialize it later.
        needs_uninitialize = false;
        return NFD_OKAY;
    } else {
        NFDi_SetError("Failed to initialize COM.");
        return NFD_ERROR;
    }
}
void NFD_Quit(void) {
    if (needs_uninitialize) ::CoUninitialize();
}

void NFD_FreePathN(nfdnchar_t* filePath) {
    assert(filePath);
    ::CoTaskMemFree(filePath);
}

nfdresult_t NFD_OpenDialogN(nfdnchar_t** outPath,
                            const nfdnfilteritem_t* filterList,
                            nfdfiltersize_t filterCount,
                            const nfdnchar_t* defaultPath) {
    ::IFileOpenDialog* fileOpenDialog;

    // Create dialog
    HRESULT result = ::CoCreateInstance(::CLSID_FileOpenDialog,
                                        nullptr,
                                        CLSCTX_ALL,
                                        ::IID_IFileOpenDialog,
                                        reinterpret_cast<void**>(&fileOpenDialog));

    if (!SUCCEEDED(result)) {
        NFDi_SetError("Could not create dialog.");
        return NFD_ERROR;
    }

    // make sure we remember to free the dialog
    Release_Guard<::IFileOpenDialog> fileOpenDialogGuard(fileOpenDialog);

    // Build the filter list
    if (!AddFiltersToDialog(fileOpenDialog, filterList, filterCount)) {
        return NFD_ERROR;
    }

    // Set auto-completed default extension
    if (!SetDefaultExtension(fileOpenDialog, filterList, filterCount)) {
        return NFD_ERROR;
    }

    // Set the default path
    if (!SetDefaultPath(fileOpenDialog, defaultPath)) {
        return NFD_ERROR;
    }

    // Only show file system items
    if (!AddOptions(fileOpenDialog, ::FOS_FORCEFILESYSTEM)) {
        return NFD_ERROR;
    }

    // Show the dialog.
    result = fileOpenDialog->Show(nullptr);
    if (SUCCEEDED(result)) {
        // Get the file name
        ::IShellItem* psiResult;
        result = fileOpenDialog->GetResult(&psiResult);
        if (!SUCCEEDED(result)) {
            NFDi_SetError("Could not get shell item from dialog.");
            return NFD_ERROR;
        }
        Release_Guard<::IShellItem> psiResultGuard(psiResult);

        nfdnchar_t* filePath;
        result = psiResult->GetDisplayName(::SIGDN_FILESYSPATH, &filePath);
        if (!SUCCEEDED(result)) {
            NFDi_SetError("Could not get file path from shell item returned by dialog.");
            return NFD_ERROR;
        }

        *outPath = filePath;

        return NFD_OKAY;
    } else if (result == HRESULT_FROM_WIN32(ERROR_CANCELLED)) {
        return NFD_CANCEL;
    } else {
        NFDi_SetError("File dialog box show failed.");
        return NFD_ERROR;
    }
}

nfdresult_t NFD_OpenDialogMultipleN(const nfdpathset_t** outPaths,
                                    const nfdnfilteritem_t* filterList,
                                    nfdfiltersize_t filterCount,
                                    const nfdnchar_t* defaultPath) {
    ::IFileOpenDialog* fileOpenDialog(nullptr);

    // Create dialog
    HRESULT result = ::CoCreateInstance(::CLSID_FileOpenDialog,
                                        nullptr,
                                        CLSCTX_ALL,
                                        ::IID_IFileOpenDialog,
                                        reinterpret_cast<void**>(&fileOpenDialog));

    if (!SUCCEEDED(result)) {
        NFDi_SetError("Could not create dialog.");
        return NFD_ERROR;
    }

    // make sure we remember to free the dialog
    Release_Guard<::IFileOpenDialog> fileOpenDialogGuard(fileOpenDialog);

    // Build the filter list
    if (!AddFiltersToDialog(fileOpenDialog, filterList, filterCount)) {
        return NFD_ERROR;
    }

    // Set auto-completed default extension
    if (!SetDefaultExtension(fileOpenDialog, filterList, filterCount)) {
        return NFD_ERROR;
    }

    // Set the default path
    if (!SetDefaultPath(fileOpenDialog, defaultPath)) {
        return NFD_ERROR;
    }

    // Set a flag for multiple options and file system items only
    if (!AddOptions(fileOpenDialog, ::FOS_FORCEFILESYSTEM | ::FOS_ALLOWMULTISELECT)) {
        return NFD_ERROR;
    }

    // Show the dialog.
    result = fileOpenDialog->Show(nullptr);
    if (SUCCEEDED(result)) {
        ::IShellItemArray* shellItems;
        result = fileOpenDialog->GetResults(&shellItems);
        if (!SUCCEEDED(result)) {
            NFDi_SetError("Could not get shell items.");
            return NFD_ERROR;
        }

        // save the path set to the output
        *outPaths = static_cast<void*>(shellItems);

        return NFD_OKAY;
    } else if (result == HRESULT_FROM_WIN32(ERROR_CANCELLED)) {
        return NFD_CANCEL;
    } else {
        NFDi_SetError("File dialog box show failed.");
        return NFD_ERROR;
    }
}

nfdresult_t NFD_SaveDialogN(nfdnchar_t** outPath,
                            const nfdnfilteritem_t* filterList,
                            nfdfiltersize_t filterCount,
                            const nfdnchar_t* defaultPath,
                            const nfdnchar_t* defaultName) {
    ::IFileSaveDialog* fileSaveDialog;

    // Create dialog
    HRESULT result = ::CoCreateInstance(::CLSID_FileSaveDialog,
                                        nullptr,
                                        CLSCTX_ALL,
                                        ::IID_IFileSaveDialog,
                                        reinterpret_cast<void**>(&fileSaveDialog));

    if (!SUCCEEDED(result)) {
        NFDi_SetError("Could not create dialog.");
        return NFD_ERROR;
    }

    // make sure we remember to free the dialog
    Release_Guard<::IFileSaveDialog> fileSaveDialogGuard(fileSaveDialog);

    // Build the filter list
    if (!AddFiltersToDialog(fileSaveDialog, filterList, filterCount)) {
        return NFD_ERROR;
    }

    // Set default extension
    if (!SetDefaultExtension(fileSaveDialog, filterList, filterCount)) {
        return NFD_ERROR;
    }

    // Set the default path
    if (!SetDefaultPath(fileSaveDialog, defaultPath)) {
        return NFD_ERROR;
    }

    // Set the default name
    if (!SetDefaultName(fileSaveDialog, defaultName)) {
        return NFD_ERROR;
    }

    // Only show file system items
    if (!AddOptions(fileSaveDialog, ::FOS_FORCEFILESYSTEM)) {
        return NFD_ERROR;
    }

    // Show the dialog.
    result = fileSaveDialog->Show(nullptr);
    if (SUCCEEDED(result)) {
        // Get the file name
        ::IShellItem* psiResult;
        result = fileSaveDialog->GetResult(&psiResult);
        if (!SUCCEEDED(result)) {
            NFDi_SetError("Could not get shell item from dialog.");
            return NFD_ERROR;
        }
        Release_Guard<::IShellItem> psiResultGuard(psiResult);

        nfdnchar_t* filePath;
        result = psiResult->GetDisplayName(::SIGDN_FILESYSPATH, &filePath);
        if (!SUCCEEDED(result)) {
            NFDi_SetError("Could not get file path from shell item returned by dialog.");
            return NFD_ERROR;
        }

        *outPath = filePath;

        return NFD_OKAY;
    } else if (result == HRESULT_FROM_WIN32(ERROR_CANCELLED)) {
        return NFD_CANCEL;
    } else {
        NFDi_SetError("File dialog box show failed.");
        return NFD_ERROR;
    }
}

nfdresult_t NFD_PickFolderN(nfdnchar_t** outPath, const nfdnchar_t* defaultPath) {
    ::IFileOpenDialog* fileOpenDialog;

    // Create dialog
    if (!SUCCEEDED(::CoCreateInstance(::CLSID_FileOpenDialog,
                                      nullptr,
                                      CLSCTX_ALL,
                                      ::IID_IFileOpenDialog,
                                      reinterpret_cast<void**>(&fileOpenDialog)))) {
        NFDi_SetError("Could not create dialog.");
        return NFD_ERROR;
    }

    Release_Guard<::IFileOpenDialog> fileOpenDialogGuard(fileOpenDialog);

    // Set the default path
    if (!SetDefaultPath(fileOpenDialog, defaultPath)) {
        return NFD_ERROR;
    }

    // Only show items that are folders and on the file system
    if (!AddOptions(fileOpenDialog, ::FOS_FORCEFILESYSTEM | ::FOS_PICKFOLDERS)) {
        return NFD_ERROR;
    }

    // Show the dialog to the user
    const HRESULT result = fileOpenDialog->Show(nullptr);
    if (result == HRESULT_FROM_WIN32(ERROR_CANCELLED)) {
        return NFD_CANCEL;
    } else if (!SUCCEEDED(result)) {
        NFDi_SetError("File dialog box show failed.");
        return NFD_ERROR;
    }

    // Get the shell item result
    ::IShellItem* psiResult;
    if (!SUCCEEDED(fileOpenDialog->GetResult(&psiResult))) {
        return NFD_ERROR;
    }

    Release_Guard<::IShellItem> psiResultGuard(psiResult);

    // Finally get the path
    nfdnchar_t* filePath;
    // Why are we not using SIGDN_FILESYSPATH?
    if (!SUCCEEDED(psiResult->GetDisplayName(::SIGDN_DESKTOPABSOLUTEPARSING, &filePath))) {
        NFDi_SetError("Could not get file path from shell item returned by dialog.");
        return NFD_ERROR;
    }

    *outPath = filePath;

    return NFD_OKAY;
}

nfdresult_t NFD_PathSet_GetCount(const nfdpathset_t* pathSet, nfdpathsetsize_t* count) {
    assert(pathSet);
    // const_cast because methods on IShellItemArray aren't const, but it should act like const to
    // the caller
    ::IShellItemArray* psiaPathSet =
        const_cast<::IShellItemArray*>(static_cast<const ::IShellItemArray*>(pathSet));

    DWORD numPaths;
    if (!SUCCEEDED(psiaPathSet->GetCount(&numPaths))) {
        NFDi_SetError("Could not get path count.");
        return NFD_ERROR;
    }
    *count = numPaths;
    return NFD_OKAY;
}

nfdresult_t NFD_PathSet_GetPathN(const nfdpathset_t* pathSet,
                                 nfdpathsetsize_t index,
                                 nfdnchar_t** outPath) {
    assert(pathSet);
    // const_cast because methods on IShellItemArray aren't const, but it should act like const to
    // the caller
    ::IShellItemArray* psiaPathSet =
        const_cast<::IShellItemArray*>(static_cast<const ::IShellItemArray*>(pathSet));

    ::IShellItem* psiPath;
    if (!SUCCEEDED(psiaPathSet->GetItemAt(index, &psiPath))) {
        NFDi_SetError("Could not get shell item.");
        return NFD_ERROR;
    }

    Release_Guard<::IShellItem> psiPathGuard(psiPath);

    nfdnchar_t* name;
    if (!SUCCEEDED(psiPath->GetDisplayName(::SIGDN_FILESYSPATH, &name))) {
        NFDi_SetError("Could not get file path from shell item.");
        return NFD_ERROR;
    }

    *outPath = name;
    return NFD_OKAY;
}

nfdresult_t NFD_PathSet_GetEnum(const nfdpathset_t* pathSet, nfdpathsetenum_t* outEnumerator) {
    assert(pathSet);
    // const_cast because methods on IShellItemArray aren't const, but it should act like const to
    // the caller
    ::IShellItemArray* psiaPathSet =
        const_cast<::IShellItemArray*>(static_cast<const ::IShellItemArray*>(pathSet));

    ::IEnumShellItems* pesiPaths;
    if (!SUCCEEDED(psiaPathSet->EnumItems(&pesiPaths))) {
        NFDi_SetError("Could not get enumerator.");
        return NFD_ERROR;
    }

    outEnumerator->ptr = static_cast<void*>(pesiPaths);
    return NFD_OKAY;
}

void NFD_PathSet_FreeEnum(nfdpathsetenum_t* enumerator) {
    assert(enumerator->ptr);

    ::IEnumShellItems* pesiPaths = static_cast<::IEnumShellItems*>(enumerator->ptr);

    // free the enumerator memory
    pesiPaths->Release();
}

nfdresult_t NFD_PathSet_EnumNextN(nfdpathsetenum_t* enumerator, nfdnchar_t** outPath) {
    assert(enumerator->ptr);

    ::IEnumShellItems* pesiPaths = static_cast<::IEnumShellItems*>(enumerator->ptr);

    ::IShellItem* psiPath;
    HRESULT res = pesiPaths->Next(1, &psiPath, NULL);
    if (!SUCCEEDED(res)) {
        NFDi_SetError("Could not get next item of enumerator.");
        return NFD_ERROR;
    }
    if (res != S_OK) {
        *outPath = nullptr;
        return NFD_OKAY;
    }

    Release_Guard<::IShellItem> psiPathGuard(psiPath);

    nfdnchar_t* name;
    if (!SUCCEEDED(psiPath->GetDisplayName(::SIGDN_FILESYSPATH, &name))) {
        NFDi_SetError("Could not get file path from shell item.");
        return NFD_ERROR;
    }

    *outPath = name;
    return NFD_OKAY;
}

void NFD_PathSet_Free(const nfdpathset_t* pathSet) {
    assert(pathSet);
    // const_cast because methods on IShellItemArray aren't const, but it should act like const to
    // the caller
    ::IShellItemArray* psiaPathSet =
        const_cast<::IShellItemArray*>(static_cast<const ::IShellItemArray*>(pathSet));

    // free the path set memory
    psiaPathSet->Release();
}

namespace {
// allocs the space in outStr -- call NFDi_Free()
nfdresult_t CopyCharToWChar(const nfdu8char_t* inStr, nfdnchar_t*& outStr) {
    int charsNeeded = MultiByteToWideChar(CP_UTF8, 0, inStr, -1, nullptr, 0);
    assert(charsNeeded);

    nfdnchar_t* tmp_outStr = NFDi_Malloc<nfdnchar_t>(sizeof(nfdnchar_t) * charsNeeded);
    if (!tmp_outStr) {
        return NFD_ERROR;
    }

    int ret = MultiByteToWideChar(CP_UTF8, 0, inStr, -1, tmp_outStr, charsNeeded);
    assert(ret && ret == charsNeeded);
    (void)ret;  // prevent warning in release build
    outStr = tmp_outStr;
    return NFD_OKAY;
}

// allocs the space in outPath -- call NFDi_Free()
nfdresult_t CopyWCharToNFDChar(const nfdnchar_t* inStr, nfdu8char_t*& outStr) {
    int bytesNeeded = WideCharToMultiByte(CP_UTF8, 0, inStr, -1, nullptr, 0, nullptr, nullptr);
    assert(bytesNeeded);

    nfdu8char_t* tmp_outStr = NFDi_Malloc<nfdu8char_t>(sizeof(nfdu8char_t) * bytesNeeded);
    if (!tmp_outStr) {
        return NFD_ERROR;
    }

    int ret = WideCharToMultiByte(CP_UTF8, 0, inStr, -1, tmp_outStr, bytesNeeded, nullptr, nullptr);
    assert(ret && ret == bytesNeeded);
    (void)ret;  // prevent warning in release build
    outStr = tmp_outStr;
    return NFD_OKAY;
}

struct FilterItem_Guard {
    nfdnfilteritem_t* data;
    nfdfiltersize_t index;
    FilterItem_Guard() noexcept : data(nullptr), index(0) {}
    ~FilterItem_Guard() {
        assert(data || index == 0);
        for (--index; index != static_cast<nfdfiltersize_t>(-1); --index) {
            NFDi_Free(const_cast<nfdnchar_t*>(data[index].spec));
            NFDi_Free(const_cast<nfdnchar_t*>(data[index].name));
        }
        if (data) NFDi_Free(data);
    }
};

nfdresult_t CopyFilterItem(const nfdu8filteritem_t* filterList,
                           nfdfiltersize_t count,
                           FilterItem_Guard& filterItemsNGuard) {
    if (count) {
        nfdnfilteritem_t*& filterItemsN = filterItemsNGuard.data;
        filterItemsN = NFDi_Malloc<nfdnfilteritem_t>(sizeof(nfdnfilteritem_t) * count);
        if (!filterItemsN) {
            return NFD_ERROR;
        }

        nfdfiltersize_t& index = filterItemsNGuard.index;
        for (; index != count; ++index) {
            nfdresult_t res = CopyCharToWChar(filterList[index].name,
                                              const_cast<nfdnchar_t*&>(filterItemsN[index].name));
            if (!res) {
                return NFD_ERROR;
            }
            res = CopyCharToWChar(filterList[index].spec,
                                  const_cast<nfdnchar_t*&>(filterItemsN[index].spec));
            if (!res) {
                // remember to free the name, because we also created it (and it won't be protected
                // by the guard, because we have not incremented the index)
                NFDi_Free(const_cast<nfdnchar_t*>(filterItemsN[index].name));
                return NFD_ERROR;
            }
        }
    }
    return NFD_OKAY;
}
nfdresult_t ConvertU8ToNative(const nfdu8char_t* u8Text, FreeCheck_Guard<nfdnchar_t>& nativeText) {
    if (u8Text) {
        nfdresult_t res = CopyCharToWChar(u8Text, nativeText.data);
        if (!res) {
            return NFD_ERROR;
        }
    }
    return NFD_OKAY;
}
void NormalizePathSeparator(nfdnchar_t* path) {
    if (path) {
        for (; *path; ++path) {
            if (*path == L'/') *path = L'\\';
        }
    }
}
}  // namespace

void NFD_FreePathU8(nfdu8char_t* outPath) {
    NFDi_Free(outPath);
}

nfdresult_t NFD_OpenDialogU8(nfdu8char_t** outPath,
                             const nfdu8filteritem_t* filterList,
                             nfdfiltersize_t count,
                             const nfdu8char_t* defaultPath) {
    // populate the real nfdnfilteritem_t
    FilterItem_Guard filterItemsNGuard;
    if (!CopyFilterItem(filterList, count, filterItemsNGuard)) {
        return NFD_ERROR;
    }

    // convert and normalize the default path, but only if it is not nullptr
    FreeCheck_Guard<nfdnchar_t> defaultPathNGuard;
    ConvertU8ToNative(defaultPath, defaultPathNGuard);
    NormalizePathSeparator(defaultPathNGuard.data);

    // call the native function
    nfdnchar_t* outPathN;
    nfdresult_t res =
        NFD_OpenDialogN(&outPathN, filterItemsNGuard.data, count, defaultPathNGuard.data);

    if (res != NFD_OKAY) {
        return res;
    }

    // convert the outPath to UTF-8
    res = CopyWCharToNFDChar(outPathN, *outPath);

    // free the native out path, and return the result
    NFD_FreePathN(outPathN);
    return res;
}

/* multiple file open dialog */
/* It is the caller's responsibility to free `outPaths` via NFD_PathSet_Free() if this function
 * returns NFD_OKAY */
nfdresult_t NFD_OpenDialogMultipleU8(const nfdpathset_t** outPaths,
                                     const nfdu8filteritem_t* filterList,
                                     nfdfiltersize_t count,
                                     const nfdu8char_t* defaultPath) {
    // populate the real nfdnfilteritem_t
    FilterItem_Guard filterItemsNGuard;
    if (!CopyFilterItem(filterList, count, filterItemsNGuard)) {
        return NFD_ERROR;
    }

    // convert and normalize the default path, but only if it is not nullptr
    FreeCheck_Guard<nfdnchar_t> defaultPathNGuard;
    ConvertU8ToNative(defaultPath, defaultPathNGuard);
    NormalizePathSeparator(defaultPathNGuard.data);

    // call the native function
    return NFD_OpenDialogMultipleN(outPaths, filterItemsNGuard.data, count, defaultPathNGuard.data);
}

/* save dialog */
/* It is the caller's responsibility to free `outPath` via NFD_FreePathU8() if this function returns
 * NFD_OKAY */
nfdresult_t NFD_SaveDialogU8(nfdu8char_t** outPath,
                             const nfdu8filteritem_t* filterList,
                             nfdfiltersize_t count,
                             const nfdu8char_t* defaultPath,
                             const nfdu8char_t* defaultName) {
    // populate the real nfdnfilteritem_t
    FilterItem_Guard filterItemsNGuard;
    if (!CopyFilterItem(filterList, count, filterItemsNGuard)) {
        return NFD_ERROR;
    }

    // convert and normalize the default path, but only if it is not nullptr
    FreeCheck_Guard<nfdnchar_t> defaultPathNGuard;
    ConvertU8ToNative(defaultPath, defaultPathNGuard);
    NormalizePathSeparator(defaultPathNGuard.data);

    // convert the default name, but only if it is not nullptr
    FreeCheck_Guard<nfdnchar_t> defaultNameNGuard;
    ConvertU8ToNative(defaultName, defaultNameNGuard);

    // call the native function
    nfdnchar_t* outPathN;
    nfdresult_t res = NFD_SaveDialogN(
        &outPathN, filterItemsNGuard.data, count, defaultPathNGuard.data, defaultNameNGuard.data);

    if (res != NFD_OKAY) {
        return res;
    }

    // convert the outPath to UTF-8
    res = CopyWCharToNFDChar(outPathN, *outPath);

    // free the native out path, and return the result
    NFD_FreePathN(outPathN);
    return res;
}

/* select folder dialog */
/* It is the caller's responsibility to free `outPath` via NFD_FreePathU8() if this function returns
 * NFD_OKAY */
nfdresult_t NFD_PickFolderU8(nfdu8char_t** outPath, const nfdu8char_t* defaultPath) {
    // convert and normalize the default path, but only if it is not nullptr
    FreeCheck_Guard<nfdnchar_t> defaultPathNGuard;
    ConvertU8ToNative(defaultPath, defaultPathNGuard);
    NormalizePathSeparator(defaultPathNGuard.data);

    // call the native function
    nfdnchar_t* outPathN;
    nfdresult_t res = NFD_PickFolderN(&outPathN, defaultPathNGuard.data);

    if (res != NFD_OKAY) {
        return res;
    }

    // convert the outPath to UTF-8
    res = CopyWCharToNFDChar(outPathN, *outPath);

    // free the native out path, and return the result
    NFD_FreePathN(outPathN);
    return res;
}

/* Get the UTF-8 path at offset index */
/* It is the caller's responsibility to free `outPath` via NFD_FreePathU8() if this function returns
 * NFD_OKAY */
nfdresult_t NFD_PathSet_GetPathU8(const nfdpathset_t* pathSet,
                                  nfdpathsetsize_t index,
                                  nfdu8char_t** outPath) {
    // call the native function
    nfdnchar_t* outPathN;
    nfdresult_t res = NFD_PathSet_GetPathN(pathSet, index, &outPathN);

    if (res != NFD_OKAY) {
        return res;
    }

    // convert the outPath to UTF-8
    res = CopyWCharToNFDChar(outPathN, *outPath);

    // free the native out path, and return the result
    NFD_FreePathN(outPathN);
    return res;
}

nfdresult_t NFD_PathSet_EnumNextU8(nfdpathsetenum_t* enumerator, nfdu8char_t** outPath) {
    // call the native function
    nfdnchar_t* outPathN;
    nfdresult_t res = NFD_PathSet_EnumNextN(enumerator, &outPathN);

    if (res != NFD_OKAY) {
        return res;
    }

    if (outPathN) {
        // convert the outPath to UTF-8
        res = CopyWCharToNFDChar(outPathN, *outPath);

        // free the native out path, and return the result
        NFD_FreePathN(outPathN);
    } else {
        *outPath = nullptr;
        res = NFD_OKAY;
    }

    return res;
}
