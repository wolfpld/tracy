/*
  Native File Dialog Extended
  Repository: https://github.com/btzy/nativefiledialog-extended
  License: Zlib
  Authors: Bernard Teo, Michael Labbe
 */

#include <AppKit/AppKit.h>
#include "nfd.h"

static const char* g_errorstr = NULL;

static void NFDi_SetError(const char* msg) {
    g_errorstr = msg;
}

static void* NFDi_Malloc(size_t bytes) {
    void* ptr = malloc(bytes);
    if (!ptr) NFDi_SetError("NFDi_Malloc failed.");

    return ptr;
}

static void NFDi_Free(void* ptr) {
    assert(ptr);
    free(ptr);
}

static NSArray* BuildAllowedFileTypes(const nfdnfilteritem_t* filterList,
                                      nfdfiltersize_t filterCount) {
    // Commas and semicolons are the same thing on this platform

    NSMutableArray* buildFilterList = [[NSMutableArray alloc] init];

    for (nfdfiltersize_t filterIndex = 0; filterIndex != filterCount; ++filterIndex) {
        // this is the spec to parse (we don't use the friendly name on OS X)
        const nfdnchar_t* filterSpec = filterList[filterIndex].spec;

        const nfdnchar_t* p_currentFilterBegin = filterSpec;
        for (const nfdnchar_t* p_filterSpec = filterSpec; *p_filterSpec; ++p_filterSpec) {
            if (*p_filterSpec == ',') {
                // add the extension to the array
                NSString* filterStr = [[[NSString alloc]
                    initWithBytes:(const void*)p_currentFilterBegin
                           length:(sizeof(nfdnchar_t) * (p_filterSpec - p_currentFilterBegin))
                         encoding:NSUTF8StringEncoding] autorelease];
                [buildFilterList addObject:filterStr];
                p_currentFilterBegin = p_filterSpec + 1;
            }
        }
        // add the extension to the array
        NSString* filterStr = [NSString stringWithUTF8String:p_currentFilterBegin];
        [buildFilterList addObject:filterStr];
    }

    NSArray* returnArray = [NSArray arrayWithArray:buildFilterList];

    [buildFilterList release];

    assert([returnArray count] != 0);

    return returnArray;
}

static void AddFilterListToDialog(NSSavePanel* dialog,
                                  const nfdnfilteritem_t* filterList,
                                  nfdfiltersize_t filterCount) {
    // note: NSOpenPanel inherits from NSSavePanel.

    if (!filterCount) return;

    assert(filterList);

    // make NSArray of file types
    NSArray* allowedFileTypes = BuildAllowedFileTypes(filterList, filterCount);

    // set it on the dialog
    [dialog setAllowedFileTypes:allowedFileTypes];
}

static void SetDefaultPath(NSSavePanel* dialog, const nfdnchar_t* defaultPath) {
    if (!defaultPath || !*defaultPath) return;

    NSString* defaultPathString = [NSString stringWithUTF8String:defaultPath];
    NSURL* url = [NSURL fileURLWithPath:defaultPathString isDirectory:YES];
    [dialog setDirectoryURL:url];
}

static void SetDefaultName(NSSavePanel* dialog, const nfdnchar_t* defaultName) {
    if (!defaultName || !*defaultName) return;

    NSString* defaultNameString = [NSString stringWithUTF8String:defaultName];
    [dialog setNameFieldStringValue:defaultNameString];
}

static nfdresult_t CopyUtf8String(const char* utf8Str, nfdnchar_t** out) {
    // byte count, not char count
    size_t len = strlen(utf8Str);

    // Too bad we have to use additional memory for all the result paths,
    // because we cannot reconstitute an NSString from a char* to release it properly.
    *out = (nfdnchar_t*)NFDi_Malloc(len + 1);
    if (*out) {
        strcpy(*out, utf8Str);
        return NFD_OKAY;
    }

    return NFD_ERROR;
}

/* public */

const char* NFD_GetError(void) {
    return g_errorstr;
}

void NFD_FreePathN(nfdnchar_t* filePath) {
    NFDi_Free((void*)filePath);
}

static NSApplicationActivationPolicy old_app_policy;

nfdresult_t NFD_Init(void) {
    NSApplication* app = [NSApplication sharedApplication];
    old_app_policy = [app activationPolicy];
    if (old_app_policy == NSApplicationActivationPolicyProhibited) {
        if (![app setActivationPolicy:NSApplicationActivationPolicyAccessory]) {
            NFDi_SetError("Failed to set activation policy.");
            return NFD_ERROR;
        }
    }
    return NFD_OKAY;
}

/* call this to de-initialize NFD, if NFD_Init returned NFD_OKAY */
void NFD_Quit(void) {
    [[NSApplication sharedApplication] setActivationPolicy:old_app_policy];
}

nfdresult_t NFD_OpenDialogN(nfdnchar_t** outPath,
                            const nfdnfilteritem_t* filterList,
                            nfdfiltersize_t filterCount,
                            const nfdnchar_t* defaultPath) {
    nfdresult_t result = NFD_CANCEL;
    @autoreleasepool {
        NSWindow* keyWindow = [[NSApplication sharedApplication] keyWindow];

        NSOpenPanel* dialog = [NSOpenPanel openPanel];
        [dialog setAllowsMultipleSelection:NO];

        // Build the filter list
        AddFilterListToDialog(dialog, filterList, filterCount);

        // Set the starting directory
        SetDefaultPath(dialog, defaultPath);

        if ([dialog runModal] == NSModalResponseOK) {
            const NSURL* url = [dialog URL];
            const char* utf8Path = [[url path] UTF8String];
            result = CopyUtf8String(utf8Path, outPath);
        }

        // return focus to the key window (i.e. main window)
        [keyWindow makeKeyAndOrderFront:nil];
    }
    return result;
}

nfdresult_t NFD_OpenDialogMultipleN(const nfdpathset_t** outPaths,
                                    const nfdnfilteritem_t* filterList,
                                    nfdfiltersize_t filterCount,
                                    const nfdnchar_t* defaultPath) {
    nfdresult_t result = NFD_CANCEL;
    @autoreleasepool {
        NSWindow* keyWindow = [[NSApplication sharedApplication] keyWindow];

        NSOpenPanel* dialog = [NSOpenPanel openPanel];
        [dialog setAllowsMultipleSelection:YES];

        // Build the filter list
        AddFilterListToDialog(dialog, filterList, filterCount);

        // Set the starting directory
        SetDefaultPath(dialog, defaultPath);

        if ([dialog runModal] == NSModalResponseOK) {
            const NSArray* urls = [dialog URLs];

            if ([urls count] > 0) {
                // have at least one URL, we return this NSArray
                [urls retain];
                *outPaths = (const nfdpathset_t*)urls;
                result = NFD_OKAY;
            }
        }

        // return focus to the key window (i.e. main window)
        [keyWindow makeKeyAndOrderFront:nil];
    }
    return result;
}

nfdresult_t NFD_SaveDialogN(nfdnchar_t** outPath,
                            const nfdnfilteritem_t* filterList,
                            nfdfiltersize_t filterCount,
                            const nfdnchar_t* defaultPath,
                            const nfdnchar_t* defaultName) {
    nfdresult_t result = NFD_CANCEL;
    @autoreleasepool {
        NSWindow* keyWindow = [[NSApplication sharedApplication] keyWindow];

        NSSavePanel* dialog = [NSSavePanel savePanel];
        [dialog setExtensionHidden:NO];
        // allow other file types, to give the user an escape hatch since you can't select "*.*" on
        // Mac
        [dialog setAllowsOtherFileTypes:TRUE];

        // Build the filter list
        AddFilterListToDialog(dialog, filterList, filterCount);

        // Set the starting directory
        SetDefaultPath(dialog, defaultPath);

        // Set the default file name
        SetDefaultName(dialog, defaultName);

        if ([dialog runModal] == NSModalResponseOK) {
            const NSURL* url = [dialog URL];
            const char* utf8Path = [[url path] UTF8String];
            result = CopyUtf8String(utf8Path, outPath);
        }

        // return focus to the key window (i.e. main window)
        [keyWindow makeKeyAndOrderFront:nil];
    }
    return result;
}

nfdresult_t NFD_PickFolderN(nfdnchar_t** outPath, const nfdnchar_t* defaultPath) {
    nfdresult_t result = NFD_CANCEL;
    @autoreleasepool {
        NSWindow* keyWindow = [[NSApplication sharedApplication] keyWindow];

        NSOpenPanel* dialog = [NSOpenPanel openPanel];
        [dialog setAllowsMultipleSelection:NO];
        [dialog setCanChooseDirectories:YES];
        [dialog setCanCreateDirectories:YES];
        [dialog setCanChooseFiles:NO];

        // Set the starting directory
        SetDefaultPath(dialog, defaultPath);

        if ([dialog runModal] == NSModalResponseOK) {
            const NSURL* url = [dialog URL];
            const char* utf8Path = [[url path] UTF8String];
            result = CopyUtf8String(utf8Path, outPath);
        }

        // return focus to the key window (i.e. main window)
        [keyWindow makeKeyAndOrderFront:nil];
    }
    return result;
}

nfdresult_t NFD_PathSet_GetCount(const nfdpathset_t* pathSet, nfdpathsetsize_t* count) {
    const NSArray* urls = (const NSArray*)pathSet;
    *count = [urls count];
    return NFD_OKAY;
}

nfdresult_t NFD_PathSet_GetPathN(const nfdpathset_t* pathSet,
                                 nfdpathsetsize_t index,
                                 nfdnchar_t** outPath) {
    const NSArray* urls = (const NSArray*)pathSet;

    @autoreleasepool {
        // autoreleasepool needed because UTF8String method might use the pool
        const NSURL* url = [urls objectAtIndex:index];
        const char* utf8Path = [[url path] UTF8String];
        return CopyUtf8String(utf8Path, outPath);
    }
}

void NFD_PathSet_Free(const nfdpathset_t* pathSet) {
    const NSArray* urls = (const NSArray*)pathSet;
    [urls release];
}

nfdresult_t NFD_PathSet_GetEnum(const nfdpathset_t* pathSet, nfdpathsetenum_t* outEnumerator) {
    const NSArray* urls = (const NSArray*)pathSet;

    @autoreleasepool {
        // autoreleasepool needed because NSEnumerator uses it
        NSEnumerator* enumerator = [urls objectEnumerator];
        [enumerator retain];
        outEnumerator->ptr = (void*)enumerator;
    }

    return NFD_OKAY;
}

void NFD_PathSet_FreeEnum(nfdpathsetenum_t* enumerator) {
    NSEnumerator* real_enum = (NSEnumerator*)enumerator->ptr;
    [real_enum release];
}

nfdresult_t NFD_PathSet_EnumNextN(nfdpathsetenum_t* enumerator, nfdnchar_t** outPath) {
    NSEnumerator* real_enum = (NSEnumerator*)enumerator->ptr;

    @autoreleasepool {
        // autoreleasepool needed because NSURL uses it
        const NSURL* url = [real_enum nextObject];
        if (url) {
            const char* utf8Path = [[url path] UTF8String];
            return CopyUtf8String(utf8Path, outPath);
        } else {
            *outPath = NULL;
            return NFD_OKAY;
        }
    }
}
