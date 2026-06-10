// platform_macos.mm — macOS backend (Cocoa + NSOpenGLView)
//
// Note: OpenGL is deprecated on macOS 10.14+, but remains functional.
// Tracy's TracyGpuContext is a no-op on Apple platforms.
//
// Compile flags:
//   clang++ -std=c++17 -ObjC++ spinning_triangle.cpp platform/platform_macos.mm \
//       -framework Cocoa -framework OpenGL -o gl_spinning_triangle

// OpenGL is only available on MacOS (no iOS support)
// Anything from Cocoa/OpenGL will spew deprecation warnings when used,
// unless GL_SILENCE_DEPRECATION has been defined beforehand
//#define GL_SILENCE_DEPRECATION
#import <Cocoa/Cocoa.h>
#import <OpenGL/OpenGL.h>
#include <CoreFoundation/CFDate.h>
#include <cstdio>
#include "platform.h"

static NSOpenGLView*  sGLView      = nullptr;
static CFAbsoluteTime sStartTime   = 0;
static void (*sRenderCb)()         = nullptr;
static void (*sShutdownCb)()       = nullptr;

@interface AppDelegate : NSObject <NSApplicationDelegate>
@property (strong) NSWindow* window;
@property (strong) NSTimer*  timer;
@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification*)notification {
    self.timer = [NSTimer scheduledTimerWithTimeInterval:1.0 / 60.0
                                                 target:self
                                               selector:@selector(tick:)
                                               userInfo:nil
                                                repeats:YES];
    [[NSRunLoop currentRunLoop] addTimer:self.timer forMode:NSRunLoopCommonModes];

    [NSEvent addLocalMonitorForEventsMatchingMask:NSEventMaskKeyDown
                                         handler:^NSEvent*(NSEvent* event) {
        if (event.keyCode == 53) { [NSApp terminate:nil]; return nil; }
        return event;
    }];

    [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
}

- (void)tick:(NSTimer*)t {
    if (sRenderCb) {
        [[sGLView openGLContext] makeCurrentContext];
        sRenderCb();
    }
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication*)app { return YES; }

- (void)applicationWillTerminate:(NSNotification*)notification {
    [self.timer invalidate];
    if (sShutdownCb) sShutdownCb();
}

@end

bool platformInit(int width, int height, const char* title) {
    [NSApplication sharedApplication];
    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];

    NSOpenGLPixelFormatAttribute attrs[] = {
        NSOpenGLPFAOpenGLProfile, NSOpenGLProfileVersion3_2Core,
        NSOpenGLPFAColorSize,     24,
        NSOpenGLPFAAlphaSize,      8,
        NSOpenGLPFADoubleBuffer,
        NSOpenGLPFAAccelerated,
        0
    };
    NSOpenGLPixelFormat* fmt = [[NSOpenGLPixelFormat alloc] initWithAttributes:attrs];
    if (!fmt) { fprintf(stderr, "Failed to create NSOpenGLPixelFormat\n"); return false; }

    NSRect frame = NSMakeRect(200, 200, width, height);
    sGLView = [[NSOpenGLView alloc] initWithFrame:frame pixelFormat:fmt];
    if (!sGLView) { fprintf(stderr, "Failed to create NSOpenGLView\n"); return false; }

    NSWindow* window = [[NSWindow alloc]
        initWithContentRect:frame
                  styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskMiniaturizable)
                    backing:NSBackingStoreBuffered
                      defer:NO];
    [window setTitle:[NSString stringWithUTF8String:title]];
    [window setContentView:sGLView];

    [[sGLView openGLContext] makeCurrentContext];

    AppDelegate* del = [[AppDelegate alloc] init];
    del.window = window;
    [NSApp setDelegate:del];

    sStartTime = CFAbsoluteTimeGetCurrent();
    return true;
}

bool platformInitGL() { return true; }

double platformGetTime() { return CFAbsoluteTimeGetCurrent() - sStartTime; }

void platformSwapBuffers() { [[sGLView openGLContext] flushBuffer]; }

void platformRunLoop(void (*render)(), void (*shutdown)()) {
    sRenderCb   = render;
    sShutdownCb = shutdown;
    @autoreleasepool { [NSApp run]; }
}
