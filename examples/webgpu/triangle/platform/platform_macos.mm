// platform_macos.mm — macOS backend (Cocoa + CAMetalLayer)
//
// Compile flags (see spinning_triangle.cpp header for full invocation):
//   -ObjC++ -framework Cocoa -framework Metal -framework QuartzCore \
//   -framework Foundation -framework IOKit -framework IOSurface

#import <Cocoa/Cocoa.h>
#import <QuartzCore/CAMetalLayer.h>
#include <CoreFoundation/CFDate.h>
#include <webgpu/webgpu.h>
#include "platform.h"

static CAMetalLayer*  sMetalLayer  = nullptr;
static CFAbsoluteTime sStartTime   = 0;
static void (*sRenderCb)()         = nullptr;
static void (*sShutdownCb)()       = nullptr;

// ---------------------------------------------------------------------------
// Cocoa app — window, metal layer, render timer
// ---------------------------------------------------------------------------

@interface AppDelegate : NSObject <NSApplicationDelegate, NSWindowDelegate>
@property (strong) NSWindow* window;
@property (strong) NSTimer*  timer;
@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification*)notification {
    // ~60 fps render loop
    self.timer = [NSTimer scheduledTimerWithTimeInterval:1.0 / 60.0
                                                 target:self
                                               selector:@selector(tick:)
                                               userInfo:nil
                                                repeats:YES];
    [[NSRunLoop currentRunLoop] addTimer:self.timer forMode:NSRunLoopCommonModes];

    [NSEvent addLocalMonitorForEventsMatchingMask:NSEventMaskKeyDown
                                         handler:^NSEvent*(NSEvent* event) {
        if (event.keyCode == 53) { // kVK_Escape
            [NSApp terminate:nil];
            return nil;
        }
        return event;
    }];

    [self.window makeKeyAndOrderFront:nil];
}

- (void)tick:(NSTimer*)t {
    if (sRenderCb) sRenderCb();
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication*)app {
    return YES;
}

- (void)applicationWillTerminate:(NSNotification*)notification {
    [self.timer invalidate];
    if (sShutdownCb) sShutdownCb();
}

@end

// ---------------------------------------------------------------------------
// Platform interface implementation
// ---------------------------------------------------------------------------

bool platformInit(int width, int height, const char* title) {
    NSApplication* app = [NSApplication sharedApplication];
    [app setActivationPolicy:NSApplicationActivationPolicyRegular];

    NSRect frame = NSMakeRect(200, 200, width, height);
    NSWindow* window = [[NSWindow alloc]
        initWithContentRect:frame
                  styleMask:(NSWindowStyleMaskTitled |
                             NSWindowStyleMaskClosable |
                             NSWindowStyleMaskMiniaturizable)
                    backing:NSBackingStoreBuffered
                      defer:NO];
    [window setTitle:[NSString stringWithUTF8String:title]];

    // Metal-backed layer
    NSView* contentView = [window contentView];
    [contentView setWantsLayer:YES];
    sMetalLayer = [CAMetalLayer layer];
    sMetalLayer.frame = contentView.bounds;
    sMetalLayer.contentsScale = [window backingScaleFactor];
    sMetalLayer.pixelFormat = MTLPixelFormatBGRA8Unorm;
    [contentView.layer addSublayer:sMetalLayer];

    AppDelegate* del = [[AppDelegate alloc] init];
    del.window = window;
    [app setDelegate:del];

    sStartTime = CFAbsoluteTimeGetCurrent();
    return true;
}

WGPUSurface platformCreateSurface(WGPUInstance instance) {
    WGPUSurfaceSourceMetalLayer metalSrc = {};
    metalSrc.chain.sType = WGPUSType_SurfaceSourceMetalLayer;
    metalSrc.layer = sMetalLayer;

    WGPUSurfaceDescriptor surfDesc = {};
    surfDesc.nextInChain = (WGPUChainedStruct*)&metalSrc;
    return wgpuInstanceCreateSurface(instance, &surfDesc);
}

double platformGetTime() {
    return CFAbsoluteTimeGetCurrent() - sStartTime;
}

void platformRunLoop(void (*render)(), void (*shutdown)()) {
    sRenderCb   = render;
    sShutdownCb = shutdown;
    @autoreleasepool {
        [[NSApplication sharedApplication] run];
    }
}
