#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <emscripten/html5.h>
#include <backends/imgui_impl_opengl3.h>

#include "Backend.hpp"
#include "RunQueue.hpp"
#include "profiler/TracyImGui.hpp"

static std::function<void()> s_redraw;
static std::function<void(float)> s_scaleChanged;
static std::function<int(void)> s_isBusy;
static RunQueue* s_mainThreadTasks;

static EGLDisplay s_eglDpy;
static EGLContext s_eglCtx;
static EGLSurface s_eglSurf;

static float s_prevScale = -1;
static int s_width, s_height;
static uint64_t s_time;
static const char* s_prevCursor = nullptr;

static ImGuiKey TranslateKeyCode( const char* code )
{
    if( strcmp( code, "Backquote" ) == 0 ) return ImGuiKey_GraveAccent;
    if( strcmp( code, "Backslash" ) == 0 ) return ImGuiKey_Backslash;
    if( strcmp( code, "BracketLeft" ) == 0 ) return ImGuiKey_LeftBracket;
    if( strcmp( code, "BracketRight" ) == 0 ) return ImGuiKey_RightBracket;
    if( strcmp( code, "Comma" ) == 0 ) return ImGuiKey_Comma;
    if( strcmp( code, "Digit0" ) == 0 ) return ImGuiKey_0;
    if( strcmp( code, "Digit1" ) == 0 ) return ImGuiKey_1;
    if( strcmp( code, "Digit2" ) == 0 ) return ImGuiKey_2;
    if( strcmp( code, "Digit3" ) == 0 ) return ImGuiKey_3;
    if( strcmp( code, "Digit4" ) == 0 ) return ImGuiKey_4;
    if( strcmp( code, "Digit5" ) == 0 ) return ImGuiKey_5;
    if( strcmp( code, "Digit6" ) == 0 ) return ImGuiKey_6;
    if( strcmp( code, "Digit7" ) == 0 ) return ImGuiKey_7;
    if( strcmp( code, "Digit8" ) == 0 ) return ImGuiKey_8;
    if( strcmp( code, "Digit9" ) == 0 ) return ImGuiKey_9;
    if( strcmp( code, "Equal" ) == 0 ) return ImGuiKey_Equal;
    if( strcmp( code, "IntlBackslash" ) == 0 ) return ImGuiKey_Backslash;
    if( strcmp( code, "IntlRo" ) == 0 ) return ImGuiKey_Backslash;
    if( strcmp( code, "IntlYen" ) == 0 ) return ImGuiKey_Backslash;
    if( strcmp( code, "KeyA" ) == 0 ) return ImGuiKey_A;
    if( strcmp( code, "KeyB" ) == 0 ) return ImGuiKey_B;
    if( strcmp( code, "KeyC" ) == 0 ) return ImGuiKey_C;
    if( strcmp( code, "KeyD" ) == 0 ) return ImGuiKey_D;
    if( strcmp( code, "KeyE" ) == 0 ) return ImGuiKey_E;
    if( strcmp( code, "KeyF" ) == 0 ) return ImGuiKey_F;
    if( strcmp( code, "KeyG" ) == 0 ) return ImGuiKey_G;
    if( strcmp( code, "KeyH" ) == 0 ) return ImGuiKey_H;
    if( strcmp( code, "KeyI" ) == 0 ) return ImGuiKey_I;
    if( strcmp( code, "KeyJ" ) == 0 ) return ImGuiKey_J;
    if( strcmp( code, "KeyK" ) == 0 ) return ImGuiKey_K;
    if( strcmp( code, "KeyL" ) == 0 ) return ImGuiKey_L;
    if( strcmp( code, "KeyM" ) == 0 ) return ImGuiKey_M;
    if( strcmp( code, "KeyN" ) == 0 ) return ImGuiKey_N;
    if( strcmp( code, "KeyO" ) == 0 ) return ImGuiKey_O;
    if( strcmp( code, "KeyP" ) == 0 ) return ImGuiKey_P;
    if( strcmp( code, "KeyQ" ) == 0 ) return ImGuiKey_Q;
    if( strcmp( code, "KeyR" ) == 0 ) return ImGuiKey_R;
    if( strcmp( code, "KeyS" ) == 0 ) return ImGuiKey_S;
    if( strcmp( code, "KeyT" ) == 0 ) return ImGuiKey_T;
    if( strcmp( code, "KeyU" ) == 0 ) return ImGuiKey_U;
    if( strcmp( code, "KeyV" ) == 0 ) return ImGuiKey_V;
    if( strcmp( code, "KeyW" ) == 0 ) return ImGuiKey_W;
    if( strcmp( code, "KeyX" ) == 0 ) return ImGuiKey_X;
    if( strcmp( code, "KeyY" ) == 0 ) return ImGuiKey_Y;
    if( strcmp( code, "KeyZ" ) == 0 ) return ImGuiKey_Z;
    if( strcmp( code, "Minus" ) == 0 ) return ImGuiKey_Minus;
    if( strcmp( code, "Period" ) == 0 ) return ImGuiKey_Period;
    if( strcmp( code, "Quote" ) == 0 ) return ImGuiKey_Apostrophe;
    if( strcmp( code, "Semicolon" ) == 0 ) return ImGuiKey_Semicolon;
    if( strcmp( code, "Slash" ) == 0 ) return ImGuiKey_Slash;
    if( strcmp( code, "AltLeft" ) == 0 ) return ImGuiKey_LeftAlt;
    if( strcmp( code, "AltRight" ) == 0 ) return ImGuiKey_RightAlt;
    if( strcmp( code, "Backspace" ) == 0 ) return ImGuiKey_Backspace;
    if( strcmp( code, "CapsLock" ) == 0 ) return ImGuiKey_CapsLock;
    if( strcmp( code, "ContextMenu" ) == 0 ) return ImGuiKey_Menu;
    if( strcmp( code, "ControlLeft" ) == 0 ) return ImGuiKey_LeftCtrl;
    if( strcmp( code, "ControlRight" ) == 0 ) return ImGuiKey_RightCtrl;
    if( strcmp( code, "Enter" ) == 0 ) return ImGuiKey_Enter;
    if( strcmp( code, "MetaLeft" ) == 0 ) return ImGuiKey_LeftSuper;
    if( strcmp( code, "MetaRight" ) == 0 ) return ImGuiKey_RightSuper;
    if( strcmp( code, "ShiftLeft" ) == 0 ) return ImGuiKey_LeftShift;
    if( strcmp( code, "ShiftRight" ) == 0 ) return ImGuiKey_RightShift;
    if( strcmp( code, "Space" ) == 0 ) return ImGuiKey_Space;
    if( strcmp( code, "Tab" ) == 0 ) return ImGuiKey_Tab;
    if( strcmp( code, "Delete" ) == 0 ) return ImGuiKey_Delete;
    if( strcmp( code, "End" ) == 0 ) return ImGuiKey_End;
    if( strcmp( code, "Home" ) == 0 ) return ImGuiKey_Home;
    if( strcmp( code, "Insert" ) == 0 ) return ImGuiKey_Insert;
    if( strcmp( code, "PageDown" ) == 0 ) return ImGuiKey_PageDown;
    if( strcmp( code, "PageUp" ) == 0 ) return ImGuiKey_PageUp;
    if( strcmp( code, "ArrowDown" ) == 0 ) return ImGuiKey_DownArrow;
    if( strcmp( code, "ArrowLeft" ) == 0 ) return ImGuiKey_LeftArrow;
    if( strcmp( code, "ArrowRight" ) == 0 ) return ImGuiKey_RightArrow;
    if( strcmp( code, "ArrowUp" ) == 0 ) return ImGuiKey_UpArrow;
    if( strcmp( code, "NumLock" ) == 0 ) return ImGuiKey_NumLock;
    if( strcmp( code, "Numpad0" ) == 0 ) return ImGuiKey_Keypad0;
    if( strcmp( code, "Numpad1" ) == 0 ) return ImGuiKey_Keypad1;
    if( strcmp( code, "Numpad2" ) == 0 ) return ImGuiKey_Keypad2;
    if( strcmp( code, "Numpad3" ) == 0 ) return ImGuiKey_Keypad3;
    if( strcmp( code, "Numpad4" ) == 0 ) return ImGuiKey_Keypad4;
    if( strcmp( code, "Numpad5" ) == 0 ) return ImGuiKey_Keypad5;
    if( strcmp( code, "Numpad6" ) == 0 ) return ImGuiKey_Keypad6;
    if( strcmp( code, "Numpad7" ) == 0 ) return ImGuiKey_Keypad7;
    if( strcmp( code, "Numpad8" ) == 0 ) return ImGuiKey_Keypad8;
    if( strcmp( code, "Numpad9" ) == 0 ) return ImGuiKey_Keypad9;
    if( strcmp( code, "NumpadAdd" ) == 0 ) return ImGuiKey_KeypadAdd;
    if( strcmp( code, "NumpadBackspace" ) == 0 ) return ImGuiKey_Backspace;
    if( strcmp( code, "NumpadComma" ) == 0 ) return ImGuiKey_KeypadDecimal;
    if( strcmp( code, "NumpadDecimal" ) == 0 ) return ImGuiKey_KeypadDecimal;
    if( strcmp( code, "NumpadDivide" ) == 0 ) return ImGuiKey_KeypadDivide;
    if( strcmp( code, "NumpadEnter" ) == 0 ) return ImGuiKey_KeypadEnter;
    if( strcmp( code, "NumpadEqual" ) == 0 ) return ImGuiKey_KeypadEqual;
    if( strcmp( code, "NumpadMultiply" ) == 0 ) return ImGuiKey_KeypadMultiply;
    if( strcmp( code, "NumpadSubtract" ) == 0 ) return ImGuiKey_KeypadSubtract;
    if( strcmp( code, "Escape" ) == 0 ) return ImGuiKey_Escape;
    if( strcmp( code, "F1" ) == 0 ) return ImGuiKey_F1;
    if( strcmp( code, "F2" ) == 0 ) return ImGuiKey_F2;
    if( strcmp( code, "F3" ) == 0 ) return ImGuiKey_F3;
    if( strcmp( code, "F4" ) == 0 ) return ImGuiKey_F4;
    if( strcmp( code, "F5" ) == 0 ) return ImGuiKey_F5;
    if( strcmp( code, "F6" ) == 0 ) return ImGuiKey_F6;
    if( strcmp( code, "F7" ) == 0 ) return ImGuiKey_F7;
    if( strcmp( code, "F8" ) == 0 ) return ImGuiKey_F8;
    if( strcmp( code, "F9" ) == 0 ) return ImGuiKey_F9;
    if( strcmp( code, "F10" ) == 0 ) return ImGuiKey_F10;
    // F11 is browser fullscreen, F12 is browser dev tools, omitting them
    if( strcmp( code, "ScrollLock" ) == 0 ) return ImGuiKey_ScrollLock;
    if( strcmp( code, "Pause" ) == 0 ) return ImGuiKey_Pause;
    return ImGuiKey_None;
}

Backend::Backend( const char* title, const std::function<void()>& redraw, const std::function<void(float)>& scaleChanged, const std::function<int(void)>& isBusy, RunQueue* mainThreadTasks )
{
    constexpr EGLint eglConfigAttrib[] = {
        EGL_SURFACE_TYPE, EGL_WINDOW_BIT,
        EGL_RED_SIZE, 8,
        EGL_GREEN_SIZE, 8,
        EGL_BLUE_SIZE, 8,
        EGL_RENDERABLE_TYPE, EGL_OPENGL_BIT,
        EGL_NONE
    };

    s_eglDpy = eglGetDisplay( EGL_DEFAULT_DISPLAY );
    EGLBoolean res;
    res = eglInitialize( s_eglDpy, nullptr, nullptr );
    if( res != EGL_TRUE ) { fprintf( stderr, "Cannot initialize EGL!\n" ); exit( 1 ); }

    EGLint count;
    EGLConfig eglConfig;
    res = eglChooseConfig( s_eglDpy, eglConfigAttrib, &eglConfig, 1, &count );
    if( res != EGL_TRUE || count != 1 ) { fprintf( stderr, "No suitable EGL config found!\n" ); exit( 1 ); }

    s_eglSurf = eglCreateWindowSurface( s_eglDpy, eglConfig, 0, nullptr );

    constexpr EGLint eglCtxAttrib[] = {
        EGL_CONTEXT_CLIENT_VERSION, 2,
        EGL_NONE
    };

    s_eglCtx = eglCreateContext( s_eglDpy, eglConfig, EGL_NO_CONTEXT, eglCtxAttrib );
    if( !s_eglCtx ) { fprintf( stderr, "Cannot create OpenGL 3.2 Core Profile context!\n" ); exit( 1 ); }
    res = eglMakeCurrent( s_eglDpy, s_eglSurf, s_eglSurf, s_eglCtx );
    if( res != EGL_TRUE ) { fprintf( stderr, "Cannot make EGL context current!\n" ); exit( 1 ); }

    ImGui_ImplOpenGL3_Init( "#version 100" );

    EM_ASM( document.title = UTF8ToString($0), title );

    s_redraw = redraw;
    s_scaleChanged = scaleChanged;
    s_isBusy = isBusy;
    s_mainThreadTasks = mainThreadTasks;

    ImGuiIO& io = ImGui::GetIO();
    io.BackendPlatformName = "wasm (tracy profiler)";

    emscripten_set_mousedown_callback( "#canvas", nullptr, EM_TRUE, []( int, const EmscriptenMouseEvent* e, void* ) -> EM_BOOL {
        ImGui::GetIO().AddMouseButtonEvent( e->button == 0 ? 0 : 3 - e->button, true );
        tracy::s_wasActive = true;
        return EM_TRUE;
    } );
    emscripten_set_mouseup_callback( "#canvas", nullptr, EM_TRUE, []( int, const EmscriptenMouseEvent* e, void* ) -> EM_BOOL {
        ImGui::GetIO().AddMouseButtonEvent( e->button == 0 ? 0 : 3 - e->button, false );
        tracy::s_wasActive = true;
        return EM_TRUE;
    } );
    emscripten_set_mousemove_callback( "#canvas", nullptr, EM_TRUE, []( int, const EmscriptenMouseEvent* e, void* ) -> EM_BOOL {
        const auto scale = EM_ASM_DOUBLE( { return window.devicePixelRatio; } );
        ImGui::GetIO().AddMousePosEvent( e->targetX * scale, e->targetY * scale );
        tracy::s_wasActive = true;
        return EM_TRUE;
    } );
    emscripten_set_mouseleave_callback( "#canvas", nullptr, EM_TRUE, []( int, const EmscriptenMouseEvent*, void* ) -> EM_BOOL {
        ImGui::GetIO().AddFocusEvent( false );
        tracy::s_wasActive = true;
        return EM_TRUE;
    } );
    emscripten_set_mouseenter_callback( "#canvas", nullptr, EM_TRUE, []( int, const EmscriptenMouseEvent*, void* ) -> EM_BOOL {
        ImGui::GetIO().AddFocusEvent( true );
        tracy::s_wasActive = true;
        return EM_TRUE;
    } );
    emscripten_set_wheel_callback( "#canvas", nullptr, EM_TRUE, []( int, const EmscriptenWheelEvent* e, void* ) -> EM_BOOL {
        ImGui::GetIO().AddMouseWheelEvent( e->deltaX * -0.05, e->deltaY * -0.05 );
        tracy::s_wasActive = true;
        return EM_TRUE;
    } );
    emscripten_set_keydown_callback( EMSCRIPTEN_EVENT_TARGET_WINDOW, nullptr, EM_TRUE, [] ( int, const EmscriptenKeyboardEvent* e, void* ) -> EM_BOOL {
        const auto code = TranslateKeyCode( e->code );
        if( code == ImGuiKey_None ) return EM_FALSE;
        ImGui::GetIO().AddKeyEvent( code, true );
        if( e->key[0] && !e->key[1] ) ImGui::GetIO().AddInputCharacter( *e->key );
        return EM_TRUE;
    } );
    emscripten_set_keyup_callback( EMSCRIPTEN_EVENT_TARGET_WINDOW, nullptr, EM_TRUE, [] ( int, const EmscriptenKeyboardEvent* e, void* ) -> EM_BOOL {
        const auto code = TranslateKeyCode( e->code );
        if( code == ImGuiKey_None ) return EM_FALSE;
        ImGui::GetIO().AddKeyEvent( code, false );
        return EM_TRUE;
    } );

    s_time = std::chrono::duration_cast<std::chrono::microseconds>( std::chrono::high_resolution_clock::now().time_since_epoch() ).count();
}

Backend::~Backend()
{
}

void Backend::Show()
{
}

void Backend::Run()
{
    emscripten_set_main_loop( []() {
        s_redraw();
        s_mainThreadTasks->Run();
    }, 0, 1 );
}

void Backend::Attention()
{
}

void Backend::NewFrame( int& w, int& h )
{
    const auto scale = GetDpiScale();
    if( scale != s_prevScale )
    {
        s_prevScale = scale;
        s_scaleChanged( scale );
    }

    w = EM_ASM_INT( { return window.innerWidth; } ) * scale;
    h = EM_ASM_INT( { return window.innerHeight; } ) * scale;

    if( s_width != w || s_height != h )
    {
        EM_ASM( Module.canvas.style.width = window.innerWidth + 'px'; Module.canvas.style.height = window.innerHeight + 'px' );
        EM_ASM( Module.canvas.width = $0; Module.canvas.height = $1, w, h );

        s_width = w;
        s_height = h;

        glViewport( 0, 0, s_width, s_height );
        tracy::s_wasActive = true;
    }

    ImGuiIO& io = ImGui::GetIO();
    io.DisplaySize = ImVec2( w, h );
    io.DisplayFramebufferScale = ImVec2( 1, 1 );

    ImGui_ImplOpenGL3_NewFrame();

    ImGuiMouseCursor cursor = ImGui::GetMouseCursor();
    const char* cursorName;
    switch( cursor )
    {
    case ImGuiMouseCursor_None:         cursorName = "none"; break;
    case ImGuiMouseCursor_Arrow:
        switch( s_isBusy() )
        {
        default:
        case 0: cursorName = "default"; break;
        case 1: cursorName = "progress"; break;
        case 2: cursorName = "wait"; break;
        }
        break;
    case ImGuiMouseCursor_TextInput:    cursorName = "text"; break;
    case ImGuiMouseCursor_ResizeAll:    cursorName = "move"; break;
    case ImGuiMouseCursor_ResizeNS:     cursorName = "ns-resize"; break;
    case ImGuiMouseCursor_ResizeEW:     cursorName = "ew-resize"; break;
    case ImGuiMouseCursor_ResizeNESW:   cursorName = "nesw-resize"; break;
    case ImGuiMouseCursor_ResizeNWSE:   cursorName = "nwse-resize"; break;
    case ImGuiMouseCursor_Hand:         cursorName = "pointer"; break;
    case ImGuiMouseCursor_NotAllowed:   cursorName = "not-allowed"; break;
    default:                            cursorName = "auto"; break;
    };
    if( s_prevCursor != cursorName )
    {
        s_prevCursor = cursorName;
        EM_ASM_INT( { document.getElementById('canvas').style.cursor = UTF8ToString($0); }, cursorName );
    }

    uint64_t time = std::chrono::duration_cast<std::chrono::microseconds>( std::chrono::high_resolution_clock::now().time_since_epoch() ).count();
    io.DeltaTime = std::min( 0.1f, ( time - s_time ) / 1000000.f );
    s_time = time;
}

void Backend::EndFrame()
{
    const ImVec4 clear_color = ImColor( 20, 20, 17 );

    ImGui::Render();
    glClearColor( clear_color.x, clear_color.y, clear_color.z, clear_color.w );
    glClear( GL_COLOR_BUFFER_BIT );
    ImGui_ImplOpenGL3_RenderDrawData( ImGui::GetDrawData() );
}

void Backend::SetIcon( uint8_t* data, int w, int h )
{
}

void Backend::SetTitle( const char* title )
{
    EM_ASM( document.title = UTF8ToString($0), title );
}

float Backend::GetDpiScale()
{
    return EM_ASM_DOUBLE( { return window.devicePixelRatio; } );
}
