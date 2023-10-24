project('tracy', ['cpp'], version: '0.10.0')

tracy_compile_args = []

if get_option('tracy_enable')
  tracy_compile_args += ['-DTRACY_ENABLE']
endif

if get_option('tracy_on_demand')
  tracy_compile_args += ['-DTRACY_ON_DEMAND']
endif

if get_option('tracy_callstack')
  tracy_compile_args += ['-DTRACY_CALLSTACK']
endif

if get_option('tracy_no_callstack')
  tracy_compile_args += ['-DTRACY_NO_CALLSTACK']
endif

if get_option('tracy_no_callstack_inlines')
  tracy_compile_args += ['-DTRACY_NO_CALLSTACK_INLINES']
endif

if get_option('tracy_only_localhost')
  tracy_compile_args += ['-DTRACY_ONLY_LOCALHOST']
endif

if get_option('tracy_no_broadcast')
  tracy_compile_args += ['-DTRACY_NO_BROADCAST']
endif

if get_option('tracy_only_ipv4')
  tracy_compile_args += ['-DTRACY_ONLY_IPV4']
endif

if get_option('tracy_no_code_transfer')
  tracy_compile_args += ['-DTRACY_NO_CODE_TRANSFER']
endif

if get_option('tracy_no_context_switch')
  tracy_compile_args += ['-DTRACY_NO_CONTEXT_SWITCH']
endif

if get_option('tracy_no_exit')
  tracy_compile_args += ['-DTRACY_NO_EXIT']
endif

if get_option('tracy_no_sampling')
  tracy_compile_args += ['-DTRACY_NO_SAMPLING']
endif

if get_option('tracy_no_verify')
  tracy_compile_args += ['-DTRACY_NO_VERIFY']
endif

if get_option('tracy_no_vsync_capture')
  tracy_compile_args += ['-DTRACY_NO_VSYNC_CAPTURE']
endif

if get_option('tracy_no_frame_image')
  tracy_compile_args += ['-DTRACY_NO_FRAME_IMAGE']
endif

if get_option('tracy_no_system_tracing')
  tracy_compile_args += ['-DTRACY_NO_SYSTEM_TRACING']
endif

if get_option('tracy_patchable_nopsleds')
  tracy_compile_args += ['-DTRACY_PATCHABLE_NOPSLEDS']
endif

if get_option('tracy_delayed_init')
  tracy_compile_args += ['-DTRACY_DELAYED_INIT']
endif

if get_option('tracy_manual_lifetime')
  tracy_compile_args += ['-DTRACY_MANUAL_LIFETIME']
endif

if get_option('tracy_fibers')
  tracy_compile_args += ['-DTRACY_FIBERS']
endif

if get_option('tracy_timer_fallback')
  tracy_compile_args += ['-DTRACY_TIMER_FALLBACK']
endif

tracy_shared_libs = get_option('tracy_shared_libs')
if tracy_shared_libs
  add_project_arguments('-DTRACY_EXPORTS', language : 'cpp')
endif

if get_option('tracy_no_crash_handler')
  tracy_compile_args += ['-DTRACY_NO_CRASH_HANDLER']
endif

add_project_arguments(tracy_compile_args, language : 'cpp')

threads_dep = dependency('threads')

if host_machine.system() == 'windows'
  add_project_arguments('-DWINVER=0x0601', '-D_WIN32_WINNT=0x0601',  language: 'cpp')
endif

includes = [
    'public/tracy/TracyC.h',
    'public/tracy/Tracy.hpp',
    'public/tracy/TracyD3D11.hpp',
    'public/tracy/TracyD3D12.hpp',
    'public/tracy/TracyLua.hpp',
    'public/tracy/TracyOpenCL.hpp',
    'public/tracy/TracyOpenGL.hpp',
    'public/tracy/TracyVulkan.hpp'
]

client_includes = [
    'public/client/tracy_concurrentqueue.h',
    'public/client/tracy_rpmalloc.hpp',
    'public/client/tracy_SPSCQueue.h',
    'public/client/TracyArmCpuTable.hpp',
    'public/client/TracyCallstack.h',
    'public/client/TracyCallstack.hpp',
    'public/client/TracyDebug.hpp',
    'public/client/TracyDxt1.hpp',
    'public/client/TracyFastVector.hpp',
    'public/client/TracyLock.hpp',
    'public/client/TracyProfiler.hpp',
    'public/client/TracyRingBuffer.hpp',
    'public/client/TracyScoped.hpp',
    'public/client/TracyStringHelpers.hpp',
    'public/client/TracySysPower.hpp',
    'public/client/TracySysTime.hpp',
    'public/client/TracySysTrace.hpp',
    'public/client/TracyThread.hpp'
]

common_includes = [
    'public/common/tracy_lz4.hpp',
    'public/common/tracy_lz4hc.hpp',
    'public/common/TracyAlign.hpp',
    'public/common/TracyAlloc.hpp',
    'public/common/TracyApi.h',
    'public/common/TracyColor.hpp',
    'public/common/TracyForceInline.hpp',
    'public/common/TracyMutex.hpp',
    'public/common/TracyProtocol.hpp',
    'public/common/TracyQueue.hpp',
    'public/common/TracySocket.hpp',
    'public/common/TracyStackFrames.hpp',
    'public/common/TracySystem.hpp',
    'public/common/TracyUwp.hpp',
    'public/common/TracyYield.hpp'
]

tracy_header_files = common_includes + client_includes + includes

tracy_src = [
    'public/TracyClient.cpp'
]

tracy_public_include_dirs = include_directories('public')

compiler = meson.get_compiler('cpp')
override_options = []
if compiler.get_id() != 'msvc'
  override_options += 'cpp_std=c++11'
endif

if tracy_shared_libs
  tracy = shared_library('tracy', tracy_src, tracy_header_files,
    dependencies        : [ threads_dep ],
    include_directories : tracy_public_include_dirs,
    override_options    : override_options,
    install             : true)
else
  tracy = static_library('tracy', tracy_src, tracy_header_files,
    dependencies        : [ threads_dep ],
    include_directories : tracy_public_include_dirs,
    override_options    : override_options,
    install             : true)
endif

install_headers(includes, subdir : 'tracy')
install_headers(common_includes, subdir : 'common')
install_headers(client_includes, subdir : 'client')

tracy_dep_compile_args = tracy_compile_args

if tracy_shared_libs
  tracy_dep_compile_args += [ '-DTRACY_IMPORTS' ]
endif

pkg = import('pkgconfig')
pkg.generate(tracy, extra_cflags: tracy_dep_compile_args)

tracy_dep = declare_dependency(
    compile_args        : tracy_dep_compile_args,
    link_with           : tracy,
    include_directories : tracy_public_include_dirs)

meson.override_dependency('tracy', tracy_dep)
