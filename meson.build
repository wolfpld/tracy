project('tracy', ['cpp'], version: '0.11.0', meson_version: '>=1.1.0')

# internal compiler flags
tracy_compile_args = []

# compiler flags shared between the capture library itself and the code using it
tracy_common_args = []

# dependencies that will be propagated to the users of the capture library
tracy_public_deps = []

if get_option('tracy_enable')
  tracy_common_args += ['-DTRACY_ENABLE']
endif

if get_option('on_demand')
  tracy_common_args += ['-DTRACY_ON_DEMAND']
endif

if get_option('callstack')
  tracy_common_args += ['-DTRACY_CALLSTACK']
endif

if get_option('no_callstack')
  tracy_common_args += ['-DTRACY_NO_CALLSTACK']
endif

if get_option('no_callstack_inlines')
  tracy_common_args += ['-DTRACY_NO_CALLSTACK_INLINES']
endif

if get_option('only_localhost')
  tracy_common_args += ['-DTRACY_ONLY_LOCALHOST']
endif

if get_option('no_broadcast')
  tracy_common_args += ['-DTRACY_NO_BROADCAST']
endif

if get_option('only_ipv4')
  tracy_common_args += ['-DTRACY_ONLY_IPV4']
endif

if get_option('no_code_transfer')
  tracy_common_args += ['-DTRACY_NO_CODE_TRANSFER']
endif

if get_option('no_context_switch')
  tracy_common_args += ['-DTRACY_NO_CONTEXT_SWITCH']
endif

if get_option('no_exit')
  tracy_common_args += ['-DTRACY_NO_EXIT']
endif

if get_option('no_sampling')
  tracy_common_args += ['-DTRACY_NO_SAMPLING']
endif

if get_option('no_verify')
  tracy_common_args += ['-DTRACY_NO_VERIFY']
endif

if get_option('no_vsync_capture')
  tracy_common_args += ['-DTRACY_NO_VSYNC_CAPTURE']
endif

if get_option('no_frame_image')
  tracy_common_args += ['-DTRACY_NO_FRAME_IMAGE']
endif

if get_option('no_system_tracing')
  tracy_common_args += ['-DTRACY_NO_SYSTEM_TRACING']
endif

if get_option('patchable_nopsleds')
  tracy_common_args += ['-DTRACY_PATCHABLE_NOPSLEDS']
endif

if get_option('delayed_init')
  tracy_common_args += ['-DTRACY_DELAYED_INIT']
endif

if get_option('manual_lifetime')
  tracy_common_args += ['-DTRACY_MANUAL_LIFETIME']
endif

if get_option('fibers')
  tracy_common_args += ['-DTRACY_FIBERS']
endif

if get_option('timer_fallback')
  tracy_common_args += ['-DTRACY_TIMER_FALLBACK']
endif

if get_option('no_crash_handler')
  tracy_common_args += ['-DTRACY_NO_CRASH_HANDLER']
endif

if get_option('libunwind_backtrace')
  tracy_common_args += ['-DTRACY_LIBUNWIND_BACKTRACE']
  tracy_public_deps += dependency('libunwind')
endif

if get_option('symbol_offline_resolve')
  tracy_compile_args += ['-DTRACY_SYMBOL_OFFLINE_RESOLVE']
endif

if get_option('libbacktrace_elf_dynload_support')
  tracy_compile_args += ['-DTRACY_LIBBACKTRACE_ELF_DYNLOAD_SUPPORT']
endif

if get_option('verbose')
  tracy_common_args += ['-DTRACY_VERBOSE']
endif

if get_option('debuginfod')
  tracy_common_args += ['-DTRACY_DEBUGINFOD']
  tracy_public_deps += dependency('libdebuginfod')
endif

tracy_shared_libs = get_option('default_library') == 'shared'

if tracy_shared_libs
  tracy_compile_args += ['-DTRACY_EXPORTS']
endif

if host_machine.system() == 'windows'
  tracy_compile_args += ['-DWINVER=0x0601', '-D_WIN32_WINNT=0x0601']
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
if compiler.get_id() != 'msvc' and compiler.get_id() != 'clang-cl'
  override_options += 'cpp_std=c++11'
endif

tracy_compile_args += tracy_common_args

tracy_deps = [dependency('threads')] + tracy_public_deps

tracy = library('tracy', tracy_src, tracy_header_files,
    dependencies        : tracy_deps,
    include_directories : tracy_public_include_dirs,
    cpp_args            : tracy_compile_args,
    override_options    : override_options,
    install             : true)

install_headers(includes, subdir : 'tracy')
install_headers(common_includes, subdir : 'common')
install_headers(client_includes, subdir : 'client')

tracy_dep_compile_args = tracy_common_args

if tracy_shared_libs
  tracy_dep_compile_args += [ '-DTRACY_IMPORTS' ]
endif

pkg = import('pkgconfig')
pkg.generate(tracy,
  extra_cflags : tracy_dep_compile_args,
  requires     : tracy_public_deps)

tracy_dep = declare_dependency(
    compile_args        : tracy_dep_compile_args,
    link_with           : tracy,
    include_directories : tracy_public_include_dirs)

meson.override_dependency('tracy', tracy_dep)
