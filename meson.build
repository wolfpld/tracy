project('tracy', ['cpp'])

if get_option('tracy_enable')
  add_project_arguments('-DTRACY_ENABLE', language : 'cpp')
endif

if get_option('tracy_on_demand')
  add_project_arguments('-DTRACY_ON_DEMAND', language : 'cpp')
endif

if get_option('tracy_callstack')
  add_project_arguments('-DTRACY_CALLSTACK', language : 'cpp')
endif

if get_option('tracy_no_callstack')
  add_project_arguments('-DTRACY_NO_CALLSTACK', language : 'cpp')
endif

if get_option('tracy_no_callstack_inlines')
  add_project_arguments('-DTRACY_NO_CALLSTACK_INLINES', language : 'cpp')
endif

if get_option('tracy_only_localhost')
  add_project_arguments('-DTRACY_ONLY_LOCALHOST', language : 'cpp')
endif

if get_option('tracy_no_broadcast')
  add_project_arguments('-DTRACY_NO_BROADCAST', language : 'cpp')
endif

if get_option('tracy_only_ipv4')
  add_project_arguments('-DTRACY_ONLY_IPV4', language : 'cpp')
endif

if get_option('tracy_no_code_transfer')
  add_project_arguments('-DTRACY_NO_CODE_TRANSFER', language : 'cpp')
endif

if get_option('tracy_no_context_switch')
  add_project_arguments('-DTRACY_NO_CONTEXT_SWITCH', language : 'cpp')
endif

if get_option('tracy_no_exit')
  add_project_arguments('-DTRACY_NO_EXIT', language : 'cpp')
endif

if get_option('tracy_no_sampling')
  add_project_arguments('-DTRACY_NO_SAMPLING', language : 'cpp')
endif

if get_option('tracy_no_verify')
  add_project_arguments('-DTRACY_NO_VERIFY', language : 'cpp')
endif

if get_option('tracy_no_vsync_capture')
  add_project_arguments('-DTRACY_NO_VSYNC_CAPTURE', language : 'cpp')
endif

if get_option('tracy_no_frame_image')
  add_project_arguments('-DTRACY_NO_FRAME_IMAGE', language : 'cpp')
endif

if get_option('tracy_no_system_tracing')
  add_project_arguments('-DTRACY_NO_SYSTEM_TRACING', language : 'cpp')
endif

if get_option('tracy_delayed_init')
  add_project_arguments('-DTRACY_DELAYED_INIT', language : 'cpp')
endif

if get_option('tracy_manual_lifetime')
  add_project_arguments('-DTRACY_MANUAL_LIFETIME', language : 'cpp')
endif

if get_option('tracy_fibers')
  add_project_arguments('-DTRACY_FIBERS', language : 'cpp')
endif

if get_option('tracy_timer_fallback')
  add_project_arguments('-DTRACY_TIMER_FALLBACK', language : 'cpp')
endif

tracy_shared_libs = get_option('tracy_shared_libs')
if tracy_shared_libs
  add_project_arguments('-DTRACY_EXPORTS', language : 'cpp')
endif

if get_option('tracy_no_crash_handler')
  add_project_arguments('-DTRACY_NO_CRASH_HANDLER', language : 'cpp')
endif

threads_dep = dependency('threads')

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
    'public/client/TracySysTime.hpp',
    'public/client/TracySysTrace.hpp',
    'public/client/TracyThread.hpp'
]

common_includes = [
    'public/common/tracy_lz4.hpp',
    'public/common/tracy_lz4hc.hpp',
    'public/common/TracyAlign.hpp',
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

install_headers(includes)
install_headers(common_includes, subdir : 'common')
install_headers(client_includes, subdir : 'client')

tracy_dep_compile_args = []

if tracy_shared_libs
  tracy_dep_compile_args += [ '-DTRACY_IMPORTS' ]
endif

tracy_dep = declare_dependency(
    compile_args        : tracy_dep_compile_args,
    link_with           : tracy,
    include_directories : tracy_public_include_dirs)

tracy_dep_dynamic = declare_dependency(
    include_directories : tracy_public_include_dirs)

meson.override_dependency('tracy', tracy_dep)
