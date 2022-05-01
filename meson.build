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
    'TracyC.h',
    'Tracy.hpp',
    'TracyD3D11.hpp',
    'TracyD3D12.hpp',
    'TracyLua.hpp',
    'TracyOpenCL.hpp',
    'TracyOpenGL.hpp',
    'TracyVulkan.hpp'
]

client_includes = [
    'client/tracy_concurrentqueue.h',
    'client/tracy_rpmalloc.hpp',
    'client/tracy_SPSCQueue.h',
    'client/TracyArmCpuTable.hpp',
    'client/TracyCallstack.h',
    'client/TracyCallstack.hpp',
    'client/TracyDebug.hpp',
    'client/TracyDxt1.hpp',
    'client/TracyFastVector.hpp',
    'client/TracyLock.hpp',
    'client/TracyProfiler.hpp',
    'client/TracyRingBuffer.hpp',
    'client/TracyScoped.hpp',
    'client/TracyStringHelpers.hpp',
    'client/TracySysTime.hpp',
    'client/TracySysTrace.hpp',
    'client/TracyThread.hpp'
]

common_includes = [
    'common/tracy_lz4.hpp',
    'common/tracy_lz4hc.hpp',
    'common/TracyAlign.hpp',
    'common/TracyAlign.hpp',
    'common/TracyAlloc.hpp',
    'common/TracyApi.h',
    'common/TracyColor.hpp',
    'common/TracyForceInline.hpp',
    'common/TracyMutex.hpp',
    'common/TracyProtocol.hpp',
    'common/TracyQueue.hpp',
    'common/TracySocket.hpp',
    'common/TracyStackFrames.hpp',
    'common/TracySystem.hpp',
    'common/TracyUwp.hpp',
    'common/TracyYield.hpp'
]

tracy_header_files = common_includes + client_includes + includes

tracy_src = [
    'TracyClient.cpp'
]

tracy_public_include_dirs = include_directories('.')

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
