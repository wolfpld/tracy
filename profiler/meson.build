profiler_sources = files(
    'src/main.cpp', 
    'src/BackendGlfw.cpp', 
    'src/ConnectionHistory.cpp', 
    'src/Filters.cpp', 
    'src/Fonts.cpp',
    'src/HttpRequest.cpp',
    'src/ImGuiContext.cpp', 
    'src/ResolvService.cpp',
    'src/RunQueue.cpp',
    'src/WindowPosition.cpp',
    'src/imgui/imgui_impl_glfw.cpp',
    'src/imgui/imgui_impl_opengl3.cpp')

glfw = dependency('glfw3')
deps = [glfw, threads_dep, server_dep, tracy_dep, zstd_dep]

if get_option('tracy_fileselector') == 'gtk'
    profiler_sources += files('../nfd/nfd_gtk.cpp')
    deps += dependency('gtk+-3.0')
endif

if get_option('tracy_use_wayland')
    deps += dependency('wayland-client')
endif

profiler_inc = include_directories('src', 'src/imgui')

executable('profiler', profiler_sources, include_directories: profiler_inc, dependencies: deps, cpp_args: '-UTRACY_ENABLE')