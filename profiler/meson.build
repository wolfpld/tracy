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
    'src/WindowPosition.cpp')

if get_option('tracy_gtk_fileselector')
    profiler_sources += files('../nfd/nfd_gtk.cpp')
endif

profiler_inc = include_directories('src', 'src/imgui')

glfw = dependency('glfw3')

executable('profiler', profiler_sources, include_directories: profiler_inc, dependencies: [glfw, threads_dep, server_dep, tracy_dep])