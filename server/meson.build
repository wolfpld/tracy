server_sources = files(
        'TracyBadVersion.cpp',
        'TracyColor.cpp', 
        # 'TracyEventDebug.cpp', 
        'TracyFilesystem.cpp', 
        'TracyImGui.cpp',
        'TracyMemory.cpp',
        'TracyMicroArchitecture.cpp',
        'TracyMmap.cpp',
        'TracyMouse.cpp',
        'TracyPrint.cpp',
        'TracyProtoHistory.cpp',
        'TracySourceContents.cpp',
        'TracySourceTokenizer.cpp',
        'TracySourceView.cpp',
        'TracyStorage.cpp',
        'TracyTaskDispatch.cpp',
        'TracyTexture.cpp',
        'TracyTextureCompression.cpp',
        'TracyThreadCompression.cpp',
        'TracyTexture.cpp')

capstone = dependency('capstone')

deps = [imgui_dep, capstone, tracy_dep]
server_lib = static_library('tracy_server', server_sources, dependencies: deps)
server_dep = declare_dependency(dependencies: deps, link_with: server_lib)