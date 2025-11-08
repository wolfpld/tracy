project('tracy-opencl-layer', 'cpp',
  meson_version: '>=1.1',
)

tracy_dep = dependency('tracy',
  static: true,
)
opencl_dep = dependency('OpenCL')

sources = files(
  'tracy-layer.cpp',
)

shared_library('tracy-opencl-layer',
  sources,
  dependencies: [tracy_dep,opencl_dep],
)
