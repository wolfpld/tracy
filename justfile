cmake_prepare_args := "-DCMAKE_BUILD_TYPE=Release"

# List all available commands
list:
    just --list

# Prepare project for compilation
[group('general')]
_prepare project build_args:
    cmake -B {{project}}/build -S {{project}} {{build_args}}


# Build project
[group('general')]
build project: (_prepare project cmake_prepare_args)
    cmake --build {{project}}/build --parallel --config Release

# Build all projects
[group('general')]
build_all: (build 'profiler') (build 'update') (build 'capture') (build 'csvexport') (build 'import')

# Copy artifacts to bin directory
[group('general')]
[unix]
copy_artifacts:
    mkdir -p bin
    cp */build/tracy-* bin

# Copy artifacts to bin directory
[group('general')]
[windows]
copy_artifacts:
    mkdir -p bin
    cp */build/Release/tracy-*.exe bin

# Strip binaries artifacts
[group('general')]
[linux]
strip_binary:
    strip bin/tracy-*

# Build Tracy as library with meson
[group('general')]
library:
    meson setup -Dprefix={{justfile_directory()}}/bin/lib build
    meson compile -C build
    meson install -C build

# Compile test. Tries to build Tracy with given flags and then cleans the build directory.
[group('general')]
_compile_test arguments: (_prepare "test" arguments)
    cmake --build test/build --parallel
    rm -rf test/build

# Test compilation with different flags.
# It clean the build folder to reset cached variables between runs.
[group('general')]
compile_tests:
    just _compile_test "-DCMAKE_BUILD_TYPE=Release"
    just _compile_test "-DCMAKE_BUILD_TYPE=Release -DTRACY_ON_DEMAND=ON ."
    just _compile_test "-DCMAKE_BUILD_TYPE=Release -DTRACY_DELAYED_INIT=ON -DTRACY_MANUAL_LIFETIME=ON ."
    just _compile_test "-DCMAKE_BUILD_TYPE=Release -DTRACY_DEMANGLE=ON ."

# Perform a build for web
[group('web')]
web_build sha:
    cmake -G Ninja -B profiler/build -S profiler -DCMAKE_BUILD_TYPE=MinSizeRel -DGIT_REV={{sha}} -DCMAKE_TOOLCHAIN_FILE=${EMSDK}/upstream/emscripten/cmake/Modules/Platform/Emscripten.cmake
    cmake --build profiler/build --parallel

# compress web build artifacts
[group('web')]
web_compress_artifacts:
    zstd -18 profiler/build/tracy-profiler.js profiler/build/tracy-profiler.wasm
    gzip -9 profiler/build/tracy-profiler.js profiler/build/tracy-profiler.wasm

# Copy web build artifacts
[group('web')]
web_copy_artifacts:
    mkdir -p bin
    cp profiler/build/index.html bin
    cp profiler/build/favicon.svg bin
    cp profiler/build/tracy-profiler.data bin
    cp profiler/build/tracy-profiler.js.gz bin
    cp profiler/build/tracy-profiler.js.zst bin
    cp profiler/build/tracy-profiler.wasm.gz bin
    cp profiler/build/tracy-profiler.wasm.zst bin

# Creates a symlink to the Tracy executable artifact.
[unix]
[working-directory: 'bin']
[group('general')]
symlink:
    ln -s tracy-profiler tracy
