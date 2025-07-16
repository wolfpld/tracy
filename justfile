cmake_prepare_args := "-DCMAKE_BUILD_TYPE=Release"

# List all available commands
list:
    just --list

# Prepare project for compilation
_prepare project build_args:
    cmake -B {{project}}/build -S {{project}} {{build_args}}


# Build project
_build project: (_prepare project cmake_prepare_args)
    cmake --build {{project}}/build --parallel --config Release

# Build all projects
_build_all: (_build 'profiler') (_build 'update') (_build 'capture') (_build 'csvexport') (_build 'import')

# Copy artifacts to bin directory
[unix]
copy_artifacts:
    mkdir -p bin
    cp profiler/build/tracy-profiler bin
    cp update/build/tracy-update bin
    cp capture/build/tracy-capture bin
    cp csvexport/build/tracy-csvexport bin
    cp import/build/tracy-import-chrome bin
    cp import/build/tracy-import-fuchsia bin
    cp import/build/tracy-import-fuchsia bin

# Copy artifacts to bin directory
[windows]
copy_artifacts:
    mkdir -p bin
    cp profiler/build/Release/tracy-profiler.exe bin
    cp update/build/Release/tracy-update.exe bin
    cp capture/build/Release/tracy-capture.exe bin
    cp csvexport/build/Release/tracy-csvexport.exe bin
    cp import/build/Release/tracy-import-chrome.exe bin
    cp import/build/Release/tracy-import-fuchsia.exe bin

# Build Tracy as library with meson
library:
    meson setup -Dprefix={{justfile_directory()}}/bin/lib build
    meson compile -C build
    meson install -C build

# Compile test. Tries to build Tracy with given flags and then cleans the build directory.
_compile_test arguments: (_prepare "test" arguments)
    cmake --build test/build --parallel
    rm -rf test/build

# Test compilation with different flags.
# It clean the build folder to reset cached variables between runs.
compile_tests:
    just _compile_test "-DCMAKE_BUILD_TYPE=Release"
    just _compile_test "-DCMAKE_BUILD_TYPE=Release -DTRACY_ON_DEMAND=ON ."
    just _compile_test "-DCMAKE_BUILD_TYPE=Release -DTRACY_DELAYED_INIT=ON -DTRACY_MANUAL_LIFETIME=ON ."
    just _compile_test "-DCMAKE_BUILD_TYPE=Release -DTRACY_DEMANGLE=ON ."

# Creates a symlink to the Tracy executable artifact.
[unix]
[working-directory: 'bin']
symlink:
    ln -s tracy-profiler tracy
