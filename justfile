cmake_build_args := if os() == "macos" { "-DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON" } else { "-DCMAKE_BUILD_TYPE=Release"}

build project:
    cmake -B {{project}}/build -S {{project}} {{cmake_build_args}}
    cmake --build {{project}}/build --parallel --config Release

build_all:
    just build profiler
    just build update
    just build capture
    just build csvexport
    just build import

[unix]
copy_artifacts:
    mkdir -p bin
    cp profiler/build/tracy-profiler bin
    cp update/build/tracy-update bin
    cp capture/build/tracy-capture bin
    cp csvexport/build/tracy-csvexport bin
    cp import/build/tracy-import-chrome bin
    cp import/build/tracy-import-fuchsia bin

[windows]
copy_artifacts:
    mkdir -p bin
    copy profiler\build\Release\tracy-profiler.exe bin
    cp update\build\Release\tracy-update.exe bin
    cp capture\build\Release\tracy-capture.exe bin
    cp csvexport\build\Release\tracy-csvexport.exe bin
    cp import\build\Release\tracy-import-chrome.exe bin
    cp import\build\Release\tracy-import-fuchsia.exe bin

library:
    meson setup -Dprefix={{justfile_directory()}}/bin/lib build
    meson compile -C build
    meson install -C build

compile_test:
    # test compilation with different flags
    # we clean the build folder to reset cached variables between runs
    cmake -B test/build -S test -DCMAKE_BUILD_TYPE=Release
    cmake --build test/build --parallel
    rm -rf test/build
    # same with TRACY_ON_DEMAND
    cmake -B test/build -S test -DCMAKE_BUILD_TYPE=Release -DTRACY_ON_DEMAND=ON .
    cmake --build test/build --parallel
    rm -rf test/build
    # same with TRACY_DELAYED_INIT TRACY_MANUAL_LIFETIME
    cmake -B test/build -S test -DCMAKE_BUILD_TYPE=Release -DTRACY_DELAYED_INIT=ON -DTRACY_MANUAL_LIFETIME=ON .
    cmake --build test/build --parallel
    rm -rf test/build
    # same with TRACY_DEMANGLE
    cmake -B test/build -S test -DCMAKE_BUILD_TYPE=Release -DTRACY_DEMANGLE=ON .
    cmake --build test/build --parallel
    rm -rf test/build
