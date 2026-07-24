#!/bin/sh
set -eu

# Builds the profiler as an AppImage. The Wayland client libraries are built
# from a pinned release and bundled, so the core protocol version does not
# depend on what the build host provides. Everything else that is host-coupled
# (glibc, EGL, dbus, xkbcommon, OpenSSL) is left to the target system, which
# is expected to be reasonably current. The build host sets the glibc floor,
# so this should run on the oldest distro release that is still supported.

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BUILD="$ROOT/profiler/build-appimage"
PREFIX="$BUILD/wayland"
APPDIR="$BUILD/AppDir"

WAYLAND_VERSION=1.25.0
APPIMAGETOOL_URL="https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"

mkdir -p "$BUILD"

if [ ! -e "$PREFIX/lib/pkgconfig/wayland-client.pc" ]; then
    git clone --depth 1 --branch $WAYLAND_VERSION https://gitlab.freedesktop.org/wayland/wayland.git "$BUILD/wayland-src"
    meson setup "$BUILD/wayland-build" "$BUILD/wayland-src" \
        --prefix "$PREFIX" --libdir lib --buildtype release \
        -Ddocumentation=false -Dtests=false -Ddtd_validation=false
    meson install -C "$BUILD/wayland-build"
fi
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig"
export PATH="$PREFIX/bin:$PATH"

cmake -B "$BUILD/profiler" -S "$ROOT/profiler" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DNO_ISA_EXTENSIONS=ON \
    -DCMAKE_BUILD_RPATH='$ORIGIN/../lib' \
    -DDOWNLOAD_CAPSTONE=ON \
    -DDOWNLOAD_FREETYPE=ON \
    -DDOWNLOAD_LIBCURL=ON \
    -DDOWNLOAD_PUGIXML=ON \
    ${GIT_REV:+-DGIT_REV=$GIT_REV}
cmake --build "$BUILD/profiler" --parallel "$(nproc)"

rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/lib" \
    "$APPDIR/usr/share/applications" \
    "$APPDIR/usr/share/mime/packages" \
    "$APPDIR/usr/share/icons/hicolor/scalable/apps" \
    "$APPDIR/usr/share/icons/hicolor/scalable/mimetypes"

cp "$BUILD/profiler/tracy-profiler" "$APPDIR/usr/bin/"
strip "$APPDIR/usr/bin/tracy-profiler"
patchelf --set-rpath '$ORIGIN/../lib' "$APPDIR/usr/bin/tracy-profiler"
cp "$PREFIX/lib/libwayland-client.so.0" \
   "$PREFIX/lib/libwayland-cursor.so.0" \
   "$PREFIX/lib/libwayland-egl.so.1" \
   "$APPDIR/usr/lib/"
cp "$ROOT/extra/desktop/tracy.desktop" "$APPDIR/usr/share/applications/"
cp "$ROOT/extra/desktop/application-tracy.xml" "$APPDIR/usr/share/mime/packages/"
cp "$ROOT/icon/icon.svg" "$APPDIR/usr/share/icons/hicolor/scalable/apps/tracy.svg"
cp "$ROOT/icon/application-tracy.svg" "$APPDIR/usr/share/icons/hicolor/scalable/mimetypes/"
ln -s usr/share/applications/tracy.desktop "$APPDIR/tracy.desktop"
ln -s usr/share/icons/hicolor/scalable/apps/tracy.svg "$APPDIR/tracy.svg"
ln -s tracy.svg "$APPDIR/.DirIcon"
ln -s usr/bin/tracy-profiler "$APPDIR/AppRun"

ldd "$APPDIR/usr/bin/tracy-profiler"

if [ ! -x "$BUILD/appimagetool" ]; then
    curl -Lf -o "$BUILD/appimagetool" "$APPIMAGETOOL_URL"
    chmod +x "$BUILD/appimagetool"
fi
ARCH=x86_64 "$BUILD/appimagetool" --appimage-extract-and-run \
    "$APPDIR" "$BUILD/tracy-profiler-x86_64.AppImage"
