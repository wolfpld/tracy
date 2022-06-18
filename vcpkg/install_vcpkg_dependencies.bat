@echo off
setlocal

pushd %~dp0

REM get vcpkg distribution
if not exist vcpkg git clone https://github.com/Microsoft/vcpkg.git || exit /b 1

REM build vcpkg
if not exist vcpkg\vcpkg.exe call vcpkg\bootstrap-vcpkg.bat -disableMetrics || exit /b 2

set VCPKG_ROOT=%cd%\vcpkg

REM install required packages
vcpkg\vcpkg.exe install --triplet x64-windows-static || exit /b 3

popd
