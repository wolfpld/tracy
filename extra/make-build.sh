#!/bin/sh

rm -rf tracy-build
mkdir tracy-build

if [ ! -f vswhere.exe ]; then
    wget https://github.com/microsoft/vswhere/releases/download/2.8.4/vswhere.exe
fi

MSVC=`./vswhere.exe -property installationPath -version '[17.0,17.999]' | head -n 1`
MSVC=`wslpath "$MSVC" | tr -d '\r'`
MSBUILD=$MSVC/MSBuild/Current/Bin/MSBuild.exe

for i in capture csvexport import-chrome update; do
    echo $i...
    "$MSBUILD" ../$i/build/win32/$i.sln /t:Clean /p:Configuration=Release /p:Platform=x64 /noconsolelogger /nologo -m
    "$MSBUILD" ../$i/build/win32/$i.sln /t:Build /p:Configuration=Release /p:Platform=x64 /noconsolelogger /nologo -m
    cp ../$i/build/win32/x64/Release/$i.exe tracy-build/
done

echo profiler...
"$MSBUILD" ../profiler/build/win32/Tracy.sln /t:Clean /p:Configuration=Release /p:Platform=x64 /noconsolelogger /nologo -m
"$MSBUILD" ../profiler/build/win32/Tracy.sln /t:Build /p:Configuration=Release /p:Platform=x64 /noconsolelogger /nologo -m
cp ../profiler/build/win32/x64/Release/Tracy.exe tracy-build/
