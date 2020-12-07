workspace "Tracy"
	architecture "x86_64"
	platforms { "Win64" }
	configurations { "Debug", "Release", "ReleaseOnDemand" }
	startproject "TracyServer"

	systemversion "latest"
	flags "MultiProcessorCompile"
	
	defines {
		"_CRT_SECURE_NO_DEPRECATE",
		"_CRT_NONSTDC_NO_DEPRECATE"
	}
	
	filter { "system:windows" }
		defines {
			"WIN32_LEAN_AND_MEAN",
			"NOMINMAX",
			"_USE_MATH_DEFINES"
		}
	
	filter { "configurations:Debug" }
		defines "_DEBUG"
		symbols "On"
		optimize "Off"

	filter { "configurations:Release*" }
		defines "NDEBUG"
		symbols "Off"
		optimize "Speed"
		
	filter {}
	
	buildoptions "/sdl"  -- Security development lifecycle checks
	
project "TracyClient"
	kind "SharedLib"
	language "C++"
	
	location "Build/TracyClient/Generated"
	buildlog "Build/TracyClient/Log/Build.log"
	objdir "Build/TracyClient/Intermediate/%{cfg.platform}_%{cfg.buildcfg}"
	targetdir "Build/TracyClient/Bin/%{cfg.platform}_%{cfg.buildcfg}"
	
	targetname "TracyClient"
	
	includedirs { "profiler/libs/gl3w", "imgui", "vcpkg/vcpkg/installed/x64-windows-static/include" }
	libdirs { "lib/glfw/bin/win32" }
	
	staticruntime "Off"
	
	defines "TRACY_EXPORTS"  -- Used for multi-DLL projects
	
	filter { "configurations:Release*" }
		defines "TRACY_ENABLE"
		
	filter { "configurations:ReleaseOnDemand" }
		defines "TRACY_ON_DEMAND"
	
	filter {}
	
	files "TracyClient.cpp"
	
project "TracyServer"
	kind "WindowedApp"
	language "C++"
	cppdialect "C++17"
	
	location "Build/TracyServer/Generated"
	buildlog "Build/TracyServer/Log/Build.log"
	objdir "Build/TracyServer/Intermediate/%{cfg.platform}_%{cfg.buildcfg}"
	targetdir "Build/TracyServer/Bin/%{cfg.platform}_%{cfg.buildcfg}"
	
	targetname "TracyServer"
	
	configmap {
		["ReleaseOnDemand"] = "Release"  -- On demand mode doesn't apply to the server
	}
	
	characterset "MBCS"
	floatingpoint "Fast"
	staticruntime "Off"
	warnings "Extra"
	vectorextensions "AVX2"
	
	buildoptions {
		"/diagnostics:caret",  -- Diagnostics format
		"/permissive-"  -- Enable conformance mode
	}
	
	filter { "configurations:Release" }
		functionlevellinking "On"
		buildoptions {
			"/GL",  -- Enable whole program optimization
			"/Oi"  -- Enable intrinsic functions
		}
		
	filter {}
	
	includedirs { "profiler/libs/gl3w", "imgui", "vcpkg/vcpkg/installed/x64-windows-static/include" }
	
	filter { "configurations:Debug" }
		libdirs "vcpkg/vcpkg/installed/x64-windows-static/debug/lib"
		
	filter { "configurations:Release" }
		libdirs "vcpkg/vcpkg/installed/x64-windows-static/lib"
		
	filter {}
	
	defines {
		"TRACY_FILESELECTOR",
		"TRACY_EXTENDED_FONT",
		"TRACY_ROOT_WINDOW"
	}
	
	files {
		"common/*.h",
		"common/*.hpp",
		"common/*.cpp",
		"imgui/*.h",
		"imgui/*.cpp",
		"nfd/*.h",
		"nfd/nfd_common.c",
		"server/*.h",
		"server/*.hpp",
		"server/*.cpp",
		"profiler/src/*.h",
		"profiler/src/*.hpp",
		"profiler/src/*.cpp",
		"profiler/libs/gl3w/**.*",
		"zstd/*.h",
		"zstd/*.c"
	}
	
	filter { "system:windows" }
		files "nfd/nfd_win.cpp"
	
	filter { "system:not windows" }
		files "nfd/nfd_gtk.c"
		removefiles "profiler/src/winmain*.*"
		
	filter {}
	
	links {
		"brotlicommon-static",
		"brotlidec-static",
		"ws2_32",
		"opengl32",
		"glfw3",
		"capstone"
	}
	
	filter { "configurations:Debug" }
		links {
			"freetyped",
			"libpng16d",
			"zlibd",
			"bz2d"
		}
		
	filter { "configurations:Release" }
		links {
			"freetype",
			"libpng16",
			"zlib",
			"bz2"
		}
		
	filter {}