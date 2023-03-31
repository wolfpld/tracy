add_library(public.common STATIC tracy_lz4.cpp tracy_lz4hc.cpp TracySocket.cpp
                                 TracyStackFrames.cpp TracySystem.cpp)

set_default_compile_options(public.common)

if(WIN32)
  find_library(Wsock32 wsock32 REQUIRED)
  find_library(Ws2_32 ws2_32 REQUIRED)
  target_link_libraries(public.common PUBLIC Wsock32 Ws2_32)
endif()
