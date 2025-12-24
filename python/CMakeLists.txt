set(CMAKE_CXX_STANDARD 20)

option(EXTERNAL_PYBIND11 "Whether to download pybind11" ON)

if(EXTERNAL_PYBIND11)
    find_package(Python 3.6 COMPONENTS Interpreter Development REQUIRED)

    include(FetchContent)

    FetchContent_Declare(pybind11 GIT_REPOSITORY "https://github.com/pybind/pybind11.git" GIT_TAG "v2.13.6" GIT_SHALLOW ON)
    FetchContent_MakeAvailable(pybind11)
endif()

pybind11_add_module(TracyClientBindings SHARED bindings/Module.cpp)
target_link_libraries(TracyClientBindings PUBLIC TracyClient)
target_link_libraries(TracyClientBindings PUBLIC ${Python_LIBRARIES})
if (UNIX)
  set_target_properties(TracyClientBindings PROPERTIES
    BUILD_RPATH_USE_ORIGIN TRUE
    INSTALL_RPATH "\$ORIGIN/lib")
endif ()

install(TARGETS TracyClientBindings
  RUNTIME DESTINATION .
  LIBRARY DESTINATION .
)
