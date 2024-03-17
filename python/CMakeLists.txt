find_package(Python 3.6 COMPONENTS Interpreter Development REQUIRED)

include(FetchContent)

FetchContent_Declare(pybind11 GIT_REPOSITORY "https://github.com/pybind/pybind11.git" GIT_TAG "v2.11.1" GIT_SHALLOW ON TEST_BEFORE_INSTALL ON)
FetchContent_MakeAvailable(pybind11)

set(BUFFER_SIZE 128 CACHE STRING "The size of the pointer buffer")
set(NAME_LENGTH 128 CACHE STRING "The length of a name in the buffer")

pybind11_add_module(TracyClientBindings SHARED bindings/Module.cpp)
target_link_libraries(TracyClientBindings PUBLIC TracyClient)
target_compile_definitions(TracyClientBindings PUBLIC BUFFER_SIZE=${BUFFER_SIZE})
target_compile_definitions(TracyClientBindings PUBLIC NAME_LENGTH=${NAME_LENGTH})

set(TRACY_PYTHON_DIR ${CMAKE_CURRENT_SOURCE_DIR}/tracy_client)
set(TRACY_LIB_SYMLINK $<TARGET_FILE_PREFIX:TracyClient>$<TARGET_FILE_BASE_NAME:TracyClient>$<TARGET_FILE_SUFFIX:TracyClient>)

add_custom_command(TARGET TracyClient TracyClientBindings POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${TRACY_PYTHON_DIR}/client
    COMMAND ${CMAKE_COMMAND} -E copy ${client_includes} ${TRACY_PYTHON_DIR}/client
    COMMAND ${CMAKE_COMMAND} -DFOLDER=${TRACY_PYTHON_DIR}/client -P ${CMAKE_CURRENT_SOURCE_DIR}/HeaderFixer.txt

    COMMAND ${CMAKE_COMMAND} -E make_directory ${TRACY_PYTHON_DIR}/common
    COMMAND ${CMAKE_COMMAND} -E copy ${common_includes} ${TRACY_PYTHON_DIR}/common
    COMMAND ${CMAKE_COMMAND} -DFOLDER=${TRACY_PYTHON_DIR}/common -P ${CMAKE_CURRENT_SOURCE_DIR}/HeaderFixer.txt

    COMMAND ${CMAKE_COMMAND} -E make_directory ${TRACY_PYTHON_DIR}/tracy
    COMMAND ${CMAKE_COMMAND} -E copy ${tracy_includes} ${TRACY_PYTHON_DIR}/tracy
    COMMAND ${CMAKE_COMMAND} -DFOLDER=${TRACY_PYTHON_DIR}/tracy -P ${CMAKE_CURRENT_SOURCE_DIR}/HeaderFixer.txt

    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:TracyClientBindings> ${TRACY_PYTHON_DIR}/

    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:TracyClient> ${TRACY_PYTHON_DIR}/
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/../${TRACY_LIB_SYMLINK} ${TRACY_PYTHON_DIR}/

    BYPRODUCTS ${TRACY_PYTHON_DIR}/client ${TRACY_PYTHON_DIR}/common ${TRACY_PYTHON_DIR}/tracy
)

set(TRACY_CLIENT_PYTHON_TARGET "" CACHE STRING "Optional directory to copy python files to")

if(NOT TRACY_CLIENT_PYTHON_TARGET STREQUAL "")
    file(GLOB_RECURSE TRACY_CLIENT_PYTHON_FILES ${TRACY_PYTHON_DIR}/*.py*)
    add_custom_command(TARGET TracyClientBindings POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory ${TRACY_CLIENT_PYTHON_TARGET}
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:TracyClientBindings> ${TRACY_CLIENT_PYTHON_TARGET}/
        COMMAND ${CMAKE_COMMAND} -E copy ${TRACY_CLIENT_PYTHON_FILES} ${TRACY_CLIENT_PYTHON_TARGET}/
        BYPRODUCTS ${TRACY_CLIENT_PYTHON_TARGET}
    )
endif()
