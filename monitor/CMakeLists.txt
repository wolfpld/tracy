cmake_minimum_required(VERSION 3.16)

set(TRACY_PUBLIC_DIR ${CMAKE_CURRENT_LIST_DIR}/../public)

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/version.cmake)

set(CMAKE_CXX_STANDARD 17)

project(
    tracy-monitor
    LANGUAGES C CXX
    VERSION ${TRACY_VERSION_STRING}
)

find_package(Threads REQUIRED)

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/config.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../cmake/vendor.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../cmake/GitRef.cmake)

set(PROGRAM_FILES
    src/monitor.cpp
)

add_executable(${PROJECT_NAME} ${PROGRAM_FILES} ${TRACY_PUBLIC_DIR}/TracyClient.cpp)
target_include_directories(${PROJECT_NAME} SYSTEM PUBLIC
    $<BUILD_INTERFACE:${TRACY_PUBLIC_DIR}>
    $<INSTALL_INTERFACE:include/tracy>)
target_compile_definitions(${PROJECT_NAME} PRIVATE
    TRACY_ENABLE
    TRACY_DELAYED_INIT
    TRACY_MANUAL_LIFETIME
    TRACY_NO_FRAME_IMAGE
)
target_link_libraries(${PROJECT_NAME} PRIVATE
    Threads::Threads
    ${CMAKE_DL_LIBS}
)

add_git_ref(${PROJECT_NAME})

install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})