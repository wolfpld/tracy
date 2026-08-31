set(PANDOC_VERSION 3.9.0.2)

find_package(Python3 COMPONENTS Interpreter REQUIRED)

find_program(TRACY_PANDOC pandoc)
if(TRACY_PANDOC)
    execute_process(
        COMMAND ${TRACY_PANDOC} --version
        OUTPUT_VARIABLE _pandoc_version
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE _pandoc_rc
        ERROR_QUIET)
    string(REGEX MATCH "pandoc [0-9.]+" _pandoc_version "${_pandoc_version}")
    if(NOT _pandoc_rc EQUAL 0 OR NOT _pandoc_version STREQUAL "pandoc ${PANDOC_VERSION}")
        set(TRACY_PANDOC "")
    endif()
endif()
if(TRACY_PANDOC)
    message(STATUS "Using system pandoc ${PANDOC_VERSION}: ${TRACY_PANDOC}")
else()
    if(WIN32)
        if(NOT CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64)$")
            message(FATAL_ERROR "No pinned pandoc ${PANDOC_VERSION} binary for ${CMAKE_HOST_SYSTEM_PROCESSOR}; install pandoc ${PANDOC_VERSION}")
        endif()
        set(_pandoc_asset pandoc-${PANDOC_VERSION}-windows-x86_64.zip)
        set(_pandoc_hash c97542f2800f446e788d9f74237856d995421ad1bb3cc8324286840c5f272d3a)
        set(_pandoc_exe pandoc-${PANDOC_VERSION}/pandoc.exe)
    elseif(APPLE)
        if(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)$")
            set(_pandoc_asset pandoc-${PANDOC_VERSION}-arm64-macOS.zip)
            set(_pandoc_hash 6e9eca844076bcbb599bbeebbba78a70f93b5307782b85c2c272872812c88875)
            set(_pandoc_exe pandoc-${PANDOC_VERSION}-arm64/bin/pandoc)
        elseif(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64)$")
            set(_pandoc_asset pandoc-${PANDOC_VERSION}-x86_64-macOS.zip)
            set(_pandoc_hash b9fbceabccbc8f34ac021a50483fc32f8160568d0b4b2c22d81bb29e3054fd82)
            set(_pandoc_exe pandoc-${PANDOC_VERSION}-x86_64/bin/pandoc)
        else()
            message(FATAL_ERROR "No pinned pandoc ${PANDOC_VERSION} binary for ${CMAKE_HOST_SYSTEM_PROCESSOR}; install pandoc ${PANDOC_VERSION}")
        endif()
    else()
        if(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
            set(_pandoc_asset pandoc-${PANDOC_VERSION}-linux-arm64.tar.gz)
            set(_pandoc_hash b6d21e8f9c3b15744f5a7ab40248019157ed7793875dbe0383d4c82ff572b528)
            set(_pandoc_exe pandoc-${PANDOC_VERSION}/bin/pandoc)
        elseif(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64)$")
            set(_pandoc_asset pandoc-${PANDOC_VERSION}-linux-amd64.tar.gz)
            set(_pandoc_hash a69abfababda8a56969a254b09f9553a7be89ddec00d4e0fe9fd585d71a67508)
        set(_pandoc_exe pandoc-${PANDOC_VERSION}/bin/pandoc)
        else()
            message(FATAL_ERROR "No pinned pandoc ${PANDOC_VERSION} binary for ${CMAKE_HOST_SYSTEM_PROCESSOR}; install pandoc ${PANDOC_VERSION}")
        endif()
    endif()

    set(TRACY_PANDOC ${CMAKE_BINARY_DIR}/tools/${_pandoc_exe})
    if(NOT EXISTS ${TRACY_PANDOC})
        message(STATUS "Downloading pandoc ${PANDOC_VERSION} (${_pandoc_asset})")
        file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/tools)
        file(DOWNLOAD
            https://github.com/jgm/pandoc/releases/download/${PANDOC_VERSION}/${_pandoc_asset}
            ${CMAKE_BINARY_DIR}/tools/pandoc.archive
            EXPECTED_HASH SHA256=${_pandoc_hash}
            STATUS _pandoc_download)
        list(GET _pandoc_download 0 _pandoc_download_rc)
        if(NOT _pandoc_download_rc STREQUAL "0")
            file(REMOVE ${CMAKE_BINARY_DIR}/tools/pandoc.archive)
            message(FATAL_ERROR "Failed to download pandoc ${PANDOC_VERSION}: ${_pandoc_download}")
        endif()
        file(ARCHIVE_EXTRACT
            INPUT ${CMAKE_BINARY_DIR}/tools/pandoc.archive
            DESTINATION ${CMAKE_BINARY_DIR}/tools)
        file(REMOVE ${CMAKE_BINARY_DIR}/tools/pandoc.archive)
    endif()
endif()
