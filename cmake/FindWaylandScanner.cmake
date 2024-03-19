#.rst:
# FindWaylandScanner
# ------------------
#
# Try to find wayland-scanner.
#
# If the wayland-scanner executable is not in your PATH, you can provide
# an alternative name or full path location with the ``WaylandScanner_EXECUTABLE``
# variable.
#
# This will define the following variables:
#
# ``WaylandScanner_FOUND``
#     True if wayland-scanner is available.
#
# ``WaylandScanner_EXECUTABLE``
#     The wayland-scanner executable.
#
# If ``WaylandScanner_FOUND`` is TRUE, it will also define the following imported
# target:
#
# ``Wayland::Scanner``
#     The wayland-scanner executable.
#
# This module provides the following functions to generate C protocol
# implementations:
#
#   - ``ecm_add_wayland_client_protocol``
#   - ``ecm_add_wayland_server_protocol``
#
# ::
#
#   ecm_add_wayland_client_protocol(<source_files_var>
#                                   PROTOCOL <xmlfile>
#                                   BASENAME <basename>)
#
# Generate Wayland client protocol files from ``<xmlfile>`` XML
# definition for the ``<basename>`` interface and append those files
# to ``<source_files_var>``.
#
# ::
#
#   ecm_add_wayland_server_protocol(<source_files_var>
#                                   PROTOCOL <xmlfile>
#                                   BASENAME <basename>)
#
# Generate Wayland server protocol files from ``<xmlfile>`` XML
# definition for the ``<basename>`` interface and append those files
# to ``<source_files_var>``.
#
# Since 1.4.0.

#=============================================================================
# Copyright 2012-2014 Pier Luigi Fiorini <pierluigi.fiorini@gmail.com>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#=============================================================================

include(${CMAKE_CURRENT_LIST_DIR}/ECMFindModuleHelpers.cmake)

ecm_find_package_version_check(WaylandScanner)

# Find wayland-scanner
find_program(WaylandScanner_EXECUTABLE NAMES wayland-scanner)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(WaylandScanner
    FOUND_VAR
        WaylandScanner_FOUND
    REQUIRED_VARS
        WaylandScanner_EXECUTABLE
)

mark_as_advanced(WaylandScanner_EXECUTABLE)

if(NOT TARGET Wayland::Scanner AND WaylandScanner_FOUND)
    add_executable(Wayland::Scanner IMPORTED)
    set_target_properties(Wayland::Scanner PROPERTIES
        IMPORTED_LOCATION "${WaylandScanner_EXECUTABLE}"
    )
endif()

include(FeatureSummary)
set_package_properties(WaylandScanner PROPERTIES
    URL "https://wayland.freedesktop.org/"
    DESCRIPTION "Executable that converts XML protocol files to C code"
)

function(ecm_add_wayland_client_protocol out_var)
    # Parse arguments
    set(oneValueArgs PROTOCOL BASENAME)
    cmake_parse_arguments(ARGS "" "${oneValueArgs}" "" ${ARGN})

    if(ARGS_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR "Unknown keywords given to ecm_add_wayland_client_protocol(): \"${ARGS_UNPARSED_ARGUMENTS}\"")
    endif()

    get_filename_component(_infile ${ARGS_PROTOCOL} ABSOLUTE)
    set(_client_header "${CMAKE_CURRENT_BINARY_DIR}/wayland-${ARGS_BASENAME}-client-protocol.h")
    set(_code "${CMAKE_CURRENT_BINARY_DIR}/wayland-${ARGS_BASENAME}-protocol.c")

    set_source_files_properties(${_client_header} GENERATED)
    set_source_files_properties(${_code} GENERATED)
    set_property(SOURCE ${_client_header} PROPERTY SKIP_AUTOMOC ON)

    add_custom_command(OUTPUT "${_client_header}"
        COMMAND ${WaylandScanner_EXECUTABLE} client-header ${_infile} ${_client_header}
        DEPENDS ${WaylandScanner_EXECUTABLE} ${_infile}
        VERBATIM
    )

    add_custom_command(OUTPUT "${_code}"
        COMMAND ${WaylandScanner_EXECUTABLE} private-code ${_infile} ${_code}
        DEPENDS ${WaylandScanner_EXECUTABLE} ${_infile} ${_client_header}
        VERBATIM
    )

    list(APPEND ${out_var} "${_client_header}" "${_code}")
    set(${out_var} ${${out_var}} PARENT_SCOPE)
endfunction()


function(ecm_add_wayland_server_protocol out_var)
    # Parse arguments
    set(oneValueArgs PROTOCOL BASENAME)
    cmake_parse_arguments(ARGS "" "${oneValueArgs}" "" ${ARGN})

    if(ARGS_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR "Unknown keywords given to ecm_add_wayland_server_protocol(): \"${ARGS_UNPARSED_ARGUMENTS}\"")
    endif()

    ecm_add_wayland_client_protocol(${out_var}
                                    PROTOCOL ${ARGS_PROTOCOL}
                                    BASENAME ${ARGS_BASENAME})

    get_filename_component(_infile ${ARGS_PROTOCOL} ABSOLUTE)
    set(_server_header "${CMAKE_CURRENT_BINARY_DIR}/wayland-${ARGS_BASENAME}-server-protocol.h")
    set_property(SOURCE ${_server_header} PROPERTY SKIP_AUTOMOC ON)
    set_source_files_properties(${_server_header} GENERATED)

    add_custom_command(OUTPUT "${_server_header}"
        COMMAND ${WaylandScanner_EXECUTABLE} server-header ${_infile} ${_server_header}
        DEPENDS ${WaylandScanner_EXECUTABLE} ${_infile}
        VERBATIM
   )

    list(APPEND ${out_var} "${_server_header}")
    set(${out_var} ${${out_var}} PARENT_SCOPE)
endfunction()
