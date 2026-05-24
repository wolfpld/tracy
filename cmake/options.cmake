# Reusable option macros for CMake projects
#
# Usage:
#   set_option(OPTION_NAME "Help text" ON/OFF)     - for boolean options
#   set_option_value(VAR_NAME "Help text" "value") - for value options (CACHE STRING)
#
# The tracy_set_option* variants optionally propagate the option as a PUBLIC
# compile definition on a target passed as trailing argument. Without a target
# they behave identically to the bare helpers above.

# Boolean options (ON/OFF)
macro(set_option option help value)
    option(${option} ${help} ${value})
    if(${option})
        message(STATUS "${option}: ON")
    else()
        message(STATUS "${option}: OFF")
    endif()
endmacro()

# Value options (strings, numbers, etc.)
macro(set_option_value var help default)
    set(${var} ${default} CACHE STRING "${help}")
    if(${var})
        message(STATUS "${var}: ${${var}}")
    else()
        message(STATUS "${var}: (not set)")
    endif()
endmacro()

# Boolean option, optionally propagated as PUBLIC compile definition.
macro(tracy_set_option option help value)
    set_option(${option} "${help}" ${value})
    if(${option} AND ${ARGC} GREATER 3)
        target_compile_definitions(${ARGV3} PUBLIC ${option})
    endif()
endmacro()

# Value option, optionally propagated as PUBLIC compile definition (VAR=value).
macro(tracy_set_option_value var help default)
    set_option_value(${var} "${help}" "${default}")
    if(${var} AND ${ARGC} GREATER 3)
        target_compile_definitions(${ARGV3} PUBLIC ${var}=${${var}})
    endif()
endmacro()

# Value option propagated as a C string literal (VAR="value").
# For options whose value is a path or string consumed verbatim in C/C++ code.
macro(tracy_set_option_value_as_string var help default)
    set_option_value(${var} "${help}" "${default}")
    if(${var} AND ${ARGC} GREATER 3)
        target_compile_definitions(${ARGV3} PUBLIC "${var}=\"${${var}}\"")
    endif()
endmacro()
