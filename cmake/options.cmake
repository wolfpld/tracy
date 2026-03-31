# Reusable option macros for CMake projects
#
# Usage:
#   set_option(OPTION_NAME "Help text" ON/OFF)     - for boolean options
#   set_option_value(VAR_NAME "Help text" "value") - for value options (CACHE STRING)

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
