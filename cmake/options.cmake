# Reusable option macros for Tracy CMake projects
#
# Usage:
#   set_option(OPTION_NAME "Help text" ON/OFF [TARGET])     - for boolean options
#   set_option_value(VAR_NAME "Help text" "value" [TARGET]) - for value options (CACHE STRING)
#   set_option_value_as_string(VAR_NAME "Help text" "value" [TARGET]) - for value options as C string literals
#
# [TARGET] is optional and specifies a target to which the option will 
# be added as a compile definition (e.g., -DOPTION_NAME or -DVAR_NAME=value).

# Boolean option (ON/OFF).
macro(set_option option help value)
    option(${option} ${help} ${value})
    if(${option})
        message(STATUS "${option}: ON")
        if(${ARGC} GREATER 3)
            target_compile_definitions(${ARGV3} PUBLIC ${option})
        endif()
    else()
        message(STATUS "${option}: OFF")
    endif()
endmacro()

# Value option (string/number).
macro(set_option_value var help default)
    set(${var} ${default} CACHE STRING "${help}")
    if(${var})
        message(STATUS "${var}: ${${var}}")
        if(${ARGC} GREATER 3)
            target_compile_definitions(${ARGV3} PUBLIC ${var}=${${var}})
        endif()
    else()
        message(STATUS "${var}: (not set)")
    endif()
endmacro()

# Value option embedded as a C string literal (VAR="value").
macro(set_option_value_as_string var help default)
    set(${var} ${default} CACHE STRING "${help}")
    if(${var})
        message(STATUS "${var}: ${${var}}")
        if(${ARGC} GREATER 3)
            target_compile_definitions(${ARGV3} PUBLIC "${var}=\"${${var}}\"")
        endif()
    else()
        message(STATUS "${var}: (not set)")
    endif()
endmacro()
