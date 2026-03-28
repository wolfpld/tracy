function(add_git_ref target)
    if(NOT DEFINED GIT_REV)
        set(GIT_REV "HEAD")
    endif()

    get_property(_git_ref_created GLOBAL PROPERTY _GIT_REF_CREATED)
    if(NOT _git_ref_created)
        set_property(GLOBAL PROPERTY _GIT_REF_CREATED TRUE)
        find_package(Git)
        set_property(GLOBAL PROPERTY _GIT_FOUND "${Git_FOUND}")
        if(Git_FOUND)
            add_custom_target(git-ref
                COMMAND ${CMAKE_COMMAND} -E echo "#pragma once" > GitRef.hpp.tmp
                COMMAND ${GIT_EXECUTABLE} -C ${CMAKE_CURRENT_SOURCE_DIR} log -1 "--format=namespace tracy { static inline const char* GitRef = %x22%h%x22; }" ${GIT_REV} >> GitRef.hpp.tmp || echo "namespace tracy { static inline const char* GitRef = \"unknown\"; }" >> GitRef.hpp.tmp
                COMMAND ${CMAKE_COMMAND} -E copy_if_different GitRef.hpp.tmp GitRef.hpp
                BYPRODUCTS GitRef.hpp GitRef.hpp.tmp
                VERBATIM
            )
        else()
            message(WARNING "git not found, using 'unknown' as git ref.")
            add_custom_command(
                OUTPUT GitRef.hpp
                COMMAND ${CMAKE_COMMAND} -E echo "#pragma once" > GitRef.hpp
                COMMAND ${CMAKE_COMMAND} -E echo "namespace tracy { static inline const char* GitRef = \"unknown\"; }" >> GitRef.hpp
                VERBATIM
            )
        endif()
    endif()

    target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    get_property(_git_found GLOBAL PROPERTY _GIT_FOUND)
    if(_git_found)
        add_dependencies(${target} git-ref)
    else()
        target_sources(${target} PUBLIC GitRef.hpp)
    endif()
endfunction()
