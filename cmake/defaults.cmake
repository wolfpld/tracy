function(set_default_compile_options TARGET_NAME)
  # Set the C++ standard version.
  target_compile_features(${TARGET_NAME} PRIVATE cxx_std_17)

  target_compile_definitions(
    ${TARGET_NAME}
    PRIVATE # Avoid `min|max` macros declared in windows.h from stamping over
            # `std::numeric_limits<T>::min|max()` declared in <limits>.
            $<$<PLATFORM_ID:Windows>:NOMINMAX>)

  # Set rpath
  get_target_property(_target_type ${TARGET_NAME} TYPE)
  if(_target_type STREQUAL "EXECUTABLE")
    if(APPLE)
      set_target_properties(${TARGET_NAME} PROPERTIES INSTALL_RPATH
                                                      "@executable_path")
    elseif(UNIX)
      set_target_properties(${TARGET_NAME} PROPERTIES INSTALL_RPATH
                                                      "$ORIGIN;$ORIGIN/../lib")
    endif()
  endif()
endfunction(set_default_compile_options)
