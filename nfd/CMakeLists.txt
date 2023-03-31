add_library(
  nfd STATIC
  $<$<PLATFORM_ID:Windows>:nfd_win.cpp>
  $<$<PLATFORM_ID:Darwin>:nfd_cocoa.m>
  # To use Linux native file dialog based on freedesktop portal, you need to
  # have one of the portal implementation installed, e.g.
  # `xdg-desktop-portal-gtk`
  $<$<PLATFORM_ID:Linux>:nfd_portal.cpp>)

set_default_compile_options(nfd)

if(UNIX AND NOT APPLE)
  include(FindPkgConfig)
  pkg_check_modules(dbus REQUIRED dbus-1)

  target_link_libraries(nfd PRIVATE ${dbus_LIBRARIES})
  target_include_directories(nfd PRIVATE ${dbus_INCLUDE_DIRS})
endif()
