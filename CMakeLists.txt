cmake_minimum_required(VERSION 3.8.2)
project (ipfilter C CXX)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

set(NGINX_SOURCE_DIR "" CACHE STRING "Path to the sources of NGINX")

set(cli_SOURCES main.cpp db.c)
set(cli_HEADERS db.h)

add_executable(ipfiltercli ${cli_SOURCES})

if(${CMAKE_SYSTEM_NAME} STREQUAL "SunOS")
  find_library(SOCKET socket REQUIRED)
  target_link_libraries(ipfiltercli socket)
endif()

add_custom_target(module_sources SOURCES
  ngx_module.c ngx_module_runtime.c ngx_module.h)

if(NOT "${NGINX_SOURCE_DIR}" STREQUAL "")
  set(LIB_NGX_MODULE ngx_http_ipfilter_module.so)
  add_custom_command(
    OUTPUT  ${NGINX_SOURCE_DIR}/objs/${LIB_NGX_MODULE}
    WORKING_DIRECTORY ${NGINX_SOURCE_DIR}
    COMMAND ./configure --with-compat --add-dynamic-module=${PROJECT_SOURCE_DIR}
    COMMAND make modules)
  add_custom_target(module ALL
    DEPENDS ${NGINX_SOURCE_DIR}/objs/${LIB_NGX_MODULE}
    COMMAND mv ${NGINX_SOURCE_DIR}/objs/${LIB_NGX_MODULE}
      ${CMAKE_BINARY_DIR}/${LIB_NGX_MODULE})
endif()

###############################################################################
# install targets

if(NOT SKIP_INSTALL_ALL)
  # Set install paths
  include(GNUInstallDirs)
  install(TARGETS ipfiltercli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

  if(NOT "${NGINX_SOURCE_DIR}" STREQUAL "")
    install(FILES ${CMAKE_BINARY_DIR}/${LIB_NGX_MODULE} DESTINATION ${CMAKE_INSTALL_LIBDIR})
  endif()

  # Configure uninstall
  configure_file(
    "${CMAKE_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
    "${CMAKE_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY
  )
  add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P "${CMAKE_BINARY_DIR}/cmake_uninstall.cmake")
endif()

