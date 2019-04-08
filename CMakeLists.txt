cmake_minimum_required(VERSION 3.3)
project(wpeframework-ocdm-playready-nexus-svp)
include(GNUInstallDirs)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")

set(PLAYREADY_PKG_CONFIG_NAME "playready4" CACHE STRING "Playready pkg-config file name (default: playready4)")

set(DRM_PLUGIN_NAME PlayReady)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig)
find_package(BcmNxServer REQUIRED)
pkg_search_module(PLAYREADY ${PLAYREADY_PKG_CONFIG_NAME})

if (NOT PLAYREADY_FOUND)
    message(STATUS "Please consider providing ${PLAYREADY_PKG_CONFIG_NAME} pkg-config file.")

    set(PLAYREADY_LIBRARIES
       -lplayready30pk
       -lprdyhttp
       -lsrai
       -ldrmrootfs
       -lcmndrm_tl
       -lcmndrm
       -lbcrypt
       -lb_secbuf
       -lnexus
      ${PLAYREADY_LIBRARIES}
    )

    # Assumes SAGE is enabled
    set(PLAYREADY_CFLAGS_OTHER
       -DCMD_DRM_PLAYREADY_SAGE_IMPL=1
       -DUSE_PK_NAMESPACES=1
       -DDRM_INCLUDE_PK_NAMESPACE_USING_STATEMENT=1
       -DDRM_BUILD_PROFILE=900
      ${PLAYREADY_CFLAGS_OTHER}
    )
endif()

message(STATUS "PLAYREADY_CFLAGS_OTHER: ${PLAYREADY_CFLAGS_OTHER}")

set(DRM_PLUGIN_SOURCES
  MediaSession.cpp
  MediaSystem.cpp
  MediaSession.h)

set(DRM_PLUGIN_INCLUDE_DIRS
  ${NXREFSW_INCLUDE_PATH}
  ${PLAYREADY_INCLUDE_DIRS}
  ${DRM_PLUGIN_INCLUDE_DIRS}
)

set(DRM_PLUGIN_CFLAGS_OTHER
  ${PLAYREADY_CFLAGS_OTHER}
  ${DRM_PLUGIN_CFLAGS_OTHER}
)

set(DRM_PLUGIN_LIBRARIES
  ${LIBNEXUS_LIBRARY}
  ${LIBNXCLIENT_LIBRARY}
  ${PLAYREADY_LIBRARIES}
)

add_library(${DRM_PLUGIN_NAME} SHARED ${DRM_PLUGIN_SOURCES})
target_compile_definitions(${DRM_PLUGIN_NAME} PRIVATE ${DRM_PLUGIN_CFLAGS_OTHER})
target_include_directories(${DRM_PLUGIN_NAME} PRIVATE ${DRM_PLUGIN_INCLUDE_DIRS})
target_link_libraries(${DRM_PLUGIN_NAME} ${DRM_PLUGIN_LIBRARIES})
set_target_properties(${DRM_PLUGIN_NAME} PROPERTIES SUFFIX ".drm")
set_target_properties(${DRM_PLUGIN_NAME} PROPERTIES PREFIX "")

install(TARGETS ${DRM_PLUGIN_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/share/${NAMESPACE}/OCDM)
