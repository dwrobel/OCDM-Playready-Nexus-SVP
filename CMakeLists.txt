cmake_minimum_required(VERSION 2.8)

include(${CMAKE_SYSROOT}${CMAKE_INSTALL_PREFIX}/include/cmake/tools.cmake)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/")

option(NEXUS_PLAYREADY_SVP_ENABLE "SAGE/SVP is enabled" OFF)

set(DRM_PLUGIN_NAME PlayReady)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

find_package(Core REQUIRED)
find_package(BcmNxServer REQUIRED)

file(GLOB DRM_PLUGIN_INCLUDES *.h)

set(DRM_PLUGIN_INCLUDES
    ${DRM_PLUGIN_INCLUDES}
    ${NXREFSW_INCLUDE_PATH}
    ${CORE_INCLUDE_DIR})

set(DRM_PLUGIN_FLAGS
    -DBSTD_CPU_ENDIAN=BSTD_ENDIAN_LITTLE
    -DUSE_PK_NAMESPACES=1
    -DDRM_INCLUDE_PK_NAMESPACE_USING_STATEMENT=1
    -DDRM_BUILD_PROFILE=900)

set(DRM_PLUGIN_LIBS
    ${LIBNEXUS_LIBRARY}
    ${LIBNXCLIENT_LIBRARY}
    -ldrmrootfs
    -lprdyhttp
    -lsrai
    -lb_secbuf
    -lplayready30pk
    ${CORE_LIBRARIES}
    ${MODULE_NAME})

set(DRM_PLUGIN_SOURCES
    MediaSession.cpp
    MediaSystem.cpp)

if (NEXUS_PLAYREADY_SVP_ENABLE)
   set(DRM_PLUGIN_FLAGS ${DRM_PLUGIN_FLAGS} -DNEXUS_PLAYREADY_SVP_ENABLE)
endif()

# add the library
add_library(${DRM_PLUGIN_NAME} SHARED ${DRM_PLUGIN_SOURCES})
target_compile_definitions(${DRM_PLUGIN_NAME} PRIVATE ${DRM_PLUGIN_FLAGS})
target_include_directories(${DRM_PLUGIN_NAME} PRIVATE ${DRM_PLUGIN_INCLUDES})
target_link_libraries(${DRM_PLUGIN_NAME} ${DRM_PLUGIN_LIBS})
set_target_properties(${DRM_PLUGIN_NAME} PROPERTIES SUFFIX ".drm")
set_target_properties(${DRM_PLUGIN_NAME} PROPERTIES PREFIX "")

install(TARGETS ${DRM_PLUGIN_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/share/${NAMESPACE}/OCDM)

