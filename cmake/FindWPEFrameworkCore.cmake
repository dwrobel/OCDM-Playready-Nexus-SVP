# - Try to find WPEFramework
# Once done this will define
#  WPEFRAMEWORK_FOUND - System has WPEFramework
#  WPEFRAMEWORK_INCLUDE_DIRS - The WPEFramework include directories
#  WPEFRAMEWORK_LIBRARIES - The libraries needed to use WPEFramework
#
# Be extremely careful! WPEFRAMEWORK_PLUGINS_INCLUDE_DIRS and WPEFRAMEWORK_LIBRARIES is already defined in
# WPEFramework/Source/plugins!!
# So here we purposely left one underscore away

find_package(PkgConfig)
pkg_check_modules(PC_WPEFRAMEWORKCORE WPEFrameworkCore)

if(PC_WPEFRAMEWORKCORE_FOUND)
    if(WPEFRAMEWORK_FIND_VERSION AND PC_WPEFRAMEWORKCORE_VERSION)
        if ("${WPEFRAMEWORK_FIND_VERSION}" VERSION_GREATER "${PC_WPEFRAMEWORKCORE_VERSION}")
            message(WARNING "Incorrect version, found ${PC_WPEFRAMEWORKCORE_VERSION}, need at least ${WPEFRAMEWORK_FIND_VERSION}, please install correct version ${WPEFRAMEWORK_FIND_VERSION}")
            set(WPEFRAMEWORK_FOUND_TEXT "Found incorrect version")
            unset(PC_WPEFRAMEWORKCORE_FOUND)
        endif()
    endif()
else()
    set(WPEFRAMEWORK_FOUND_TEXT "Not found")
endif()

if(PC_WPEFRAMEWORKCORE_FOUND)
    find_path(
        WPEFRAMEWORKCORE_INCLUDE_DIR
        NAMES core/core.h
        HINTS ${PC_WPEFRAMEWORKCORE_INCLUDEDIR} ${PC_WPEFRAMEWORKCORE_INCLUDE_DIRS})

    set(WPEFRAMEWORKCORE_LIBRARY ${PC_WPEFRAMEWORKCORE_LIBRARIES})

    if("${WPEFRAMEWORK_INCLUDE_DIRS}" STREQUAL "" OR "${WPEFRAMEWORK_LIBRARY}" STREQUAL "")
        set(WPEFRAMEWORK_FOUND_TEXT "Not found")
    else()
        set(WPEFRAMEWORK_FOUND_TEXT "Found")
    endif()
else()
    set(WPEFRAMEWORK_FOUND_TEXT "Not found")
endif()

mark_as_advanced(WPEFRAMEWORKCORE_INCLUDE_DIR WPEFRAMEWORKCORE_LIBRARY)