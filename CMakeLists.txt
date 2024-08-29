# SPDX-License-Identifier: BSD-2-Clause

cmake_minimum_required (VERSION 3.16)
project (dublin-traceroute)

IF(APPLE)
    # macOS Mojave is not using /usr/include anymore, see https://github.com/neovim/neovim/issues/9050
    if(NOT DEFINED ENV{MACOSX_DEPLOYMENT_TARGET} AND NOT DEFINED ENV{SDKROOT})
        set(CMAKE_THREAD_LIBS_INIT "-lpthread")
        set(CMAKE_OSX_DEPLOYMENT_TARGET ${CMAKE_SYSTEM_VERSION})
    ENDIF()
    # assume built-in pthreads on MacOS
    set(CMAKE_HAVE_THREADS_LIBRARY 1)
    set(CMAKE_USE_WIN32_THREADS_INIT 0)
    set(CMAKE_USE_PTHREADS_INIT 1)
    set(THREADS_PREFER_PTHREAD_FLAG ON)
ENDIF()

# TODO sync this with VERSION in include/dublintraceroute/common.h
set (dublin-traceroute_VERSION_MAJOR_0)
set (dublin-traceroute_VERSION_MINOR_5)
set (dublin-traceroute_VERSION_PATCH_0)

# ensure that /usr/local is used to find dependencies. This is especially
# necessary for brew on OSX and for libraries installed manually under
# /usr/local
list(APPEND CMAKE_PREFIX_PATH /usr/local)

include_directories(
    "${PROJECT_SOURCE_DIR}/include"
)

add_library(dublintraceroute SHARED
    src/common.cc
    src/dublin_traceroute.cc
    src/hop.cc
    src/udpv4probe.cc
    src/traceroute_results.cc
)

# Set the shared library version
set_target_properties(dublintraceroute
    PROPERTIES
      SOVERSION 0.2.0
    )

find_package(PkgConfig)
find_package(Threads REQUIRED)
find_package(libtins 3.4)
if (${libtins_FOUND})
    MESSAGE(STATUS "libtins found via CMake")
else (${libtins_FOUND})
    MESSAGE(STATUS "libtins not found via CMake, trying pkg-config")
    pkg_search_module(libtins REQUIRED libtins)
endif (${libtins_FOUND})

if (${jsoncpp_FOUND})
    MESSAGE(STATUS "jsoncpp found via CMake")
else (${jsoncpp_FOUND})
    MESSAGE(STATUS "jsoncpp not found via CMake, trying pkg-config")
    pkg_search_module(JSONCPP REQUIRED jsoncpp)
endif (${jsoncpp_FOUND})

add_executable(dublin-traceroute src/main.cc)
target_link_libraries(dublintraceroute ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(dublin-traceroute dublintraceroute)
target_link_libraries(dublintraceroute tins)

target_link_libraries(dublintraceroute ${JSONCPP_LIBRARIES} jsoncpp)
target_include_directories(dublintraceroute PUBLIC ${JSONCPP_INCLUDE_DIRS} ${TINS_INCLUDE_DIRS})

if(APPLE)
    # with macOS Mojave /usr/local/{include,lib} have to be specified explicitly
    target_include_directories(dublintraceroute PUBLIC /usr/local/include)
    target_include_directories(dublintraceroute PUBLIC /opt/homebrew/include)
    target_link_directories(dublintraceroute PUBLIC /usr/local/lib)
    target_link_directories(dublintraceroute PUBLIC /opt/homebrew/lib)
endif(APPLE)

#set_property(TARGET dublintraceroute PROPERTY CXX_STANDARD 11)
#set_property(TARGET dublintraceroute PROPERTY CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

add_dependencies(dublin-traceroute dublintraceroute)

if (NOT CMAKE_INSTALL_BINDIR)
    set(CMAKE_INSTALL_BINDIR "bin")
endif()

if (NOT CMAKE_INSTALL_LIBDIR)
    set(CMAKE_INSTALL_LIBDIR "lib")
endif()

install(TARGETS dublin-traceroute dublintraceroute
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
install(DIRECTORY include/dublintraceroute DESTINATION include)

# find setcap
find_program(SETCAP_EXECUTABLE
    NAMES
        setcap
    PATHS
        /bin
        /usr/bin
        /usr/local/bin
        /sbin
)

if (SETCAP_EXECUTABLE)
    install(CODE "execute_process(
        COMMAND
            ${SETCAP_EXECUTABLE}
            cap_net_raw+ep
            ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/dublin-traceroute
        RESULT_VARIABLE
            SETCAP_RESULT
        )
        if (SETCAP_RESULT)
            message(WARNING \"setcap failed (${SETCAP_RESULT})\")
        endif()"
    )
endif()


# Testing
INCLUDE(ExternalProject)
# Only include googletest if the git submodule has been fetched
IF(EXISTS "${CMAKE_SOURCE_DIR}/googletest/CMakeLists.txt")
    # Enable tests and add the test directory
    MESSAGE(STATUS "Tests have been enabled")
    SET(GOOGLETEST_ROOT ${CMAKE_SOURCE_DIR}/googletest)
    SET(GOOGLETEST_INCLUDE ${GOOGLETEST_ROOT}/googletest/include)
    SET(GOOGLETEST_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/googletest)
    SET(GOOGLETEST_LIBRARY ${GOOGLETEST_BINARY_DIR}/googletest)

    ExternalProject_Add(
        googletest
        DOWNLOAD_COMMAND ""
        SOURCE_DIR ${GOOGLETEST_ROOT}
        BINARY_DIR ${GOOGLETEST_BINARY_DIR}
        CMAKE_CACHE_ARGS "-DBUILD_GTEST:bool=ON" "-DBUILD_GMOCK:bool=OFF"
                         "-Dgtest_force_shared_crt:bool=ON"
        INSTALL_COMMAND ""
    )
    # Make sure we build googletest before anything else
    ADD_DEPENDENCIES(dublintraceroute googletest)
    ENABLE_TESTING()
    ADD_SUBDIRECTORY(tests)
ELSE()
    MESSAGE(STATUS "googletest git submodule is absent. Run `git submodule init && git submodule update` to get it")
ENDIF()

