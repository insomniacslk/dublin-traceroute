cmake_minimum_required (VERSION 2.8)
project (dublin-traceroute)

set (dublin-traceroute_VERSION_MAJOR_0)
set (dublin-traceroute_VERSION_MINOR_2)

include_directories("${PROJECT_SOURCE_DIR}/include")

add_library(dublintraceroute SHARED
    src/common.cc
    src/dublin_traceroute.cc
    src/hop.cc
    src/traceroute_results.cc
)

find_package(PkgConfig)
find_package(Threads REQUIRED)
find_package(libtins)
if (${libtins_FOUND})
    MESSAGE(STATUS "libtins found via CMake")
else (${libtins_FOUND})
    MESSAGE(STATUS "libtins not found via CMake, trying pkg-config")
    pkg_search_module(libtins REQUIRED libtins)
endif (${libtins_FOUND})

pkg_search_module(JSONCPP REQUIRED jsoncpp)

add_executable(dublin-traceroute src/main.cc)
target_link_libraries (dublin-traceroute ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(dublin-traceroute dublintraceroute)
target_link_libraries(dublintraceroute tins)

target_link_libraries(dublintraceroute ${JSONCPP_LIBRARIES} jsoncpp)
target_include_directories(dublintraceroute PUBLIC ${JSONCPP_INCLUDE_DIRS})

#set_property(TARGET dublintraceroute PROPERTY CXX_STANDARD 11)
#set_property(TARGET dublintraceroute PROPERTY CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

add_dependencies(dublin-traceroute dublintraceroute)

install(TARGETS dublin-traceroute dublintraceroute
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    )
install(DIRECTORY include/dublintraceroute DESTINATION include)
