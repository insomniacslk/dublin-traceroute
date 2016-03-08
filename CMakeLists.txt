cmake_minimum_required (VERSION 2.8)
project (dublin-traceroute
    VERSION 0.2)

set (dublin-traceroute_VERSION_MAJOR_1)
set (dublin-traceroute_VERSION_MINOR_0)

include_directories("${PROJECT_SOURCE_DIR}/include")

add_library(dublintraceroute SHARED
    src/common.cc
    src/dublin_traceroute.cc
    src/hop.cc
    src/traceroute_results.cc
)

find_package (Threads)

add_executable(dublin-traceroute src/main.cc)
target_link_libraries (dublin-traceroute ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(dublin-traceroute dublintraceroute)
target_link_libraries(dublintraceroute tins)
target_link_libraries(dublintraceroute jsoncpp)

add_dependencies(dublin-traceroute dublintraceroute)

set_property(TARGET dublintraceroute PROPERTY CXX_STANDARD 11)
set_property(TARGET dublin-traceroute PROPERTY CXX_STANDARD 11)

install(TARGETS dublin-traceroute dublintraceroute
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    )
install(DIRECTORY include/dublintraceroute DESTINATION include)
