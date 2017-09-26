# This file is shamelessly copied and modified from libtins.
# Use dublintraceroute's include directories + test include directories
INCLUDE_DIRECTORIES(
    ${PROJECT_SOURCE_DIR}/include/dublintraceroute/
    ${GOOGLETEST_INCLUDE}
)

# Find pthread library
FIND_PACKAGE(Threads REQUIRED)

LINK_DIRECTORIES(
    ${GOOGLETEST_LIBRARY}
)
# Link against GoogleTest, libdublintraceroute and pthread.
# Pthread is required by GoogleTest
LINK_LIBRARIES(
    gtest
    gtest_main
    dublintraceroute
    ${CMAKE_THREAD_LIBS_INIT}
)

# Add tests target
ADD_CUSTOM_TARGET(
    tests DEPENDS
    UDPv4Test
    HopsTest
    ${OPTIONAL_TEST_TARGETS}
)

# Test executables

ADD_EXECUTABLE(UDPv4Test EXCLUDE_FROM_ALL udpv4.cxx)
ADD_EXECUTABLE(HopsTest EXCLUDE_FROM_ALL hops.cxx)

# Tests

ADD_TEST(UDPv4 UDPv4Test)
ADD_TEST(Hops HopsTest)
