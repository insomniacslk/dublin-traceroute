#include <dublintraceroute/udpv4probe.h>
#include <gtest/gtest.h>


namespace {

class UDPv4Test: public ::testing::Test {
};

TEST_F(UDPv4Test, TestUDPv4Constructor) {
	UDPv4Probe p = UDPv4Probe(IPv4Address("8.8.8.8"), 33434, 12345, 64, IPv4Address("127.0.0.2"));
	ASSERT_EQ(p.local_port(), 12345);
	ASSERT_EQ(p.remote_port(), 33434);
	ASSERT_EQ(p.ttl(), 64);
	ASSERT_EQ(p.remote_addr().to_string(), std::string("8.8.8.8"));
	ASSERT_EQ(p.local_addr().to_string(), std::string("127.0.0.2"));
}

}


int main(int argc, char **argv) {
	::testing::InitGoogleTest(&argc, argv);
	std::exit(RUN_ALL_TESTS());
}

