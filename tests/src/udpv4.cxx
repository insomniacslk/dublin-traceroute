/* SPDX-License-Identifier: BSD-2-Clause */

#include <dublintraceroute/udpv4probe.h>
#include <gtest/gtest.h>
#include <tins/tins.h>


using namespace Tins;


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

TEST_F(UDPv4Test, TestUDPv4ConstructorDefaultLocalAddr) {
	UDPv4Probe p = UDPv4Probe(IPv4Address("8.8.8.8"), 33434, 12345, 64);
	ASSERT_EQ(p.local_port(), 12345);
	ASSERT_EQ(p.remote_port(), 33434);
	ASSERT_EQ(p.ttl(), 64);
	ASSERT_EQ(p.remote_addr().to_string(), std::string("8.8.8.8"));
	ASSERT_EQ(p.local_addr().to_string(), std::string("0.0.0.0"));
}

TEST_F(UDPv4Test, TestUDPv4PacketForging) {
	UDPv4Probe p = UDPv4Probe(IPv4Address("127.0.0.3"), 33434, 12345, 64, IPv4Address("127.0.0.2"));
	IP* ip = p.forge();
	ASSERT_EQ(ip->tos(), 0);
	ASSERT_EQ(ip->id(), 60794);
	ASSERT_EQ(ip->flags(), Tins::IP::Flags::DONT_FRAGMENT);
	ASSERT_EQ(ip->ttl(), 64);
	ASSERT_EQ(ip->dst_addr().to_string(), std::string("127.0.0.3"));
	ASSERT_EQ(ip->src_addr().to_string(), std::string("127.0.0.2"));
	delete ip;
}

TEST_F(UDPv4Test, TestUDPv4PacketForgingDefaultLocalAddr) {
	UDPv4Probe p = UDPv4Probe(IPv4Address("8.8.8.8"), 33434, 12345, 64);
	IP* ip = p.forge();
	ASSERT_EQ(ip->tos(), 0);
	ASSERT_EQ(ip->flags(), Tins::IP::Flags::DONT_FRAGMENT);
	ASSERT_EQ(ip->ttl(), 64);
	ASSERT_EQ(ip->dst_addr().to_string(), std::string("8.8.8.8"));
	// not testing src_addr and IP ID because the default addr depends on
	// the actual network interface's configuration
	delete ip;
}

}


int main(int argc, char **argv) {
	::testing::InitGoogleTest(&argc, argv);
	std::exit(RUN_ALL_TESTS());
}

