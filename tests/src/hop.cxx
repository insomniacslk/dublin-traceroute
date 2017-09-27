#include <dublintraceroute/hop.h>
#include <dublintraceroute/exceptions.h>
#include <gtest/gtest.h>
#include <tins/tins.h>


using namespace Tins;


namespace {

class HopTest: public ::testing::Test {
};

TEST_F(HopTest, TestHopConstructor) {
	Hop h = Hop();
	ASSERT_EQ(h.is_last_hop(), false);
	ASSERT_EQ(h.sent(), nullptr);
	ASSERT_EQ(h.received(), nullptr);
	ASSERT_EQ(h.name(), std::string());
	ASSERT_EQ(h.sent_timestamp(), nullptr);
	ASSERT_EQ(h.received_timestamp(), nullptr);
	ASSERT_THROW(h.nat_id(), DublinTracerouteException);
	ASSERT_THROW(h.zerottl_forwarding_bug(), DublinTracerouteException);
	ASSERT_EQ(h.flowhash(), 0);
	ASSERT_EQ(h.rtt(), 0);
	ASSERT_EQ((bool)h, false);
}

TEST_F(HopTest, TestHopSentPacketIPOnly) {
	Hop h = Hop();
	IP ip = IP("8.8.8.8", "0.0.0.0");
	ip.ttl(32);
	h.sent(ip);
	ASSERT_EQ(h.sent()->dst_addr(), "8.8.8.8");
	ASSERT_EQ(h.sent()->src_addr(), "0.0.0.0");
	ASSERT_EQ(h.sent()->ttl(), 32);
	ASSERT_EQ(h.flowhash(), 0);  // need UDP layer to have a flow hash
}

TEST_F(HopTest, TestHopSentPacketIPUDP) {
	Hop h = Hop();
	IP ip = IP("8.8.8.8", "0.0.0.0") / UDP(33435, 12344);
	ip.ttl(16);
	h.sent(ip);
	ASSERT_EQ(h.sent()->dst_addr(), "8.8.8.8");
	ASSERT_EQ(h.sent()->src_addr(), "0.0.0.0");
	ASSERT_EQ(h.sent()->ttl(), 16);
	ASSERT_EQ(h.flowhash(), 47835);
}

TEST_F(HopTest, TestHopReceivedPacketIPOnly) {
	Hop h = Hop();
	IP ip = IP("8.8.8.8", "0.0.0.0");
	auto now = Tins::Timestamp::current_time();
	h.sent_timestamp(now);

	struct timeval tv;
	tv.tv_sec = now.seconds() + 2;
	tv.tv_usec = now.microseconds();
	auto then = Tins::Timestamp(tv);
	h.received(ip, then);
	ASSERT_THROW(h.nat_id(), Tins::pdu_not_found);
	ASSERT_THROW(h.zerottl_forwarding_bug(), Tins::pdu_not_found);
	ASSERT_EQ(h.rtt(), 2000000);
}

// TODO test resolver, summary and JSON representation

}


int main(int argc, char **argv) {
	::testing::InitGoogleTest(&argc, argv);
	std::exit(RUN_ALL_TESTS());
}

