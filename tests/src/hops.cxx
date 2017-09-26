#include <dublintraceroute/hops.h>
#include <gtest/gtest.h>
#include <tins/tins.h>


using namespace Tins;


namespace {

class HopsTest: public ::testing::Test {
};

TEST_F(HopsTest, TestHopsConstructor) {
	Hops h = Hops();
}

TEST_F(HopsTest, TestHopsCopyConstructor) {
	Hops h1 = Hops();
	Hops h2 = Hops(h1);
	ASSERT_EQ(h1, h2);
}

TEST_F(HopsTest, TestHopsSize) {
	Hops hops = Hops();
	ASSERT_EQ(hops.size(), 0);
}

TEST_F(HopsTest, TestHopsPushBack) {
	Hops hops = Hops();
	hops.push_back(Hop());
	ASSERT_EQ(hops.size(), 1);
	hops.push_back(Hop());
	ASSERT_EQ(hops.size(), 2);
	hops.push_back(Hop());
	ASSERT_EQ(hops.size(), 3);
}

TEST_F(HopsTest, TestHopsAt) {
	Hops hops = Hops();
	Hop h = Hop();
	std::string name = "test";
	h.name(name);
	hops.push_back(h);
	ASSERT_EQ(hops.at(0), h);
	ASSERT_EQ(hops.at(0).name(), name);
}

TEST_F(HopsTest, TestHopsForwardIterator) {
	Hops hops = Hops();
	int i;
	for (i = 0; i < 3; i++) {
		Hop h = Hop();
		std::string name = std::to_string(i);
		h.name(name);
		hops.push_back(h);
	}
	i = 0;
	for (auto &h: hops) {
		std::string name = std::to_string(i);
		ASSERT_EQ(hops.at(i).name(), name);
		i++;
	}
}

TEST_F(HopsTest, TestHopsReverseIterator) {
	Hops hops = Hops();
	int i;
	for (i = 0; i < 3; i++) {
		Hop h = Hop();
		std::string name = std::to_string(i);
		h.name(name);
		hops.push_back(h);
	}
	i = 2;
	for (auto hop = hops.rbegin(); hop != hops.rend(); hop++) {
		std::string name = std::to_string(i);
		ASSERT_EQ(hops.at(i).name(), name);
		i--;
	}
}

}


int main(int argc, char **argv) {
	::testing::InitGoogleTest(&argc, argv);
	std::exit(RUN_ALL_TESTS());
}

