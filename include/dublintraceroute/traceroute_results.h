#include <vector>

#include "common.h"
#include "hop.h"


class TracerouteResults {
private:
	std::shared_ptr<flow_map_t> flows_;
	bool compressed_;

public:
	TracerouteResults(std::shared_ptr<flow_map_t> flows);
	~TracerouteResults() { };
	inline flow_map_t &flows() { return *flows_; }
	std::shared_ptr<IP> match_packet(const Packet &packet);
	void show(std::ostream &stream=std::cout);
	void compress();
	std::string to_json();
};

