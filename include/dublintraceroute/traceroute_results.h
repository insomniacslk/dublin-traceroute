/**
 * \file   traceroute_results.h
 * \author Andrea Barberio <insomniac@slackware.it>
 * \copyright 2-clause BSD
 * \date   October 2015
 * \brief  Traceroute results class for dublin-traceroute
 *
 * This file contains the Traceroute results class for dublin-traceroute.
 *
 * This class is a container for a per-flow hops representation, and offers
 * facilities to print the traceroute output and convert it to a JSON
 * representation.
 *
 * \sa traceroute_results.cc
 */
 
#include <vector>

#include "common.h"
#include "hop.h"


class TracerouteResults {
private:
	std::shared_ptr<flow_map_t> flows_;
	bool compressed_;
	bool dsr_;

public:
	TracerouteResults(std::shared_ptr<flow_map_t> flows, const bool dsr /* = false */);
	~TracerouteResults() { };
	inline flow_map_t &flows() { return *flows_; }
	std::shared_ptr<IP> match_packet(const Packet &packet);
	void show(std::ostream &stream=std::cout);
	void compress();
	std::string to_json();
};

