/* SPDX-License-Identifier: BSD-2-Clause */

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

#ifndef _TRACEROUTE_RESULTS_H
#define _TRACEROUTE_RESULTS_H

#include <vector>
#include <iostream>

#include "common.h"
#include "hop.h"


class TracerouteResults {
private:
	std::shared_ptr<flow_map_t> flows_;
	uint8_t min_ttl = 1;
	bool compressed_;
	bool broken_nat_;
	bool use_srcport_for_path_generation_;

public:
	TracerouteResults(std::shared_ptr<flow_map_t> flows, const uint8_t min_ttl /* = 1 */, const bool broken_nat /* = false */, const bool use_srcport_for_path_generation /* = false */);
	~TracerouteResults() { };
	inline flow_map_t &flows() { return *flows_; }
	std::shared_ptr<Tins::IP> match_packet(const Tins::Packet &packet);
	void show(std::ostream &stream=std::cerr);
	void compress();
	std::string to_json();
};

#endif /* _TRACEROUTE_RESULTS_H */

