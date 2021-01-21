/* SPDX-License-Identifier: BSD-2-Clause */

/**
 * \file   dublin_traceroute.h
 * \author Andrea Barberio <insomniac@slackware.it>
 * \copyright 2-clause BSD
 * \date   October 2015
 * \brief  Main class for the NAT-aware multipath traceroute
 *
 * This module contains the implementation of the NAT-aware multipath
 * traceroute known as dublin-traceroute.
 *
 * \sa dublin_traceroute.cc
 */

#ifndef _Dublin_TRACEROUTE_H
#define _Dublin_TRACEROUTE_H

#include <iostream>
#include <arpa/inet.h>
#include <thread>
#include <mutex>

#include "common.h"
#include "exceptions.h"
#include "traceroute_results.h"

// TODO add copyright and author

/* TODO put everything into a namespace, e.g.
 *      namespace DublinTraceroute {  // or DublinTraceroute
 *          class Traceroute {
 *              TracerouteResults run();
 *              ...
 *          }
 *      }
 */

enum probe_type {
	// valid probe types must be within `min` and `max`, which are used for
	// argument checking.
	min,
	// UDP over IPv4
	UDPv4,
	max,
};

inline
const std::string
probe_type_name(probe_type type) {
	switch (type) {
	case probe_type::UDPv4:
		return "IPv4/UDP";
	default:
		return "<unknown probe type>";
	}
}

class  DublinTraceroute {

private:
	const uint16_t		 srcport_,
				 dstport_;
	const std::string	 dst_;
	const probe_type	 type_;
	Tins::IPv4Address		 target_;
	const uint8_t		 npaths_,
				 min_ttl_,
				 max_ttl_;
	const uint16_t		 delay_;
	const bool		 broken_nat_,
				 use_srcport_for_path_generation_,
				 no_dns_;
	std::mutex		 mutex_tracerouting,
				 mutex_sniffed_packets;
	Tins::IPv4Address		 my_address;
	std::vector<std::shared_ptr<Tins::Packet>>	 sniffed_packets;
	const void		 validate_arguments();

public:
	static const probe_type  default_type = probe_type::UDPv4;
	static const uint16_t	 default_srcport = 12345;
	static const uint16_t	 default_dstport = 33434;
	static const uint8_t	 default_npaths = 20;
	static const uint8_t	 default_min_ttl = 1;
	static const uint8_t	 default_max_ttl = 30;
	static const uint16_t	 default_delay = 10;
	static const bool	 default_broken_nat = false;
	static const bool	 default_use_srcport_for_path_generation = false;
	static const bool	 default_no_dns = false;
	DublinTraceroute(
			const std::string &dst,
			const probe_type type = default_type,
			const uint16_t srcport = default_srcport,
			const uint16_t dstport = default_dstport,
			const uint8_t npaths = default_npaths,
			const uint8_t min_ttl = default_min_ttl,
			const uint8_t max_ttl = default_max_ttl,
			const uint16_t delay = default_delay,
			const bool broken_nat = default_broken_nat,
			const bool use_srcport_for_path_generation = default_use_srcport_for_path_generation,
			const bool no_dns = default_no_dns
			):
				dst_(dst),
				type_(type),
				srcport_(srcport),
				dstport_(dstport),
				npaths_(npaths),
				min_ttl_(min_ttl),
				max_ttl_(max_ttl),
				delay_(delay),
				broken_nat_(broken_nat),
				use_srcport_for_path_generation_(use_srcport_for_path_generation),
				no_dns_(no_dns)
	{ validate_arguments(); }
	DublinTraceroute(
			const char *dst,
			const probe_type type = default_type,
			const uint16_t srcport = default_srcport,
			const uint16_t dstport = default_dstport,
			const uint8_t npaths = default_npaths,
			const uint8_t min_ttl = default_min_ttl,
			const uint8_t max_ttl = default_max_ttl,
			const uint16_t delay = default_delay,
			const bool broken_nat = default_broken_nat,
			const bool use_srcport_for_path_generation = default_use_srcport_for_path_generation,
			const bool no_dns = default_no_dns
		       ):
				dst_(std::string(dst)),
				type_(type),
				srcport_(srcport),
				dstport_(dstport),
				npaths_(npaths),
				min_ttl_(min_ttl),
				max_ttl_(max_ttl),
				delay_(delay),
				broken_nat_(broken_nat),
				use_srcport_for_path_generation_(use_srcport_for_path_generation),
				no_dns_(no_dns)
	{ validate_arguments(); }
	~DublinTraceroute() { std::lock_guard<std::mutex> lock(mutex_tracerouting); };
	DublinTraceroute(const DublinTraceroute& source):
		dst_(source.dst_),
		type_(source.type_),
		srcport_(source.srcport_),
		dstport_(source.dstport_),
		npaths_(source.npaths_),
		min_ttl_(source.min_ttl_),
		max_ttl_(source.max_ttl_),
		delay_(source.delay_),
		broken_nat_(source.broken_nat_),
		use_srcport_for_path_generation_(source.use_srcport_for_path_generation_),
		no_dns_(source.no_dns_)
	{ validate_arguments(); }

	inline const std::string &dst() const { return dst_; }
	inline const probe_type type() const { return static_cast<probe_type>(type_); }
	inline const uint16_t srcport() const { return srcport_; }
	inline const uint16_t dstport() const { return dstport_; }
	inline const uint8_t npaths() const { return npaths_; }
	inline const uint8_t min_ttl() const { return min_ttl_; }
	inline const uint8_t max_ttl() const { return max_ttl_; }
	inline const uint16_t delay() const { return delay_; }
	inline const bool broken_nat() const { return broken_nat_; }
	inline const bool no_dns() const { return no_dns_; }
	inline const bool use_srcport_for_path_generation() const { return use_srcport_for_path_generation_; }
	inline const Tins::IPv4Address &target() const { return target_; }
	void target(const Tins::IPv4Address &addr) { target_ = addr; }
	std::shared_ptr<TracerouteResults> traceroute();

private:
	bool sniffer_callback(Tins::Packet& packet);
	void match_sniffed_packets(TracerouteResults &results);
	void match_hostnames(TracerouteResults &results, std::shared_ptr<flow_map_t> flows);
};

#endif /* _Dublin_TRACEROUTE_H */

