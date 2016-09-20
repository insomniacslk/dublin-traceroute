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

using namespace Tins;

// TODO add copyright and author

/* TODO put everything into a namespace, e.g.
 *      namespace DublinTraceroute {  // or DublinTraceroute
 *          class Traceroute {
 *              TracerouteResults run();
 *              ...
 *          }
 *      }
 */


class  DublinTraceroute {

private:
	const uint16_t		 srcport_,
				 dstport_;
	const std::string	 dst_;
	IPv4Address		 target_;
	const uint8_t		 npaths_,
				 max_ttl_;
	const bool		 dsr_; // direct server response
	std::mutex		 mutex_tracerouting,
				 mutex_sniffed_packets;
	IPv4Address		 my_address;
	std::vector<std::shared_ptr<Packet>>	 sniffed_packets;

public:
	static const uint16_t	 default_srcport = 12345;
	static const uint16_t	 default_dstport = 33434;
	static const uint8_t	 default_npaths = 20;
	static const uint8_t	 default_max_ttl = 30;
	static const bool	 default_dsr = false;
	DublinTraceroute(
			const std::string &dst,
			const uint16_t srcport = default_srcport,
			const uint16_t dstport = default_dstport,
			const uint8_t npaths = default_npaths,
			const uint8_t max_ttl = default_max_ttl,
			const bool dsr = default_dsr
			):
				srcport_(srcport),
				dstport_(dstport),
				dst_(dst),
				npaths_(npaths),
				max_ttl_(max_ttl),
				dsr_(dsr)
	{ }
	DublinTraceroute(
			const char *dst,
			const uint16_t srcport = default_srcport,
			const uint16_t dstport = default_dstport,
			const uint8_t npaths = default_npaths,
			const uint8_t max_ttl = default_max_ttl,
			const bool dsr = default_dsr
		       ):
				srcport_(srcport),
				dstport_(dstport),
				dst_(std::string(dst)),
				npaths_(npaths),
				max_ttl_(max_ttl),
				dsr_(dsr)
	{ }
	~DublinTraceroute() { std::lock_guard<std::mutex> lock(mutex_tracerouting); };
	DublinTraceroute(const DublinTraceroute& source):
		srcport_(source.srcport_),
		dstport_(source.dstport_),
		dst_(source.dst_),
		npaths_(source.npaths_),
		max_ttl_(source.max_ttl_),
		dsr_(source.dsr_)
	{ }

	inline const uint16_t srcport() const { return srcport_; }
	inline const uint16_t dstport() const { return dstport_; }
	inline const uint8_t npaths() const { return npaths_; }
	inline const uint8_t max_ttl() const { return max_ttl_; }
	inline const bool dsr() const { return dsr_; }
	inline const std::string &dst() const { return dst_; }
	inline const IPv4Address &target() const { return target_; }
	void target(const IPv4Address &addr) { target_ = addr; }
	std::shared_ptr<flow_map_t> generate_per_flow_packets();
	void send_all(std::shared_ptr<flow_map_t> flows);
	std::string get_pcap_filter();
	TracerouteResults &traceroute();

private:
	bool sniffer_callback(Packet& packet);
	void match_sniffed_packets(TracerouteResults &results);
	void match_hostnames(TracerouteResults &results, std::shared_ptr<flow_map_t> flows);
};

#endif /* _Dublin_TRACEROUTE_H */

