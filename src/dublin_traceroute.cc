/**
 * \file   dublin_traceroute.cc
 * \author Andrea Barberio <insomniac@slackware.it>
 * \copyright 2-clause BSD
 * \date   October 2015
 * \brief  Main class for the NAT-aware multipath traceroute
 *
 * This module contains the implementation of the NAT-aware multipath
 * traceroute known as dublin-traceroute.
 *
 * \sa dublin_traceroute.h
 */

#include <vector>
#include <sstream>
#include <chrono>
#include <functional>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <errno.h>

extern int errno;

#include <tins/utils.h>

#include "dublintraceroute/dublin_traceroute.h"
#include "dublintraceroute/hops.h"
#include "dublintraceroute/udpv4probe.h"

/*
 * Dublin Traceroute
 * NAT-aware extension of paris-traceroute based on libtins
 *
 * https://dublin-traceroute.net
 * http://paris-traceroute.net
 * https://libtins.github.io
 */


#define SNIFFER_TIMEOUT_MS	2000


Tins::Timestamp extract_timestamp_from_msg(struct msghdr &msg) {
	int level, type;
	struct cmsghdr *cm;
	struct timeval *tvp = NULL,
			tv,
			now;
	// if there's no timestamp in the control message, fall back to
	// gettimeofday, and get it early in this function
	if (gettimeofday(&now, NULL) == -1) {
		std::cerr << strerror(errno) << std::endl;
		return Tins::Timestamp();
	}
	for (cm = CMSG_FIRSTHDR(&msg); cm != NULL; cm = CMSG_NXTHDR(&msg, cm))
	{
		level = cm->cmsg_level;
		type  = cm->cmsg_type;
		if (SOL_SOCKET == level && SO_TIMESTAMP == type) {
			tvp = (struct timeval *) CMSG_DATA(cm);
			break;
		}
	}
	if (tvp != NULL) {
		tv.tv_sec = tvp->tv_sec;
		tv.tv_usec = tvp->tv_usec;
		return Tins::Timestamp(tv);
	}
	return Tins::Timestamp(now);
}

/** \brief Method that validates the arguments passed at the construction
 *
 * This method checks that the arguments passed at the construction are valid
 * and in the expected range.
 *
 * \sa DublinTraceroute
 *
 * \return none
 */
const void DublinTraceroute::validate_arguments() {
	// it is not necessary to validate srcport, dstport, npaths and
	// broken_nat, as they are already constrained by their types.
	// Similarly for min_ttl and max_ttl, but the latter must be greater or
	// equal than the former.
	if (min_ttl_ > max_ttl_) {
		throw std::invalid_argument(
			"max-ttl must be greater or equal than min-ttl");
	}
	if (delay_ > 1000) {
		throw std::invalid_argument(
			"delay must be between 0 and 1000 milliseconds");
	}
}


/** \brief run the multipath traceroute
 *
 * This method will execute a multipath traceroute. The way it operates is by
 * crafting and sending packets suitable for a multipath traceroute, and
 * sniffind the network traffic for the replies.
 *
 * \sa TracerouteResults
 * \returns an instance of TracerouteResults
 */
std::shared_ptr<TracerouteResults> DublinTraceroute::traceroute() {
	// avoid running multiple traceroutes
	if (mutex_tracerouting.try_lock() == false)
		throw DublinTracerouteInProgressException("Traceroute already in progress");

	validate_arguments();

	// Resolve the target host
	try {
		target(Utils::resolve_domain(dst()));
	} catch (std::runtime_error) {
		target(IPv4Address(dst()));
	}

	uint16_t num_packets = (max_ttl() - min_ttl() + 1) * npaths();
	std::chrono::steady_clock::time_point deadline = \
		std::chrono::steady_clock::now() + \
		std::chrono::milliseconds(SNIFFER_TIMEOUT_MS) + \
		std::chrono::milliseconds(delay() * num_packets);
	// configure the sniffing handler
	auto handler = std::bind(
		&DublinTraceroute::sniffer_callback,
		this,
		std::placeholders::_1
	);

	// start the ICMP listener
	std::thread listener_thread(
		[&]() {
			int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
			if (sock == -1) {
				throw std::runtime_error(strerror(errno));
			}
			int ts_flag = 1;
			int ret;
			if ((ret = setsockopt(sock, SOL_SOCKET, SO_TIMESTAMP, (int *)&ts_flag, sizeof(ts_flag))) == -1) {
				throw std::runtime_error(strerror(errno));
			}
			size_t received;
			char buf[512];
			struct msghdr msg;
			memset(&msg, 0, sizeof(msg));
			struct iovec iov[1];
			iov[0].iov_base = buf;
			iov[0].iov_len = sizeof(buf);
			msg.msg_iov = iov;
			msg.msg_iovlen = sizeof(iov) / sizeof(struct iovec);
			struct csmghdr *cmsg;
			msg.msg_control = cmsg;
			msg.msg_controllen = 0;
			while (std::chrono::steady_clock::now() <= deadline) {
				received = recvmsg(sock, &msg, MSG_DONTWAIT);
				if (received == -1) {
					if (errno != EAGAIN && errno != EWOULDBLOCK) {
						std::cerr << strerror(errno) << std::endl;
					}
				} else if (msg.msg_flags & MSG_TRUNC) {
					std::cerr << "Warning: received datagram too large for buffer" << std::endl;
				} else if (received < 20) {
					std::cerr << "Warning: short read, less than 20 bytes" << std::endl;
				} else if (buf[0] >> 4 == 4) {
					// is it IP version 4? Then enqueue it
					// for processing
					IP *ip;
					try {
						ip = new IP((const uint8_t *)buf, received);
					} catch (Tins::malformed_packet&) {
						std::cerr << "Warning: malformed packet" << std::endl;
						continue;
					}
					// Tins::Timestamp is a timeval struct,
					// so no monotonic clock anyway..
					auto timestamp = extract_timestamp_from_msg((struct msghdr &)msg);
					Packet packet = Packet((PDU *)ip, timestamp);
					handler(packet);
					delete ip;
				}
				std::this_thread::sleep_for(std::chrono::milliseconds(5));
			}
			close(sock);
		}
	);

	std::shared_ptr<flow_map_t> flows(new flow_map_t);

	uint16_t iterated_port = dstport();
	if(use_srcport_for_path_generation()) iterated_port = srcport();
	uint16_t end_port = iterated_port + npaths();

	// forge the packets to send
	for (iterated_port; iterated_port < end_port; iterated_port++) {
		/* Forge the packets to send and append them to the packets
		 * vector.
		 * To force a packet through the same network flow, it has to
		 * maintain several constant fields that will be used for the
		 * ECMP hashing. These fields are, in the case of IP+UDP:
		 *
		 *   IPv4.tos
		 *   IPv4.proto
		 *   IPv4.src
		 *   IPv4.dst
		 *   UDP.sport
		 *   UDP.dport
		 */
		Hops hops;
		for (uint8_t ttl = min_ttl_; ttl <= max_ttl_; ttl++) {
			/*
		 	 * Adjust the payload for each flow to obtain the same UDP
		 	 * checksum. The UDP checksum is used to identify the flow.
		 	 */
			
			UDPv4Probe *probe = NULL;
			if(use_srcport_for_path_generation()){
				probe = new UDPv4Probe(target(), dstport(), iterated_port, ttl);
			}
			else{
				probe = new UDPv4Probe(target(), iterated_port, srcport(), ttl);
				//UDPv4Probe probe(target(), dport, srcport(), ttl);	
			}
			auto packet = probe->send();
			auto now = Tins::Timestamp::current_time();

			try {
				Hop hop;
				hop.sent(packet);
				hop.sent_timestamp(now);
				hops.push_back(hop);
			} catch (std::runtime_error e) {
				std::stringstream ss;
				ss << "Cannot find flow: " << iterated_port << ": " << e.what();
				throw DublinTracerouteException(ss.str());
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(delay()));
		}
		flows->insert(std::make_pair(iterated_port, std::make_shared<Hops>(hops)));
	}

	listener_thread.join();

	TracerouteResults *results = new TracerouteResults(flows, min_ttl_, broken_nat(), use_srcport_for_path_generation());

	match_sniffed_packets(*results);
	if (!no_dns()) {
		match_hostnames(*results, flows);
	}

	mutex_tracerouting.unlock();

	return std::make_shared<TracerouteResults>(*results);
}


bool DublinTraceroute::sniffer_callback(Packet &packet) {
	std::lock_guard<std::mutex> lock(mutex_sniffed_packets);
	sniffed_packets.push_back(std::make_shared<Packet>(packet));
	return true;
}


void DublinTraceroute::match_sniffed_packets(TracerouteResults &results) {
	for (auto &packet: sniffed_packets)
		results.match_packet(*packet);
}


void DublinTraceroute::match_hostnames(TracerouteResults &results, std::shared_ptr<flow_map_t> flows) {
	// TODO make this asynchronous
	// TODO move this to a proxy method ::resolve() in TracerouteResults
	for (auto &iter: *flows) {
		auto packets = iter.second;
		for (auto &hop: *packets) {
			hop.resolve();
		}
	}
}


