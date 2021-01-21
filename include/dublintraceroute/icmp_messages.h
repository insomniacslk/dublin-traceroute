/* SPDX-License-Identifier: BSD-2-Clause */

/**
 * \file   icmp_messages.h
 * \Author Andrea Barberio <insomniac@slackware.it>
 * \date   October 2015
 * \brief  ICMP messages definitions
 *
 * This file contains the ICMP messages definitions
 */

#ifndef _ICMP_MESSAGES_H
#define _ICMP_MESSAGES_H

#define ICMP_EXTENSION_MPLS_CLASS	1
#define ICMP_EXTENSION_MPLS_TYPE	1


#include <sstream>
#include <tuple>
#include <unordered_map>

// defining a map key that wraps ICMP type and code
typedef std::tuple<uint8_t, uint8_t> icmpmessage_t;


struct icmpmessage_hash: public std::unary_function<icmpmessage_t, std::size_t> {
	std::size_t operator()(const icmpmessage_t &key) const {
		return std::get<0>(key) ^ std::get<1>(key);
	}
};


struct icmpmessage_equals: public std::binary_function<icmpmessage_t, icmpmessage_t, bool> {
	bool operator()(const icmpmessage_t &left, const icmpmessage_t &right) const {
		return (
			std::get<0>(left) == std::get<0>(right) &&
			std::get<1>(left) == std::get<1>(right)
		);
	}
};


struct data {
	std::string x;
};


typedef std::unordered_map<icmpmessage_t, data, icmpmessage_hash, icmpmessage_equals> icmpmessagemap_t;


struct icmpmessages {
private:
	icmpmessagemap_t icmp_message_map;
public:
	icmpmessages() {
		// Codes coming from https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages
		// ICMP code 0 (echo reply)
		icmp_message_map[std::make_tuple(0, 0)] = {"Echo reply"};
		// ICMP code 1 is reserved
		// ICMP code 2 is reserved
		// ICMP code 3 (destination unreachable)
		icmp_message_map[std::make_tuple(3, 0)] = {"Destination network unreachable"};
		icmp_message_map[std::make_tuple(3, 1)] = {"Destination host unreachable"};
		icmp_message_map[std::make_tuple(3, 2)] = {"Destination protocol unreachable"};
		icmp_message_map[std::make_tuple(3, 3)] = {"Destination port unreachable"};
		icmp_message_map[std::make_tuple(3, 4)] = {"DF set but fragmentation required"};
		icmp_message_map[std::make_tuple(3, 5)] = {"Source route failed"};
		icmp_message_map[std::make_tuple(3, 6)] = {"Destination network unknown"};
		icmp_message_map[std::make_tuple(3, 7)] = {"Destination host unknown"};
		icmp_message_map[std::make_tuple(3, 8)] = {"Source host isolated"};
		icmp_message_map[std::make_tuple(3, 9)] = {"Network administratively prohibited"};
		icmp_message_map[std::make_tuple(3, 10)] = {"Host administratively prohibited"};
		icmp_message_map[std::make_tuple(3, 11)] = {"Network unreachable for TOS"};
		icmp_message_map[std::make_tuple(3, 12)] = {"Host unreachable for TOS"};
		icmp_message_map[std::make_tuple(3, 13)] = {"Communication administratively prohibited"};
		icmp_message_map[std::make_tuple(3, 14)] = {"Host precedence violation"};
		icmp_message_map[std::make_tuple(3, 15)] = {"Precedence cutoff in effect"};
		// ICMP code 4 (source quench) is deprecated
		icmp_message_map[std::make_tuple(4, 0)] = {"Source quench (congestion control)"};
		// ICMP code 5 (redirect message)
		icmp_message_map[std::make_tuple(5, 0)] = {"Redirect datagram for the network"};
		icmp_message_map[std::make_tuple(5, 1)] = {"Redirect datagram for the host"};
		icmp_message_map[std::make_tuple(5, 2)] = {"Redirect datagram for the TOS and network"};
		icmp_message_map[std::make_tuple(5, 3)] = {"Redirect datagram for the TOS and host"};
		// ICMP code 6 (alternate host address) is deprecated
		icmp_message_map[std::make_tuple(6, 0)] = {"Alternate host address"};
		// ICMP code 7 is reserved
		// ICMP code 8 (echo request)
		icmp_message_map[std::make_tuple(8, 0)] = {"Echo request"};
		// ICMP code 9 (Router advertisement)
		icmp_message_map[std::make_tuple(9, 0)] = {"Router advertisement"};
		// ICMP code 10 (Router solicitation)
		icmp_message_map[std::make_tuple(10, 0)] = {"Router solicitation"};
		// ICMP code 11
		icmp_message_map[std::make_tuple(11, 0)] = {"TTL expired in transit"};
		icmp_message_map[std::make_tuple(11, 1)] = {"Fragment reassembly time exceeded"};
		// ICMP code 12 (parameter problem: bad IP header)
		icmp_message_map[std::make_tuple(12, 0)] = {"Pointer indicates the error"};
		icmp_message_map[std::make_tuple(12, 1)] = {"Missing a required option"};
		icmp_message_map[std::make_tuple(12, 2)] = {"Bad length"};
		// ICMP code 13 (timestamp)
		icmp_message_map[std::make_tuple(13, 0)] = {"Timestamp"};
		// ICMP code 14 (timestamp reply)
		icmp_message_map[std::make_tuple(14, 0)] = {"Timestamp reply"};
		// ICMP code 15 (information request) is deprecated
		icmp_message_map[std::make_tuple(15, 0)] = {"Information request"};
		// ICMP code 16 (information reply) is deprecated
		icmp_message_map[std::make_tuple(16, 0)] = {"Information reply"};
		// ICMP code 17 (address mask request) is deprecated
		icmp_message_map[std::make_tuple(17, 0)] = {"Address mask request"};
		// ICMP code 18 (address mask reply) is deprecated
		icmp_message_map[std::make_tuple(18, 0)] = {"Address mask reply"};
		// ICMP code 19 is reserved for security
		// ICMP codes 20~29 are reserved for robustness experiment
		// ICMP code 30 (traceroute) is deprecated
		icmp_message_map[std::make_tuple(30, 0)] = {"Traceroute"};
		// ICMP code 31 is deprecated
		icmp_message_map[std::make_tuple(31, 0)] = {"Datagram conversion error"};
		// ICMP code 32 is deprecated
		icmp_message_map[std::make_tuple(32, 0)] = {"Mobile host redirect"};
		// ICMP code 33 is deprecated
		icmp_message_map[std::make_tuple(33, 0)] = {"Where-are-you (originally for IPv6)"};
		// ICMP code 34 is deprecated
		icmp_message_map[std::make_tuple(34, 0)] = {"Here-I-am (originally for IPv6)"};
		// ICMP code 35 is deprecated
		icmp_message_map[std::make_tuple(35, 0)] = {"Mobile registration request"};
		// ICMP code 36 is deprecated
		icmp_message_map[std::make_tuple(36, 0)] = {"Mobile registration reply"};
		// ICMP code 37 is deprecated
		icmp_message_map[std::make_tuple(37, 0)] = {"Domain name request"};
		// ICMP code 38 is deprecated
		icmp_message_map[std::make_tuple(38, 0)] = {"Domain name reply"};
		// ICMP code 39 is deprecated
		icmp_message_map[std::make_tuple(39, 0)] = {"SKIP algorighm discovery protocol"};
		// ICMP code 40 is deprecated
		icmp_message_map[std::make_tuple(40, 0)] = {"Photuris, security failures"};
		// ICMP code 41 is experimental
		icmp_message_map[std::make_tuple(41, 0)] = {"Experimental mobility protocols"};
		// ICMP codes 42~252 are reserved
		// ICMP code 253 is experimental
		icmp_message_map[std::make_tuple(253, 0)] = {"RFC3692-style experiment 1"};
		// ICMP code 254 is experimental
		icmp_message_map[std::make_tuple(254, 0)] = {"RFC3692-style experiment 2"};
		// ICMP code 255 is reserved
	}
	std::string get(uint8_t type, uint8_t code) {
		try {
			return icmp_message_map.at(std::make_tuple(type, code)).x;
		} catch (std::out_of_range) {
			std::stringstream ss;
			ss << "Unknown message (type=" << static_cast<int>(type) << ", code=" << static_cast<int>(code) << ")";
			return ss.str();
		}
	}
};

#endif /* _ICMP_MESSAGES_H */

