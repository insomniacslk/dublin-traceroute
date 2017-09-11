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

/** \brief Method that generates and returns the packets to send
 *
 * This method generates a map containing the packets to send in order to run a
 * multipath traceroute. The packets are grouped by flow, each identified by a
 * destination port. Each flow specifies a vector of IP packets, and its
 * position determines the TTL used for the packet. E.g. the packet at position
 * 0 has TTL 1, and so on.
 * The number of flows is determined by npaths(), which is passed to the
 * constructor.
 *
 * \sa traceroute()
 * \sa npaths()
 *
 * \return the packets to send
 */
std::shared_ptr<flow_map_t> DublinTraceroute::generate_per_flow_packets() {
	NetworkInterface iface = NetworkInterface::default_interface();
	NetworkInterface::Info info = iface.addresses();
	std::shared_ptr<flow_map_t> flows(new flow_map_t);

	/* The payload is used to manipulate the UDP checksum, that will be
	 * used as hop identifier.
	 * The last two bytes will be adjusted to influence the hop identifier,
	 * which for UDP traceroutes is the UDP checksum.
	 */
	unsigned char payload[] = {'N', 'S', 'M', 'N', 'C', 0x00, 0x00};

	// Resolve the target host
	// TODO support IPv6
	try {
		target(Utils::resolve_domain(dst()));
	} catch (std::runtime_error) {
		target(IPv4Address(dst()));
	}

	// check for valid min and max TTL
	if (min_ttl_ > max_ttl_) {
		throw std::invalid_argument("max_ttl must be greater or equal than min_ttl");
	}

	// forge the packets to send
	for (uint16_t dport = dstport(); dport < dstport() + npaths(); dport++) {
		hops_t hops(new std::vector<Hop>());
		flows->insert(std::make_pair(dport, hops));
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
		for (uint8_t ttl = min_ttl_; ttl <= max_ttl_; ttl++) {
			/*
		 	 * Adjust the payload for each flow to obtain the same UDP
		 	 * checksum. The UDP checksum is used to identify the flow.
		 	 */
			uint16_t identifier = dport + ttl;
			payload[5] = ((unsigned char *)&identifier)[0];
			payload[6] = ((unsigned char *)&identifier)[1];

			IP packet = IP(target(), info.ip_addr) /
				UDP(dport, srcport()) /
				RawPDU((char *)payload);
			packet.ttl(ttl);
			packet.flags(IP::DONT_FRAGMENT); // set DF bit

			// serialize the packet so that we can extract src IP
			// and checksum
			packet.serialize();

			// get our own IPv4 address - will be used by the sniffer thread to
			// sniff only the relevant traffic
			if (my_address == "0.0.0.0")
				my_address = IPv4Address(packet.src_addr());
			else {
				if (packet.src_addr() != my_address) {
					std::stringstream ss;
					ss << "Packets flowing through more than one interface, " << my_address << " and " << packet.src_addr();
					throw DublinTracerouteException(ss.str());
				}
			}
			packet.id(packet.rfind_pdu<UDP>().checksum());

			try {
				Hop hop;
				hop.sent(packet);
				hops->push_back(hop);
			} catch (std::runtime_error e) {
				std::stringstream ss;
				ss << "Cannot find flow: " << dport << ": " << e.what();
				throw DublinTracerouteException(ss.str());
			}
		}
	}

	return flows;
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
TracerouteResults &DublinTraceroute::traceroute() {
	// avoid running multiple traceroutes
	if (mutex_tracerouting.try_lock() == false)
		throw DublinTracerouteInProgressException("Traceroute already in progress");

	auto flows = generate_per_flow_packets();

	TracerouteResults *results = new TracerouteResults(flows, min_ttl_, broken_nat());

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
				}
				std::this_thread::sleep_for(std::chrono::milliseconds(5));
			}
			close(sock);
		}
	);
	// send everything out
	send_all(flows);

	listener_thread.join();

	match_sniffed_packets(*results);
	match_hostnames(*results, flows);

	mutex_tracerouting.unlock();

	return *results;
}

void DublinTraceroute::send_all(std::shared_ptr<flow_map_t> flows) {
	NetworkInterface iface = NetworkInterface::default_interface();
	PacketSender sender;
	for (auto &iter: *flows) {
		auto packets = iter.second;
		for (auto &hop: *packets) {
			auto packet = hop.sent();

			sender.send(*packet, iface.name());
			hop.sent_timestamp(Tins::Timestamp::current_time());
			std::this_thread::sleep_for(std::chrono::milliseconds(delay()));
		}
	}
}


bool DublinTraceroute::sniffer_callback(Packet &packet) {
	std::lock_guard<std::mutex> lock(mutex_sniffed_packets);
	sniffed_packets.push_back(std::make_shared<Packet>(Packet(packet)));
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


