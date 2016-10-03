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


#define SNIFFER_TIMEOUT_MS	5000


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

std::string DublinTraceroute::get_pcap_filter() {
	std::stringstream filter;
	filter << "(icmp[icmptype] == 3 and (icmp[icmpcode] == 3 or icmp[icmpcode] == 4)) or (icmp[icmptype] == 11 and icmp[icmpcode] == 0) and dst " << my_address;
	return filter.str();
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

	// configure the sniffer
	SnifferConfiguration config;
	config.set_filter(get_pcap_filter());
	config.set_promisc_mode(false);
	config.set_snap_len(65535);

	Sniffer *_sniffer;
	try {
		_sniffer = new Sniffer(NetworkInterface::default_interface().name(), config);
	} catch (std::runtime_error &exc) {
		mutex_tracerouting.unlock();
		throw DublinTracerouteFailedException(exc.what());
	}
	std::shared_ptr<Sniffer> sniffer(_sniffer);

	TracerouteResults *results = new TracerouteResults(flows, min_ttl_, broken_nat());

	// configure the sniffing handler
	auto handler = std::bind(
		&DublinTraceroute::sniffer_callback,
		this,
		std::placeholders::_1
	);

	// start the sniffing thread
	std::thread sniffer_thread(
		[&]() { sniffer->sniff_loop(handler); }
	);
	std::thread timer_thread(
		[&]() {
			std::this_thread::sleep_for(std::chrono::milliseconds(SNIFFER_TIMEOUT_MS));
			sniffer->stop_sniff();
		}
	);

	// send everything out
	send_all(flows);

	sniffer_thread.join();
	timer_thread.join();

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


