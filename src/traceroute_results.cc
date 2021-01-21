/**
 * \file   traceroute_results.cc
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
 * \sa traceroute_results.h
 */

#include <random>
#include <future>

#include "dublintraceroute/traceroute_results.h"
#include "dublintraceroute/icmp_messages.h"


TracerouteResults::TracerouteResults(std::shared_ptr<flow_map_t> flows, const uint8_t min_ttl = 1, const bool broken_nat = true, const bool use_srcport_for_path_generation = true):
		flows_(flows), min_ttl(min_ttl), compressed_(false), broken_nat_(broken_nat), use_srcport_for_path_generation_(use_srcport_for_path_generation) {
}


std::shared_ptr<Tins::IP> TracerouteResults::match_packet(const Tins::Packet &packet) {
	// Is this an IP packet?
	Tins::IP ip;
	try {
		ip = packet.pdu()->rfind_pdu<Tins::IP>();
	} catch (Tins::pdu_not_found) {
		return nullptr;
	}

	// Does it contain an ICMP response?
	Tins::ICMP icmp;
	try {
		icmp = ip.rfind_pdu<Tins::ICMP>();
	} catch (Tins::pdu_not_found) {
		return nullptr;
	}

	// does the ICMP contain an inner IP packet sent by us?
	Tins::IP inner_ip;
	try {
		inner_ip = icmp.rfind_pdu<Tins::RawPDU>().to<Tins::IP>();
	} catch (Tins::pdu_not_found) {
		return nullptr;
	} catch (Tins::malformed_packet) {
		return nullptr;
	}

	// does the inner packet contain our original UDP packet?
	Tins::UDP inner_udp;
	try {
		inner_udp = inner_ip.rfind_pdu<Tins::UDP>();
	} catch (Tins::pdu_not_found) {
		return nullptr;
	} catch (Tins::malformed_packet) {
		return nullptr;
	}

	// Try to match the received packet against the sent packets. The flow
	// is identified by the UDP destination port in the case of use_srcport_for_path_generation is set to false
	// if use_srcport_for_path_generation is set to true the source port is used to identify the flow
	auto flow_id = inner_udp.dport();
	if(use_srcport_for_path_generation_){
		flow_id = inner_udp.sport();
	}

	std::shared_ptr<Hops> hops;
	try {
		hops = flows().at(flow_id);
	} catch (std::out_of_range) {
		return nullptr;
	}

	unsigned int index = 0;
	for (auto &hop: *hops) {
		// FIXME catch Tins::pdu_not_found
		auto &sent = hop.sent()->rfind_pdu<Tins::IP>();
		if (!broken_nat_) {
			if (sent.src_addr() != inner_ip.src_addr())
				continue;
		}
		// FIXME catch Tins::pdu_not_found
		auto &udp = hop.sent()->rfind_pdu<Tins::UDP>();
		/*
		 * The original paris-traceroute would match the checksum, but
		 * this does not work when there is NAT translation. Using the
		 * IP ID to match the packets works through NAT rewriting
		 * instead, and only requires the inner IP layer, which is
		 * guaranteed to return entirely in ICMP ttl-exceeded responses.
		 *
		 * To use the paris-traceroute approach, undefine
		 * USE_IP_ID_MATCHING in common.h .
		 */
#ifdef USE_IP_ID_MATCHING
		if (udp.checksum() == inner_ip.id()) {
#else /* USE_IP_ID_MATCHING */
		 if (udp.checksum() == inner_udp.checksum()) {
#endif /* USE_IP_ID_MATCHING */
			try {
				hop.received(ip, packet.timestamp());
				return std::make_shared<Tins::IP>(ip);
			} catch (std::out_of_range) {
				// this should never happen
				throw;
			}
		}
		index++;
	}
	return nullptr;
}

void TracerouteResults::show(std::ostream &stream) {
	compress();
	icmpmessages icmpm;

	for (auto &iter: flows()) {
		unsigned int hopnum = min_ttl;
		unsigned int index = 0;
		uint16_t prev_nat_id = 0;
		stream << "== Flow ID " << iter.first << " ==" << std::endl;
		for (auto &hop: *iter.second) {
			stream << hopnum << "    ";
			if (!hop) {
				stream << "*" << std::endl;
			} else {
				// print the IP address of the hop
				stream << hop.received()->src_addr();
				if (hop.name() != "") {
					stream << " (" << hop.name() << ")";
				}

				// print the response IP ID, useful to detect
				// loops due to NATs, fake hops, etc
				stream << ", IP ID: " << hop.received()->id();
				
				// print the RTT
				std::stringstream rttss;
				rttss << (hop.rtt() / 1000) << "." << (hop.rtt() % 1000) << " ms ";
				stream << " RTT " << rttss.str();

				// print the ICMP type and code
				Tins::ICMP icmp;
				try {
					icmp = hop.received()->rfind_pdu<Tins::ICMP>();
					stream << " ICMP "
						<< "(type=" << icmp.type() << ", code=" << static_cast<int>(icmp.code()) << ") '"
						<< icmpm.get(icmp.type(), icmp.code()) << "'";
					if (icmp.has_extensions()) {
						for (auto &extension : icmp.extensions().extensions()) {
							unsigned int ext_class = static_cast<unsigned int>(extension.extension_class());
							unsigned int ext_type = static_cast<unsigned int>(extension.extension_type());
							auto &payload = extension.payload();
							if (ext_class == ICMP_EXTENSION_MPLS_CLASS && ext_type == ICMP_EXTENSION_MPLS_TYPE) {
								// expecting size to be a multiple of 4 in valid MPLS label stacks
								unsigned int num_labels = (extension.size() - 4) / 4;
								for (unsigned int idx = 0; idx < payload.size() ; idx += 4) {
									unsigned int label = (payload[idx + 0] << 12) + (payload[idx + 1] << 4) + (payload[idx + 2] >> 4);
									unsigned int experimental = (payload[idx + 2] & 0x0f) >> 1;
									unsigned int bottom_of_stack = payload[idx + 2] & 0x01;
									unsigned int ttl = payload[idx + 3];
									stream << ", MPLS(label=" << label << ", experimental=" << experimental << ", bottom_of_stack=" << bottom_of_stack << ", ttl=" << ttl << ")";
								}
							} else {
								stream
									<< ", Extension("
									<< "class=" << ext_class
									<< ", type=" << ext_type
									<< ", payload_size=" << payload.size()
									<< ")";
							}
						}
					}
				} catch (Tins::pdu_not_found) {
				}

				/* NAT detection.
				 * Note that if the previous hop was not
				 * responding, the detected NAT could have been
				 * started before
				 */
				auto inner_ip = hop.received()->rfind_pdu<Tins::RawPDU>().to<Tins::IP>();
				stream << ", NAT ID: " << hop.nat_id();
				if (hopnum > 1 && hop.nat_id() != prev_nat_id)
					stream << " (NAT detected)";
				prev_nat_id = hop.nat_id();

				// Show the flow hash for the sent packet
				stream << ", flow hash: " << hop.flowhash();

				stream << std::endl;

			}
			// Break if we reached the target hop
			if (hop.is_last_hop())
				break;
			hopnum++;
			index++;
		}
	}
}

void TracerouteResults::compress() {
	/** \brief compress the traceroute graph
	 *
	 * Compress the traceroute graph in order to remove repetitions of
	 * non-responding hops (i.e. the ones that show a "*" in a traceroute).
	 *
	 * Implementation note: this is not actually a compression, since the
	 * traceroute is not implemented (yet) as a graph, but this will come in
	 * a future release. Currently this method simply marks the first
	 * non-responding hop at the end of a path as last-hop.
	 *
	 * It is safe to call this method multiple times, and there is no
	 * performance penalty.
	 */
	if (compressed_)
		return;
	for (auto &iter: flows()) {
		Tins::IPv4Address target = iter.second->at(0).sent()->dst_addr();
		for (auto hop = iter.second->rbegin(); hop != iter.second->rend(); hop++) {
			// TODO also check for ICMP type==3 and code==3
			if (hop->received()) {
				if (hop->received()->src_addr() != target)
					break;
			}
			hop->is_last_hop(true);
		}
	}
	compressed_ = true;
}

std::string TracerouteResults::to_json() {
	compress();
	std::stringstream json;
	Json::Value root;

	for (auto &iter: flows()) {
		auto flow_id = std::to_string(iter.first);
		Json::Value hops(Json::arrayValue);
		for (auto &hop: *iter.second) {
			hops.append(hop.to_json());
			if (hop.is_last_hop())
				break;
		}
		root["flows"][flow_id] = hops;
	}

	json << root;
	return json.str();
}
