/**
 * \file   udpv4probe.h
 * \Author Andrea Barberio <insomniac@slackware.it>
 * \date   2017
 * \brief  Definition of the UDPProbev4 class
 *
 * This file contains the definition of the UDPv4Probe class, which represents
 * an UDP probe that will be sent over IPv4.
 *
 * \sa udpv4probe.cc
 */

#ifndef _UDPV4PROBE_H
#define _UDPV4PROBE_H

#include <tins/tins.h>

using namespace Tins;


class UDPv4Probe {
private:
	IPv4Address local_addr_;
	IPv4Address remote_addr_;
	uint16_t local_port_;
	uint16_t remote_port_;
	uint8_t ttl_;
public:
	const IPv4Address local_addr() const { return local_addr_; }
	const IPv4Address remote_addr() const { return remote_addr_; }
	const uint16_t local_port() const { return local_port_; };
	const uint16_t remote_port() const { return remote_port_; };
	const uint8_t ttl() const { return ttl_; };

	UDPv4Probe(
		IPv4Address remote_addr,
		uint16_t remote_port,
		uint16_t local_port,
		uint8_t ttl,
		IPv4Address local_addr = 0):
			remote_addr_(remote_addr),
			remote_port_(remote_port),
			local_port_(local_port),
			ttl_(ttl),
			local_addr_(local_addr) { };
	IP* forge();
	IP& send();
};

#endif /* _UDPV4PROBE_H */

