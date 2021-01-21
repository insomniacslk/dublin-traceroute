/**
 * \file   udpv4probe.cc
 * \Author Andrea Barberio <insomniac@slackware.it>
 * \date   2017
 * \brief  Definition of the UDPv4Probe class
 *
 * This file contains the definition of the UDPv4Probe class, which represents
 * an UDP probe that will be sent over IPv4.
 *
 * \sa udpv4probe.h
 */

#include <memory>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <iostream>
#include <iomanip>

#include "dublintraceroute/udpv4probe.h"
#include "dublintraceroute/common.h"
#include "dublintraceroute/exceptions.h"
#include "dublintraceroute/icmp_messages.h"


/** \brief method that sends the probe to the specified destination
 */
Tins::IP* UDPv4Probe::forge() {
	/* The payload is used to manipulate the UDP checksum, that will be
	 * used as hop identifier.
	 * The last two bytes will be adjusted to influence the hop identifier,
	 * which for UDP traceroutes is the UDP checksum.
	 */
	unsigned char payload[] = {'N', 'S', 'M', 'N', 'C', 0x00, 0x00};

	/* The identifier is used to identify and match a response packet to
	 * the corresponding sent packet
	 */
	uint16_t identifier = remote_port_ + ttl_;

	payload[5] = ((unsigned char *)&identifier)[0];
	payload[6] = ((unsigned char *)&identifier)[1];
	Tins::IP *packet = new Tins::IP(remote_addr_, local_addr_) /
		Tins::UDP(remote_port_, local_port_) /
		Tins::RawPDU((char *)payload);
	packet->ttl(ttl_);
	packet->flags(Tins::IP::DONT_FRAGMENT);

	// serialize the packet so we can extract source IP and checksum
	packet->serialize();

	packet->id(packet->rfind_pdu<Tins::UDP>().checksum());
	return packet;
}

Tins::IP &UDPv4Probe::send() {
	Tins::NetworkInterface iface = Tins::NetworkInterface::default_interface();
	Tins::PacketSender sender;
	if (packet == nullptr) {
		packet = forge();
	}
	sender.send(*packet, iface.name());
	return *packet;
}

UDPv4Probe::~UDPv4Probe() {
	if (packet != nullptr)
		delete packet;
}

