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
IP& UDPv4Probe::send() {
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
	IP *packet = new IP(remote_addr_, local_addr_) /
		UDP(remote_port_, local_port_) /
		RawPDU((char *)payload);
	packet->ttl(ttl_);
	packet->flags(IP::DONT_FRAGMENT);

	// serialize the packet so we can extract source IP and checksum
	packet->serialize();

	packet->id(packet->rfind_pdu<UDP>().checksum());

	NetworkInterface iface = NetworkInterface::default_interface();
	PacketSender sender;
	sender.send(*packet, iface.name());
	return *packet;
}

