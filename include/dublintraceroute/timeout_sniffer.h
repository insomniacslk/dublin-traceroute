/**
 * \file   timeoutsniffer.h
 * \author Andrea Barberio <insomniac@slackware.it>
 * \copyright 2-clause BSD
 * \date   July 2017
 * \brief  Sniffer class with multi-platform timeout support
 *
 * This module contains the implementation of a Sniffer class that supports
 * timeout on multiple platforms, working around some of the libpcap
 * limitations.
 *
 * \sa timeoutsniffer.cc
 */

#ifndef _TIMEOUT_SNIFFER_H
#define _TIMEOUT_SNIFFER_H


class  TimeoutSniffer: public Tins::Sniffer {
	using Tins::Sniffer::Sniffer;
public:
	PtrPacket next_packet();
};

#endif /* _TIMEOUT_SNIFFER_H */

