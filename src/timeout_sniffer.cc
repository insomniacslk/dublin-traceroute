/**
 * \file   timeout_sniffer.cc
 * \author Andrea Barberio <insomniac@slackware.it>
 * \copyright 2-clause BSD
 * \date   July 2017
 * \brief  Sniffer with timeout that uses pcap_dispatch instead of pcap_loop
 *
 * This module contains a subclass of the Tins::Sniffer class, where
 * next_packet() internally uses pcap_dispatch instead of pcap_loop. The latter
 * does not support timeouts on some platforms.
 *
 * \sa dublin_traceroute.h
 */

#include "dublintraceroute/timeout_sniffer.h"

/*
 * This method is simply a copy of Sniffer::next_packet with pcap_dispatch
 * instead of pcap_loop
 */
PtrPacket TimeoutSniffer::next_packet() {
    sniff_data data;
    const int iface_type = pcap_datalink(handle_);
    pcap_handler handler = 0;
    if (extract_raw_) {
        handler = &sniff_loop_handler<RawPDU>;
    }
    else {
        switch (iface_type) {
            case DLT_EN10MB:
                handler = &sniff_loop_eth_handler;
                break;
            case DLT_NULL:
                handler = &sniff_loop_handler<Tins::Loopback>;
                break;
            case DLT_LINUX_SLL:
                handler = &sniff_loop_handler<SLL>;
                break; 
            case DLT_PPI:
                handler = &sniff_loop_handler<PPI>;
                break;
            case DLT_RAW:
                handler = &sniff_loop_raw_handler;
                break;

            // Dot11 related protocols
            #ifdef TINS_HAVE_DOT11
            case DLT_IEEE802_11_RADIO:
                handler = &sniff_loop_handler<RadioTap>;
                break;
            case DLT_IEEE802_11:
                handler = &sniff_loop_dot11_handler;
                break;
            #else
            case DLT_IEEE802_11_RADIO:
            case DLT_IEEE802_11:
                throw protocol_disabled();
            #endif // TINS_HAVE_DOT11

            #ifdef DLT_PKTAP
            case DLT_PKTAP:
                handler = &sniff_loop_handler<PKTAP>;
                break;
            #endif // DLT_PKTAP

            default:
                throw unknown_link_type();
        }
    }
    // keep calling pcap_loop until a well-formed packet is found.
    while (data.pdu == 0 && data.packet_processed) {
        data.packet_processed = false;
        if (pcap_dispatch(handle_, 1, handler, (u_char*)&data) < 0) {
            return PtrPacket(0, Timestamp());
        }
    }
    return PtrPacket(data.pdu, data.tv);
}

