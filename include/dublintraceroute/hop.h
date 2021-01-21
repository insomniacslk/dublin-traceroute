/**
 * \file   hop.h
 * \Author Andrea Barberio <insomniac@slackware.it>
 * \date   October 2015
 * \brief  Definition of the Hop class
 *
 * This file contains the definition of the Hop class, which represent every
 * single hop in a traceroute. A Hop includes the sent packet, the matching
 * received packet (if any), NAT information and last-hop information.
 *
 * This module currently offers the set-up of the logging facilities.
 *
 * \sa hop.cc
 */

#ifndef _HOP_H
#define _HOP_H

#include <future>
#include <memory>

#include <tins/tins.h>

#include <json/json.h>


class Hop {
private:
	std::shared_ptr<Tins::IP> sent_;
	std::shared_ptr<Tins::IP> received_;
	std::shared_ptr<Tins::Timestamp> sent_timestamp_;
	std::shared_ptr<Tins::Timestamp> received_timestamp_;
	std::string name_ = "";
	bool last_hop_;
public:
	Hop(): last_hop_(false) { }
	std::shared_ptr<Tins::IP> sent() { return sent_; }
	std::shared_ptr<Tins::IP> received() { return received_; }
	std::string name() { return name_; }
	std::shared_ptr<Tins::Timestamp> received_timestamp() { return received_timestamp_; }
	std::shared_ptr<Tins::Timestamp> sent_timestamp() { return sent_timestamp_; }
	std::string resolve();
	uint16_t nat_id();
	const bool zerottl_forwarding_bug();
	void sent(Tins::IP &packet);
	void received(Tins::IP &packet, const Tins::Timestamp &timestamp);
	void name(std::string &name);
	void sent_timestamp(const Tins::Timestamp &timestamp);
	const bool is_last_hop() const { return last_hop_; }
	void is_last_hop(bool is_last) { last_hop_ = is_last; }
	unsigned int rtt();
	const uint16_t flowhash();
	operator bool() const { return (bool)received_; }
	Json::Value to_json();
	std::string summary();
};

#endif /* _HOP_H */

