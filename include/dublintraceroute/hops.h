/**
 * \file   hops.h
 * \Author Andrea Barberio <insomniac@slackware.it>
 * \date   2017
 * \brief  Definition of the Hops class
 *
 * This file contains a wrapper class around a std::vector of Hop objects.
 *
 * \sa hops.cc
 */

#ifndef _HOPS_H
#define _HOPS_H

#include "dublintraceroute/hop.h"


class Hops {
private:
	std::vector<Hop> hops_;
public:
	Hops() { }
	Hops(const Hops &source): hops_(source.hops_) { }
	void push_back(Hop hop) { hops_.push_back(hop); };
	std::vector<Hop>::iterator begin() { return hops_.begin(); };
	std::vector<Hop>::iterator end() { return hops_.end(); };
	std::vector<Hop>::reverse_iterator rbegin() { return hops_.rbegin(); };
	std::vector<Hop>::reverse_iterator rend()  { return hops_.rend(); };
	Hop at(std::vector<Hop>::size_type pos) { return hops_.at(pos); }
	std::vector<Hop>::size_type size() { return hops_.size(); }
	bool operator==(const Hops &rhs) const { return hops_ == rhs.hops_; }
};

#endif /* _HOPS_H */

