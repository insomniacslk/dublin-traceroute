/* SPDX-License-Identifier: BSD-2-Clause */

/**
 * \file   common.h
 * \author Andrea Barberio <insomniac@slackware.it>
 * \copyright 2-clause BSD
 * \date   October 2015
 * \brief  Common utilities for dublin-traceroute
 *
 * This file contains the common utilities for dublin-traceroute.
 *
 * This module currently offers the set-up of the logging facilities and IP ID
 * matching algorithm switch.
 *
 * \sa common.cc
 */

#ifndef _COMMON_H
#define _COMMON_H

#define VERSION	"0.5.0"

#include <map>

#include <tins/tins.h>
#include <json/json.h>

#include "hops.h"


/* Define/undefine USE_IP_ID_MATCHING to enable the IP ID packet matching, that
 * enables multipath traceroutes to work through NAT
 */
#define USE_IP_ID_MATCHING

#define PROGNAME	"dublin-traceroute"

typedef uint16_t flow_id_t;
typedef std::map<flow_id_t, std::shared_ptr<Hops>> flow_map_t;

void setupLogging();
void shutDownLogging();

#endif /* _COMMON_H */

