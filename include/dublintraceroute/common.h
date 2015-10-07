#ifndef _COMMON_H
#define _COMMON_H

#include <map>

#include <tins/tins.h>
#include <json/json.h>

#include "hop.h"


/* Define/undefine USE_IP_ID_MATCHING to enable the IP ID packet matching, that
 * enables multipath traceroutes to work through NAT
 */
#define USE_IP_ID_MATCHING

using namespace Tins;

#define PROGNAME	"dublin-traceroute"
#define LOG_DIR		"logs"

typedef uint16_t flow_id_t;
typedef std::vector<Hop> hops_internal_t;
typedef std::shared_ptr<hops_internal_t> hops_t;
typedef std::map<flow_id_t, hops_t> flow_map_t;

void setupLogging();
void shutDownLogging();

#endif /* _COMMON_H */

