/**
 * \file   main.cc
 * \Author Andrea Barberio <insomniac@slackware.it>
 * \date   October 2015
 * \brief  entry point for dublin-traceroute
 *
 * This file contains the main routine for calling the standalone dublin-traceroute
 * executable.
 */

#include <iostream>
#include <fstream>

#include <dublintraceroute/dublin_traceroute.h>
#include <docopt/docopt.h>

static const char USAGE[] =
R"(Dublin Traceroute
Written by Andrea Barberio - https://insomniac.slackware.it

Usage:
  dublin-traceroute <target> [--sport=SRC_PORT]
                             [--dport=dest_base_port]
                             [--npaths=num_paths]
                             [--max-ttl=max_ttl]
                             [--dsr]

Options:
  -s SRC_PORT --sport=SRC_PORT  the source port to send packets from
  -d DST_PORT --dport=DST_PORT  the base destination port to send packets to
  -n NPATHS --npaths=NPATHS     the number of paths to probe
  -t MAX_TTL --max-ttl=MAX_TTL  the maximum TTL to probe
  -d --dsr                      the network has a DSR NAT. May help when you only see a few hops


See documentation at https://dublin-traceroute.net
Please report bugs at https://github.com/insomniacslk/dublin-traceroute
)";


int
main(int argc, char **argv) {
	std::string	target;
	long	sport = DublinTraceroute::default_srcport;
	long	dport = DublinTraceroute::default_dstport;
	long	npaths = DublinTraceroute::default_npaths;
	long	max_ttl = DublinTraceroute::default_max_ttl;
	bool	dsr = DublinTraceroute::default_dsr;

	std::map <std::string, docopt::value> args = docopt::docopt(
			USAGE,
			{ argv + 1, argv + argc},
			true,	// show help if requested
			"Dublin Traceroute v" VERSION
			);

	#define CONVERT_TO_LONG_OR_EXIT(arg, out_var) {			\
		if (arg) {						\
			try {						\
				out_var = arg.asLong();			\
			} catch (std::invalid_argument) {		\
				std::cout << USAGE << std::endl;	\
				std::exit(EXIT_FAILURE);		\
			}						\
		}							\
	}
	for (auto const& arg : args) {
		if (arg.first == "<target>")
			target = arg.second.asString();
		else if (arg.first == "--sport") {
			CONVERT_TO_LONG_OR_EXIT(arg.second, sport);
		} else if (arg.first == "--dport") {
			CONVERT_TO_LONG_OR_EXIT(arg.second, dport);
		} else if (arg.first == "--npaths") {
			CONVERT_TO_LONG_OR_EXIT(arg.second, npaths);
		} else if (arg.first == "--max-ttl") {
			CONVERT_TO_LONG_OR_EXIT(arg.second, max_ttl);
		} else if (arg.first == "--dsr") {
			dsr = arg.second.asBool();
		}
	}
	#undef CONVERT_TO_LONG_OR_EXIT
	std::cout << "Source port: " << sport << std::endl;
	if (sport < 1 || sport > 65535) {
		std::cerr << "Source port must be between 1 and 65535" << std::endl;
		std::exit(EXIT_FAILURE);
	}
	
	if (dport < 1 || dport > 65535) {
		std::cerr << "Destination port must be between 1 and 65535" << std::endl;
		std::exit(EXIT_FAILURE);
	}
	if (npaths < 1 || npaths > 65535) {
		std::cerr << "Number of paths must be between 1 and 65535" << std::endl;
		std::exit(EXIT_FAILURE);
	}
	if (max_ttl < 1 || max_ttl > 255) {
		std::cerr << "Max TTL must be between 1 and 255" << std::endl;
		std::exit(EXIT_FAILURE);
	}
	if (dport + npaths - 1 > 65535) {
		std::cerr << "Destination port + number of paths must not exceed 65535" << std::endl;
		std::exit(EXIT_FAILURE);
	}

	std::cout << "Starting dublin-traceroute" << std::endl;

	DublinTraceroute Dublin(
			target,
			sport,
			dport,
			npaths,
			max_ttl,
			dsr
	);
	std::cout
		<< "Traceroute from 0.0.0.0:" << Dublin.srcport()
		<< " to " << Dublin.dst()
		<< ":" << Dublin.dstport() << "~" << (Dublin.dstport() + npaths - 1)
		<< " (probing " << npaths << " path" << (npaths == 1 ? "" : "s")
		<< ", max TTL is " << max_ttl << ")"
		<< std::endl;

	std::shared_ptr<TracerouteResults> results;
	try {
		results = std::make_shared<TracerouteResults>(Dublin.traceroute());
	} catch (DublinTracerouteException &e) {
		std::cout << "Failed: " << e.what() << std::endl;
		std::exit(EXIT_FAILURE);
	} catch (std::runtime_error &e) {
		std::cout << "Failed: " << e.what() << std::endl;
		std::exit(EXIT_FAILURE);
	}

	results->show();

	// Save as JSON
	std::ofstream jsonfile;
	jsonfile.open("trace.json");
	jsonfile << results->to_json();
	jsonfile.close();
	std::cout << "Saved JSON file to trace.json ." << std::endl;

	std::cout << "You can convert it to DOT by running python -m dublintraceroute plot trace.json" << std::endl;

	std::exit(EXIT_SUCCESS);
}

