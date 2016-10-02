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
#include <unistd.h>
#include <getopt.h>

#include <dublintraceroute/dublin_traceroute.h>

const char *shortopts = "hvs:d:n:t:b";
const struct option longopts[] = {
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{"sport", required_argument, NULL, 's'},
	{"dport", required_argument, NULL, 'd'},
	{"npaths", required_argument, NULL, 'n'},
	{"max-ttl", required_argument, NULL, 't'},
	{"broken-nat", no_argument, NULL, 'b'},
	{NULL, 0, NULL, 0},
};

static void usage() {
	std::cout <<
R"(Dublin Traceroute
Written by Andrea Barberio - https://insomniac.slackware.it

Usage:
  dublin-traceroute <target> [--sport=SRC_PORT]
                             [--dport=dest_base_port]
                             [--npaths=num_paths]
                             [--max-ttl=max_ttl]
                             [--broken-nat]
                             [--help]
                             [--version]

Options:
  -h --help                     this help
  -v --version                  print the version of Dublin Traceroute
  -s SRC_PORT --sport=SRC_PORT  the source port to send packets from
  -d DST_PORT --dport=DST_PORT  the base destination port to send packets to
  -n NPATHS --npaths=NPATHS     the number of paths to probe
  -t MAX_TTL --max-ttl=MAX_TTL  the maximum TTL to probe
  -b --broken-nat               the network has a broken NAT configuration (e.g. no payload fixup). Try this if you see less hops than expected


See documentation at https://dublin-traceroute.net
Please report bugs at https://github.com/insomniacslk/dublin-traceroute
Additional features in the Python module at https://github.com/insomniacslk/python-dublin-traceroute
)";
}


int
main(int argc, char **argv) {
	std::string	target;
	long	sport = DublinTraceroute::default_srcport;
	long	dport = DublinTraceroute::default_dstport;
	long	npaths = DublinTraceroute::default_npaths;
	long	max_ttl = DublinTraceroute::default_max_ttl;
	bool	broken_nat = DublinTraceroute::default_broken_nat;

	if (geteuid() == 0) {
		std::cout
			<< "WARNING: you are running this program as root. Consider setting the CAP_NET_RAW " << std::endl
			<< "         capability and running as non-root user as a more secure alternative." << std::endl;
	}

	int	 index,
		 iarg = 0;

	#define TO_LONG(name, value) {								\
			try {									\
				name = std::stol(value);					\
			} catch (std::invalid_argument) {					\
				std::cerr << "Invalid argument. See --help" << std::endl;	\
				std::exit(EXIT_FAILURE);					\
			}									\
		}
	while ((iarg = getopt_long(argc, argv, shortopts, longopts, &index)) != -1) {
		switch (iarg) {
			case 'h':
				usage();
				std::exit(EXIT_SUCCESS);
			case 'v':
				std::cout << "Dublin Traceroute " << VERSION << std::endl;
				std::exit(EXIT_SUCCESS);
			case 's':
				TO_LONG(sport, optarg);
				break;
			case 'd':
				TO_LONG(dport, optarg);
				break;
			case 'n':
				TO_LONG(npaths, optarg);
				break;
			case 't':
				TO_LONG(max_ttl, optarg);
				break;
			case 'b':
				broken_nat = true;
				break;
			default:
				std::cerr << "Invalid argument: " << iarg << ". See --help" << std::endl;
				std::exit(EXIT_FAILURE);
		}
	}
	#undef TO_LONG
	if (optind == argc) {
		std::cerr << "Target is required. See --help" << std::endl;
		std::exit(EXIT_FAILURE);
	}
	if (optind + 1 < argc) {
		std::cerr << "Exactly one target is required. See --help" << std::endl;
		std::exit(EXIT_FAILURE);
	}
	target = argv[optind];

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
			broken_nat
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

