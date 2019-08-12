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
#include <iostream>
#include <unistd.h>
#include <getopt.h>

#include <dublintraceroute/dublin_traceroute.h>

#define DEFAULT_OUTPUT_FILE	"trace.json"


const char *shortopts = "hvs:d:n:t:T:D:biNo:";
const struct option longopts[] = {
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{"sport", required_argument, NULL, 's'},
	{"dport", required_argument, NULL, 'd'},
	{"npaths", required_argument, NULL, 'n'},
	{"min-ttl", required_argument, NULL, 't'},
	{"max-ttl", required_argument, NULL, 'T'},
	{"delay", required_argument, NULL, 'D'},
	{"broken-nat", no_argument, NULL, 'b'},
	{"use-srcport", no_argument, NULL, 'i'},
	{"no-dns", no_argument, NULL, 'N'},
	{"output-file", required_argument, NULL, 'o'},
	{NULL, 0, NULL, 0},
};

static void usage() {
	std::cout <<
"Dublin Traceroute v" VERSION "\n"
R"(Written by Andrea Barberio - https://insomniac.slackware.it

Usage:
  dublin-traceroute <target> [--sport=src_base_port]
                             [--dport=dest_base_port]
                             [--npaths=num_paths]
                             [--min-ttl=min_ttl]
                             [--max-ttl=max_ttl]
                             [--delay=delay_in_ms]
                             [--broken-nat]
                             [--use-srcport]
                             [--no-dns]
                             [--output-file=file_name]
                             [--help]
                             [--version]

Options:
  -h --help                     this help
  -v --version                  print the version of Dublin Traceroute
  -s SRC_PORT --sport=SRC_PORT  the source port to send packets from (default: )" << DublinTraceroute::default_srcport << R"()
  -d DST_PORT --dport=DST_PORT  the base destination port to send packets to (default: )" << DublinTraceroute::default_dstport << R"()
  -n NPATHS --npaths=NPATHS     the number of paths to probe (default: )" << static_cast<int>(DublinTraceroute::default_npaths) << R"()
  -t MIN_TTL --min-ttl=MIN_TTL  the minimum TTL to probe (default: )" << static_cast<int>(DublinTraceroute::default_min_ttl) << R"()
  -T MAX_TTL --max-ttl=MAX_TTL  the maximum TTL to probe. Must be greater or equal than the minimum TTL (default: )" << static_cast<int>(DublinTraceroute::default_max_ttl) << R"()
  -D DELAY --delay=DELAY        the inter-packet delay in milliseconds (default: )" << DublinTraceroute::default_delay << R"()
  -b --broken-nat               the network has a broken NAT configuration (e.g. no payload fixup). Try this if you see fewer hops than expected
  -i --use-srcport              generate paths using source port instead of destination port
  -N --no-dns                   do not attempt to do reverse DNS lookup of the hops
  -o --output-file              the output file name (default: )" << DEFAULT_OUTPUT_FILE << R"()


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
	long	min_ttl = DublinTraceroute::default_min_ttl;
	long	max_ttl = DublinTraceroute::default_max_ttl;
	long	delay = DublinTraceroute::default_delay;
	bool	broken_nat = DublinTraceroute::default_broken_nat;
	bool	use_srcport_for_path_generation = DublinTraceroute::default_use_srcport_for_path_generation;
	bool	no_dns = DublinTraceroute::default_no_dns;
	std::string	output_file = DEFAULT_OUTPUT_FILE;

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
				TO_LONG(min_ttl, optarg);
				break;
			case 'T':
				TO_LONG(max_ttl, optarg);
				break;
			case 'D':
				TO_LONG(delay, optarg);
				break;
			case 'b':
				broken_nat = true;
				break;
			case 'i':
				use_srcport_for_path_generation = true;
				break;
			case 'N':
				no_dns = true;
				break;
			case 'o':
				output_file.assign(optarg);
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
	if (min_ttl < 1 || min_ttl > 255) {
		std::cerr << "Min TTL must be between 1 and 255" << std::endl;
		std::exit(EXIT_FAILURE);
	}
	if (max_ttl < 1 || max_ttl > 255) {
		std::cerr << "Max TTL must be between 1 and 255" << std::endl;
		std::exit(EXIT_FAILURE);
	}
	if (min_ttl > max_ttl) {
		std::cerr << "Min TTL must be smaller or equal than max TTL" << std::endl;
		std::exit(EXIT_FAILURE);
	}
	if (use_srcport_for_path_generation) {
		if (sport + npaths - 1 > 65535) {
			std::cerr << "Source port + number of paths must not exceed 65535" << std::endl;
			std::exit(EXIT_FAILURE);
		}
	} else {
		if (dport + npaths - 1 > 65535) {
			std::cerr << "Destination port + number of paths must not exceed 65535" << std::endl;
			std::exit(EXIT_FAILURE);
		}
	}
	if (delay < 0 || delay > 1000) {
		std::cerr << "The inter-packet delay must be a number between 0 and 1000 milliseconds" << std::endl;
		std::exit(EXIT_FAILURE);
	}

	std::cout << "Starting dublin-traceroute" << std::endl;

	DublinTraceroute Dublin(
			target,
			sport,
			dport,
			npaths,
			min_ttl,
			max_ttl,
			delay,
			broken_nat,
			use_srcport_for_path_generation,
			no_dns
	);
	
	std::cout << "Traceroute from 0.0.0.0:" << Dublin.srcport();
	if(use_srcport_for_path_generation == 1){
		std::cout << "~" << (Dublin.srcport() + npaths - 1);
	}
	
	std::cout << " to " << Dublin.dst() << ":" << Dublin.dstport();
	if(use_srcport_for_path_generation == 0){
		std::cout << "~" << (Dublin.dstport() + npaths - 1);
	}
	
	std::cout << " (probing " << npaths << " path" << (npaths == 1 ? "" : "s")
		<< ", min TTL is " << min_ttl
		<< ", max TTL is " << max_ttl
		<< ", delay is " << delay << " ms"
		<< ")"
		<< std::endl;

	std::shared_ptr<TracerouteResults> results;
	try {
		results = Dublin.traceroute();
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
	jsonfile.open(output_file);
	jsonfile << results->to_json();
	jsonfile.close();
	std::cout << "Saved JSON file to " << output_file << " ." << std::endl;

	std::cout << "You can convert it to DOT by running python3 -m dublintraceroute plot " << output_file << std::endl;

	std::exit(EXIT_SUCCESS);
}

