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

// TODO argument parsing

#define TARGET		"8.8.8.8"
#define PATHS		10

void
usage(const char *name) {
	std::cout << "Usage: " << name << " target" << std::endl;
	exit(EXIT_SUCCESS);
}


int
main(int argc, char **argv) {
	if (argc != 2)
		usage(argv[0]);

	const std::string target = std::string(argv[1]);
	std::cout << "Starting dublin-traceroute" << std::endl;

	DublinTraceroute Dublin(
			target,
			12345,
			(1<<15) + 666,  // traceroute's port
			PATHS
	);
	std::cout
		<< "Traceroute from 0.0.0.0:" << Dublin.srcport()
		<< " to " << Dublin.dst()
		<< ":" << Dublin.dstport() << "~" << (Dublin.dstport() + PATHS - 1)
		<< std::endl;

	std::shared_ptr<TracerouteResults> results;
	try {
		results = std::make_shared<TracerouteResults>(Dublin.traceroute());
	} catch (DublinTracerouteException &e) {
		std::cout << "Failed: " << e.what() << std::endl;
		exit(EXIT_FAILURE);
	} catch (std::runtime_error &e) {
		std::cout << "Failed: " << e.what() << std::endl;
		exit(EXIT_FAILURE);
	}

	results->show();

	// Save as JSON
	std::ofstream jsonfile;
	jsonfile.open("trace.json");
	jsonfile << results->to_json();
	jsonfile.close();
	std::cout << "Saved JSON file to trace.json ." << std::endl;

	std::cout << "You can convert it to DOT by running python -m dublintraceroute --plot trace.json" << std::endl;

	exit(EXIT_SUCCESS);
}

