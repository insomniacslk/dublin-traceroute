* Implement UDP-DNS probes
* Implement TCP-80/443
* sniff traffic and react to failing probes
* Support IPv6
* implement ICMP-paris
* testing!
* Implement merge of ICMP-paris, UDP-paris and TCP-paris probes
* Implement Bellovin's  technique using response's IP ID.
  [paper](https://www.cs.columbia.edu/~smb/papers/fnat.pdf) and
  [slides](https://www.cs.columbia.edu/~smb/talks/findnat.pdf)
* use RocketFuel's technique to identify different network interfaces on a
  router using IP ID
* support MPLS, https://tools.ietf.org/html/rfc4950
* break on destination unreachable
* improve documentation
* use CMake
* put everything under a namespace
* implement command line parser in main.cc
* Add author and copyright to every source file
* Add an uninstall target in the Makefile for the python extension
* Fix the memory leak where TracerouteResults is not freed
* IP_ID_MATCHING must become a constructor parameter
* SNIFFER_TIMEOUT must become a constructor parameter
* Handle open UDP dst port responses
* Send 3 packets per hop
* Convert the traceroute internal representation into a graph
* Use both src and dst ports for tracerouting
* Add path MTU discovery and measure fragmentation-induced latency
* Use [pyasn](https://github.com/hadiasghari/pyasn) to look up AS by IP
* Integrate the ASN graph with a world map (e.g. openstreetmap or google maps)
* Add --webserver to the python CLI to expose a SimpleHTTPServer that serves a PNG with the traceroute diagram
