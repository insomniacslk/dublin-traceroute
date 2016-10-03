* Implement UDP-DNS probes
* Implement TCP-80/443
* sniff traffic and react to failing probes
* Support IPv6
* implement ICMP-paris
* testing!
* add min-ttl option
* Implement merge of ICMP-paris, UDP-paris and TCP-paris probes
* Implement Bellovin's  technique using response's IP ID.
  [paper](https://www.cs.columbia.edu/~smb/papers/fnat.pdf) and
  [slides](https://www.cs.columbia.edu/~smb/talks/findnat.pdf)
* use RocketFuel's technique to identify different network interfaces on a
  router using IP ID
* ~~support MPLS, https://tools.ietf.org/html/rfc4950~~, done in https://github.com/insomniacslk/dublin-traceroute/issues/6
* break on destination unreachable
* improve documentation
* put everything under a namespace
* ~~implement command line parser in main.cc~~ done in [commit 8a3ae75](https://github.com/insomniacslk/dublin-traceroute/commit/8a3ae7513645afdad5eabd8d6f368383dff98c8b)
* Add an uninstall target in the Makefile for the python extension
* Fix the memory leak where TracerouteResults is not freed
* IP_ID_MATCHING must become a constructor parameter
* SNIFFER_TIMEOUT must become a constructor parameter
* Handle open UDP dst port responses
* Explore the use of eBPF as a backend
* Send 3 packets per hop
* Convert the traceroute internal representation into a graph (use https://graph-tool.skewed.de/ maybe?)
* Use both src and dst ports for tracerouting
* Add path MTU discovery and measure fragmentation-induced latency
* Use [pyasn](https://github.com/hadiasghari/pyasn) to look up AS by IP
* Integrate the ASN graph with a world map (e.g. openstreetmap or google maps)
* Add --webserver to the python CLI to expose a SimpleHTTPServer that serves a PNG with the traceroute diagram
* heat map/flame graph of the network latencies over time (links history)
* ~~improve the build system (there is just a static Makefile now)~~ done in [commit ffa9d3c](https://github.com/insomniacslk/dublin-traceroute/commit/ffa9d3c306fb772e2c95963a94cdc386b0126206), using CMake
