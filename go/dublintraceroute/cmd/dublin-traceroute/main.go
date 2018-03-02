package main

import (
	"errors"
	"flag"
	"fmt"
	"go/build"
	"log"
	"net"
	"os"
	"time"

	"github.com/insomniacslk/dublin-traceroute/go/dublintraceroute"
	"github.com/insomniacslk/dublin-traceroute/go/dublintraceroute/probes"
)

// Program constants and default values
const (
	ProgramName        = "Dublin Traceroute"
	ProgramVersion     = "v0.1"
	DefaultSourcePort  = 12345
	DefaultDestPort    = 33434
	DefaultNumPaths    = 10
	DefaultMinTTL      = 1
	DefaultMaxTTL      = 30
	DefaultDelay       = 50 //msec
	DefaultReadTimeout = 3 * time.Second
	DefaultOutputFile  = "trace.json"
)

// used to hold flags
type args struct {
	version    bool
	target     string
	sport      int
	dport      int
	npaths     int
	minTTL     int
	maxTTL     int
	delay      int
	brokenNAT  bool
	outputFile string
	v4         bool
}

// resolve returns the first IP address for the given host. If `wantV6` is true,
// it will return the first IPv6 address, or nil if none. Similarly for IPv4
// when `wantV6` is false.
// If the host is already an IP address, such IP address will be returned. If
// `wantV6` is true but no IPv6 address is found, it will return an error.
// Similarly for IPv4 when `wantV6` is false.
func resolve(host string, wantV6 bool) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if wantV6 && ip.To4() != nil {
			return nil, errors.New("Wanted an IPv6 address but got an IPv4 address")
		} else if !wantV6 && ip.To4() == nil {
			return nil, errors.New("Wanted an IPv4 address but got an IPv6 address")
		}
		return ip, nil
	}
	ipaddrs, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	var ret net.IP
	for _, ipaddr := range ipaddrs {
		if wantV6 && ipaddr.To4() == nil {
			ret = ipaddr
			break
		} else if !wantV6 && ipaddr.To4() != nil {
			ret = ipaddr
		}
	}
	if ret == nil {
		return nil, errors.New("No IP address of the requested type was found")
	}
	return ret, nil
}

var Args args

func init() {
	// Ensure that CGO is disabled
	var ctx build.Context
	if ctx.CgoEnabled {
		fmt.Println("Disabling CGo")
		ctx.CgoEnabled = false
	}

	// handle flags
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of Dublin Traceroute\n")
		flag.PrintDefaults()
	}
	// Args holds the program's arguments as parsed by `flag`
	flag.BoolVar(&Args.version, "version", false, "Print version and exit")
	flag.IntVar(&Args.sport, "sport", DefaultSourcePort, "Set the base source port")
	flag.IntVar(&Args.dport, "dport", DefaultDestPort, "Set the base destination port")
	flag.IntVar(&Args.npaths, "npaths", DefaultNumPaths, "Set the number of paths to probe")
	flag.IntVar(&Args.minTTL, "min-ttl", DefaultMinTTL, "Set the minimum TTL")
	flag.IntVar(&Args.maxTTL, "max-ttl", DefaultMaxTTL, "Set the maximum TTL")
	flag.IntVar(&Args.delay, "delay", DefaultDelay, "Set the inter-packet delay in msecs")
	flag.BoolVar(&Args.brokenNAT, "broken-nat", false, "Use this when the network has a broken NAT. Useful when no results are shown after a certain TTL when they are expected")
	flag.StringVar(&Args.outputFile, "output-file", DefaultOutputFile, "Output file")
	flag.BoolVar(&Args.v4, "force-ipv4", false, "Force the use of the legacy IPv4 protocol")
}

func main() {
	if os.Geteuid() == 0 {
		fmt.Fprintf(os.Stderr, "WARNING: you are running this program as root. Consider setting the CAP_NET_RAW capability and running as non-root user as a more secure alternative\n")
	}

	flag.Parse()
	if Args.version {
		fmt.Printf("%v %v\n", ProgramName, ProgramVersion)
		os.Exit(0)
	}

	if len(flag.Args()) != 1 {
		log.Fatal("Exactly one target is required")
	}

	target, err := resolve(flag.Arg(0), !Args.v4)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stderr, "Target: %v\n", target)

	var dt dublintraceroute.DublinTraceroute
	if Args.v4 {
		dt = &probes.UDPv4{
			Target:    target,
			SrcPort:   uint16(Args.sport),
			DstPort:   uint16(Args.dport),
			NumPaths:  uint16(Args.npaths),
			MinTTL:    uint8(Args.minTTL),
			MaxTTL:    uint8(Args.maxTTL),
			Delay:     time.Duration(Args.delay) * time.Millisecond,
			Timeout:   DefaultReadTimeout,
			BrokenNAT: Args.brokenNAT,
		}
	} else {
		dt = &probes.UDPv6{
			Target:      target,
			SrcPort:     uint16(Args.sport),
			DstPort:     uint16(Args.dport),
			NumPaths:    uint16(Args.npaths),
			MinHopLimit: uint8(Args.minTTL),
			MaxHopLimit: uint8(Args.maxTTL),
			Delay:       time.Duration(Args.delay) * time.Millisecond,
			Timeout:     DefaultReadTimeout,
			BrokenNAT:   Args.brokenNAT,
		}
	}
	results, err := dt.Traceroute()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(results.ToJson(true))
}
