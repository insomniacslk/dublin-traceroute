package probev6

import (
	"bytes"
	"errors"
	"log"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/net/icmp"

	inet "github.com/insomniacslk/dublin-traceroute/go/dublintraceroute/net"
	"github.com/insomniacslk/dublin-traceroute/go/dublintraceroute/probes"
	"github.com/insomniacslk/dublin-traceroute/go/dublintraceroute/results"
)

// UDPv6 is a probe type based on IPv6 and UDP
type UDPv6 struct {
	Target      net.IP
	SrcPort     uint16
	DstPort     uint16
	UseSrcPort  bool
	NumPaths    uint16
	MinHopLimit uint8
	MaxHopLimit uint8
	Delay       time.Duration
	Timeout     time.Duration
	BrokenNAT   bool
}

// Validate checks that the probe is configured correctly and it is safe to
// subsequently run the Traceroute() method
func (d *UDPv6) Validate() error {
	if d.Target.To16() == nil {
		return errors.New("Invalid IPv6 address")
	}
	if d.UseSrcPort {
		if d.SrcPort+d.NumPaths > 0xffff {
			return errors.New("Source port plus number of paths cannot exceed 65535")
		}
	} else {
		if d.DstPort+d.NumPaths > 0xffff {
			return errors.New("Destination port plus number of paths cannot exceed 65535")
		}
	}
	if d.MaxHopLimit < d.MinHopLimit {
		return errors.New("Invalid maximum Hop Limit, must be greater or equal than minimum Hop Limit")
	}
	if d.Delay < 1 {
		return errors.New("Invalid delay, must be positive")
	}
	return nil
}

// packet generates a probe packet and returns its bytes
func (d UDPv6) packet(hl uint8, src, dst net.IP, srcport, dstport uint16) ([]byte, []byte, error) {
	// Forge the payload so that it can be used for path tracking and
	// NAT detection.
	//
	// The payload length does the trick here, in a similar manner to
	// how the IP ID is used for the IPv4 probes.
	// In order to uniquely track a probe packet we need a unique field
	// that:
	// * is part of the first 1280 bytes including the ICMPv6 packet.
	// * is not used by the ECMP hashing algorithm.
	//
	// The Payload Length in the IPv6 header is used for this purpose,
	// and the payload size is tuned to represent a unique ID that
	// will be used to identify the original probe packet carried by the
	// ICMP response.

	// Length is 13 for the first flow, 14 for the second, etc.
	// 13 is given by 8 (udp header length) + 5 (magic string
	// length, "NSMNC")
	plen := 10 + int(hl)
	magic := []byte("NSMNC")
	// FIXME this is wrong. Or maybe not.
	payload := bytes.Repeat(magic, plen/len(magic)+1)[:plen]

	udph := inet.UDP{
		Src: srcport,
		Dst: dstport,
	}
	udpb, err := udph.Marshal()
	if err != nil {
		return nil, nil, err
	}
	return udpb, payload, nil
}

type pkt struct {
	UDPHeader, Payload []byte
	Src                net.IP
	SrcPort, DstPort   int
	HopLimit           int
}

// packets returns a channel of packets that will be sent as probes
func (d UDPv6) packets(src, dst net.IP) <-chan pkt {
	numPackets := int(d.NumPaths) * int(d.MaxHopLimit-d.MinHopLimit)
	ret := make(chan pkt, numPackets)

	go func() {
		var srcPort, dstPort, basePort uint16
		if d.UseSrcPort {
			basePort = d.SrcPort
		} else {
			basePort = d.DstPort
		}
		for hl := d.MinHopLimit; hl <= d.MaxHopLimit; hl++ {
			for port := basePort; port < basePort+d.NumPaths; port++ {
				if d.UseSrcPort {
					srcPort = port
					dstPort = d.DstPort
				} else {
					srcPort = d.SrcPort
					dstPort = port
				}
				udpb, payload, err := d.packet(hl, src, dst, srcPort, dstPort)
				if err != nil {
					log.Printf("Warning: cannot generate packet for hop limit=%d srcport=%d dstport=%d: %v", hl, srcPort, dstPort, err)
				} else {
					ret <- pkt{UDPHeader: udpb, Payload: payload, Src: src, SrcPort: int(srcPort), DstPort: int(dstPort), HopLimit: int(hl)}
				}
			}
		}
		close(ret)
	}()
	return ret
}

// SendReceive sends all the packets to the target address, respecting the
// configured inter-packet delay
func (d UDPv6) SendReceive() ([]probes.Probe, []probes.ProbeResponse, error) {
	// FIXME close fd
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, nil, os.NewSyscallError("socket", err)
	}
	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return nil, nil, os.NewSyscallError("setsockopt", err)
	}
	if err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IP_HDRINCL, 1); err != nil {
		return nil, nil, os.NewSyscallError("setsockopt", err)
	}
	var daddrBytes [net.IPv6len]byte
	copy(daddrBytes[:], d.Target.To16())

	numPackets := int(d.NumPaths) * int(d.MaxHopLimit-d.MinHopLimit)

	// spawn the listener
	recvErrors := make(chan error)
	recvChan := make(chan []probes.ProbeResponse, 1)
	go func(errch chan error, rc chan []probes.ProbeResponse) {
		howLong := d.Delay*time.Duration(numPackets) + d.Timeout
		received, err := d.ListenFor(howLong)
		errch <- err
		// TODO pass the rp chan to ListenFor and let it feed packets there
		rc <- received
	}(recvErrors, recvChan)

	// ugly porkaround until I find how to get the local address in a better way
	conn, err := net.Dial("udp6", net.JoinHostPort(d.Target.String(), "0"))
	if err != nil {
		return nil, nil, err
	}
	localAddr := *(conn.LocalAddr()).(*net.UDPAddr)
	conn.Close()
	sent := make([]probes.Probe, 0, numPackets)
	bound := make(map[int]bool)
	for p := range d.packets(localAddr.IP, d.Target) {
		if _, ok := bound[p.SrcPort]; !ok {
			// bind() can be called only once per path listener
			var saddrBytes [16]byte
			copy(saddrBytes[:], p.Src.To16())
			sa := syscall.SockaddrInet6{
				Addr: saddrBytes,
				Port: int(p.SrcPort),
			}
			if err := syscall.Bind(fd, &sa); err != nil {
				return nil, nil, os.NewSyscallError("bind", err)
			}
			bound[p.SrcPort] = true
		}
		daddr := syscall.SockaddrInet6{
			Addr: daddrBytes,
			Port: int(p.DstPort),
		}
		// desired hoplimit
		if err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, p.HopLimit); err != nil {
			return nil, nil, os.NewSyscallError("setsockopt", err)
		}
		if err = syscall.Sendto(fd, p.Payload, 0, &daddr); err != nil {
			return nil, nil, os.NewSyscallError("sendto", err)
		}
		probe := ProbeUDPv6{
			Data:       append(p.UDPHeader, p.Payload...),
			LocalAddr:  localAddr.IP,
			RemoteAddr: d.Target,
			HopLimit:   p.HopLimit,
			PayloadLen: len(p.UDPHeader) + len(p.Payload),
			Timestamp:  time.Now(),
		}
		if err := probe.Validate(); err != nil {
			return nil, nil, err
		}
		sent = append(sent, &probe)
		time.Sleep(d.Delay)
	}
	if err = <-recvErrors; err != nil {
		return nil, nil, err
	}
	received := <-recvChan
	return sent, received, nil
}

// ListenFor waits for ICMP packets until the timeout expires
func (d UDPv6) ListenFor(howLong time.Duration) ([]probes.ProbeResponse, error) {
	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	packets := make([]probes.ProbeResponse, 0)
	deadline := time.Now().Add(howLong)
	for {
		if deadline.Sub(time.Now()) <= 0 {
			break
		}
		select {
		default:
			// TODO tune data size
			data := make([]byte, 4096)
			now := time.Now()
			conn.SetReadDeadline(now.Add(time.Millisecond * 100))
			n, addr, err := conn.ReadFrom(data)
			receivedAt := time.Now()
			if err != nil {
				if nerr, ok := err.(*net.OpError); ok {
					if nerr.Timeout() {
						continue
					}
					return nil, err
				}
			}
			packets = append(packets, &ProbeResponseUDPv6{
				Data:      data[:n],
				Addr:      (*(addr).(*net.IPAddr)).IP,
				Timestamp: receivedAt,
			})
		}
	}
	return packets, nil
}

// Match compares the sent and received packets and finds the matching ones. It
// returns a Results structure
func (d UDPv6) Match(sent []probes.Probe, received []probes.ProbeResponse) results.Results {
	res := results.Results{
		Flows: make(map[uint16][]results.Probe),
	}
	for _, sp := range sent {
		spu := sp.(*ProbeUDPv6)
		if err := spu.Validate(); err != nil {
			log.Printf("Invalid probe: %v", err)
			continue
		}
		sentUDP := spu.UDP()
		probe := results.Probe{
			Sent: results.Packet{
				Timestamp: spu.Timestamp,
				IP: results.IP{
					SrcIP: spu.LocalAddr,
					DstIP: spu.RemoteAddr,
					TTL:   uint8(spu.HopLimit), // TTL should be really renamed to something better..
				},
				UDP: results.UDP{
					SrcPort: uint16(sentUDP.Src),
					DstPort: uint16(sentUDP.Dst),
				},
			},
		}
		var flowID uint16
		if d.UseSrcPort {
			flowID = uint16(sentUDP.Src)
		} else {
			flowID = uint16(sentUDP.Dst)
		}
		for _, rp := range received {
			rpu := rp.(*ProbeResponseUDPv6)
			if err := rpu.Validate(); err != nil {
				log.Printf("Invalid probe response: %v", err)
				continue
			}
			if !rpu.Matches(spu) {
				continue
			}
			// source port may be mangled by a NAT
			if sentUDP.Src != rpu.InnerUDP().Src {
				// source ports do not match - it's not for this packet
				probe.NATID = uint16(rpu.InnerUDP().Src)
			}
			// TODO
			// Here, in IPv4, we would check for innerIP.ID != sentIP.Id but
			// for IPv6 we need something different. See the comment above
			// about Payload Length, and line 278 in probes/probev4/udpv4.go

			// at this point, we know that the sent and received packet
			// belong to the same flow.
			// TODO in IPv4, at this point we can detect a NAT using the
			// checksum. Implement a similar technique for v6

			// TODO implement computeFlowHash also for IPv6. The function
			// can be generalized for both v4 and v6
			// flowhash, err := computeFlowHash(spu.Packet)
			icmp := rpu.ICMPv6()
			description := "Unknown"
			if icmp.Type == inet.ICMPv6TypeDestUnreachable && icmp.Code == inet.ICMPv6CodePortUnreachable {
				description = "Destination port unreachable"
			} else if icmp.Type == inet.ICMPv6TypeTimeExceeded && icmp.Code == inet.ICMPv6CodeHopLimitExceeded {
				description = "Hop limit exceeded"
			}
			// this is our packet. Let's fill the probe data up
			// probe.Flowhash = flowhash
			// TODO check if To16() is the right thing to do here
			probe.IsLast = bytes.Equal(rpu.Addr.To16(), d.Target.To16())
			probe.Name = rpu.Addr.String()
			probe.RttUsec = uint64(rpu.Timestamp.Sub(spu.Timestamp)) / 1000
			probe.ZeroTTLForwardingBug = (rpu.InnerIP().HopLimit == 0)
			probe.Received = &results.Packet{
				Timestamp: rpu.Timestamp,
				ICMP: results.ICMP{
					Type:        uint8(icmp.Type),
					Code:        uint8(icmp.Code),
					Description: description,
				},
				IP: results.IP{
					SrcIP: rpu.Addr,
					DstIP: spu.LocalAddr,
				},
				UDP: results.UDP{
					SrcPort: uint16(rpu.InnerUDP().Src),
					DstPort: uint16(rpu.InnerUDP().Dst),
				},
			}
			// break, since this is a response to the sent probe
			break
		}
		res.Flows[flowID] = append(res.Flows[flowID], probe)
	}
	return res
}

// Traceroute sends the probes and returns a Results structure or an error
func (d UDPv6) Traceroute() (*results.Results, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	sent, received, err := d.SendReceive()
	if err != nil {
		return nil, err
	}
	results := d.Match(sent, received)

	return &results, nil
}
