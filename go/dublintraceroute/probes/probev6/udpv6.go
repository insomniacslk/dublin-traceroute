package probev6

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/net/icmp"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/insomniacslk/dublin-traceroute/go/dublintraceroute/probes"
	"github.com/insomniacslk/dublin-traceroute/go/dublintraceroute/results"
)

// UDPv6 is a probe type based on IPv6 and UDP
type UDPv6 struct {
	Target      net.IP
	SrcPort     uint16
	DstPort     uint16
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
	if d.DstPort+d.NumPaths > 0xffff {
		return errors.New("Destination port plus number of paths cannot exceed 65535")
	}
	if d.MaxHopLimit < d.MinHopLimit {
		return errors.New("Invalid maximum Hop Limit, must be greater or equal than minimum Hop Limit")
	}
	if d.Delay < 1 {
		return errors.New("Invalid delay, must be positive")
	}
	return nil
}

// ForgePackets returns a list of packets that will be sent as probes
func (d UDPv6) ForgePackets() []gopacket.Packet {
	packets := make([]gopacket.Packet, 0)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true}
	for hopLimit := d.MinHopLimit; hopLimit <= d.MaxHopLimit; hopLimit++ {
		ip := layers.IPv6{
			Version:    6,
			SrcIP:      net.IPv6unspecified,
			DstIP:      d.Target,
			HopLimit:   hopLimit,
			NextHeader: layers.IPProtocolUDP,
		}
		for dstPort := d.DstPort; dstPort <= d.DstPort+d.NumPaths-1; dstPort++ {
			udp := layers.UDP{
				SrcPort: layers.UDPPort(d.SrcPort),
				DstPort: layers.UDPPort(dstPort),
			}
			udp.SetNetworkLayerForChecksum(&ip)
			ip.Length += 8 // UDP header size

			// forge payload
			// The payload does the trick here - in a similar manner to how the
			// IP ID is used for the IPv4 probes.
			// In order to uniquely track a probe packet we need a unique  field
			// that is part of the IP header or the first 8 bytes of the above
			// layer (UDP, TCP, whatever it is), because these are the bytes
			// that are guaranteed to be returned by an ICMP message.
			// This field also doesn't have to be used by the ECMP hashing
			// algorithm. Therefore dublin-traceroute uses the Payload Length in
			// the IPv6 header and tunes its size to represent a unique ID that
			// will be used to identify the original probe packet carried by the
			// ICMP response.
			// TODO implement the above technique
			payload := []byte{'N', 'S', 'M', 'N', 'C'}
			id := dstPort + uint16(hopLimit)
			payload = append(payload, byte(id&0xff), byte((id>>8)&0xff))
			binary.BigEndian.PutUint16(payload[len(payload)-2:], dstPort+uint16(hopLimit))

			gopacket.SerializeLayers(buf, opts, &ip, &udp, gopacket.Payload(payload))
			p := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv6, gopacket.Lazy)
			packets = append(packets, p)
		}
	}
	return packets
}

// SendReceive sends all the packets to the target address, respecting the
// configured inter-packet delay
func (d UDPv6) SendReceive(packets []gopacket.Packet) ([]probes.Probe, []probes.ProbeResponse, error) {
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

	// spawn the listener
	recvErrors := make(chan error)
	recvChan := make(chan []probes.ProbeResponse, 1)
	go func(errch chan error, rc chan []probes.ProbeResponse) {
		howLong := d.Delay*time.Duration(len(packets)) + d.Timeout
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
	sent := make([]probes.Probe, 0, len(packets))
	for _, p := range packets {
		// TODO set source port
		daddr := syscall.SockaddrInet6{
			Addr: daddrBytes,
			Port: int(p.TransportLayer().(*layers.UDP).DstPort),
		}
		// FIXME lots of overhead here! Don't use setsockopt for each packet
		// TODO add ancillary data via cmsg, IPV6_UNICAST_HOPS set to the
		// desired hoplimit
		hoplimit := p.NetworkLayer().(*layers.IPv6).HopLimit
		if err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, int(hoplimit)); err != nil {
			return nil, nil, os.NewSyscallError("setsockopt", err)
		}
		if err = syscall.Sendto(fd, p.Data(), 0, &daddr); err != nil {
			return nil, nil, os.NewSyscallError("sendto", err)
		}
		sent = append(sent, ProbeUDPv6{Packet: p, LocalAddr: localAddr.IP, Timestamp: time.Now()})
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
			data := make([]byte, 1024)
			now := time.Now()
			conn.SetReadDeadline(now.Add(time.Millisecond * 100))
			n, addr, err := conn.ReadFrom(data)
			if err != nil {
				if nerr, ok := err.(*net.OpError); ok {
					if nerr.Timeout() {
						continue
					}
					return nil, err
				}
			}
			p := gopacket.NewPacket(data[:n], layers.LayerTypeICMPv6, gopacket.Lazy)
			packets = append(packets, &ProbeResponseUDPv6{
				Packet:    p,
				Addr:      (*(addr).(*net.IPAddr)).IP,
				Timestamp: now,
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
		spu := sp.(ProbeUDPv6)
		sentIP, err := spu.IPv6Layer()
		if err != nil {
			log.Printf("Error getting IPv6 layer in sent packet: %v", err)
			continue
		}
		sentUDP, err := spu.UDPLayer()
		if err != nil {
			log.Printf("Error getting UDP layer in sent packet: %v", err)
		}
		probe := results.Probe{
			Sent: results.Packet{
				Timestamp: spu.Timestamp,
				IP: results.IP{
					SrcIP: spu.LocalAddr, // unfortunately gopacket does not compute sentIP.SrcIP
					DstIP: sentIP.DstIP,
					TTL:   sentIP.HopLimit, // TTL should be really renamed to something better..
				},
				UDP: results.UDP{
					SrcPort: uint16(sentUDP.SrcPort),
					DstPort: uint16(sentUDP.DstPort),
				},
			},
		}
		flowID := uint16(sentUDP.DstPort)
		for _, rp := range received {
			rpu := rp.(*ProbeResponseUDPv6)
			icmp, err := rpu.ICMPv6Layer()
			if err != nil {
				log.Printf("Error getting ICMPv6 layer in received packet: %v", err)
				continue
			}
			if icmp.TypeCode.Type() != layers.ICMPv6TypeTimeExceeded &&
				!(icmp.TypeCode.Type() == layers.ICMPv6TypeDestinationUnreachable && icmp.TypeCode.Code() == layers.ICMPv6CodePortUnreachable) {
				// we want time-exceeded or port-unreachable
				log.Print("Bad ICMP type/code")
				continue
			}
			innerIP, err := rpu.InnerIPv6Layer()
			if err != nil {
				log.Printf("Error getting inner IPv6 layer in received packet: %v", err)
				continue
			}
			// TODO check that To16() is the right thing to call here
			if !bytes.Equal(innerIP.DstIP.To16(), d.Target.To16()) {
				// this is not a response to any of our probes, discard it
				continue
			}
			innerUDP, err := rpu.InnerUDPLayer()
			if err != nil {
				log.Printf("Error getting inner UDP layer in received packet: %v", err)
				continue
			}
			if sentUDP.SrcPort != innerUDP.SrcPort || sentUDP.DstPort != innerUDP.DstPort {
				// source and destination ports do not match - it's not for
				// this packet
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

			// gopacket does not export the fields with descriptions :(
			description := "Unknown"
			if icmp.TypeCode.Type() == layers.ICMPv6TypeDestinationUnreachable && icmp.TypeCode.Code() == layers.ICMPv6CodePortUnreachable {
				description = "Destination port unreachable"
			} else if icmp.TypeCode.Type() == layers.ICMPv6TypeTimeExceeded && icmp.TypeCode.Code() == layers.ICMPv6CodeHopLimitExceeded {
				description = "Hop limit exceeded"
			}
			// this is our packet. Let's fill the probe data up
			// probe.Flowhash = flowhash
			// TODO check if To16() is the right thing to do here
			probe.IsLast = bytes.Equal(rpu.Addr.To16(), d.Target.To16())
			probe.Name = rpu.Addr.String() // TODO compute this field
			probe.RttUsec = uint64(rpu.Timestamp.Sub(spu.Timestamp)) / 1000
			// probe.NATID = NATID // TODO implement NAT detection for IPv6
			probe.ZeroTTLForwardingBug = (innerIP.HopLimit == 0)
			probe.Received = &results.Packet{
				Timestamp: rpu.Timestamp,
				ICMP: results.ICMP{
					// XXX it seems that gopacket's ICMP does not support
					// extentions for MPLS..
					Type:        icmp.TypeCode.Type(),
					Code:        icmp.TypeCode.Code(),
					Description: description,
				},
				IP: results.IP{
					SrcIP: rpu.Addr,
					DstIP: spu.LocalAddr,
				},
				UDP: results.UDP{
					SrcPort: uint16(innerUDP.SrcPort),
					DstPort: uint16(innerUDP.DstPort),
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
	packets := d.ForgePackets()
	sent, received, err := d.SendReceive(packets)
	if err != nil {
		return nil, err
	}
	results := d.Match(sent, received)

	return &results, nil
}
