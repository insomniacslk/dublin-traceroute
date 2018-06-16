package probev4

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/insomniacslk/dublin-traceroute/go/dublintraceroute/probes"
	"github.com/insomniacslk/dublin-traceroute/go/dublintraceroute/results"
	"golang.org/x/net/icmp"
)

// UDPv4 is a probe type based on IPv4 and UDP
type UDPv4 struct {
	Target   net.IP
	SrcPort  uint16
	DstPort  uint16
	NumPaths uint16
	MinTTL   uint8
	MaxTTL   uint8
	Delay    time.Duration
	Timeout  time.Duration
	// TODO implement broken nat detection
	BrokenNAT bool
}

func computeFlowhash(p gopacket.Packet) (uint16, error) {
	if len(p.Layers()) < 2 ||
		p.Layers()[0].LayerType() != layers.LayerTypeIPv4 ||
		p.Layers()[1].LayerType() != layers.LayerTypeUDP {
		return 0, errors.New("Cannot compute flow hash: required a packet with IP and UDP layers")
	}
	ip := p.Layers()[0].(*layers.IPv4)
	udp := p.Layers()[1].(*layers.UDP)
	var flowhash uint16
	flowhash += uint16(ip.TOS) + uint16(ip.Protocol)
	flowhash += binary.BigEndian.Uint16(ip.SrcIP.To4()[:2]) + binary.BigEndian.Uint16(ip.SrcIP.To4()[2:4])
	flowhash += binary.BigEndian.Uint16(ip.DstIP.To4()[:2]) + binary.BigEndian.Uint16(ip.DstIP.To4()[2:4])
	flowhash += uint16(udp.SrcPort) + uint16(udp.DstPort)
	return flowhash, nil
}

// Validate checks that the probe is configured correctly and it is safe to
// subsequently run the Traceroute() method
func (d *UDPv4) Validate() error {
	if d.Target.To4() == nil {
		return errors.New("Invalid IPv4 address")
	}
	if d.NumPaths == 0 {
		return errors.New("Number of paths must be a positive integer")
	}
	if d.DstPort+d.NumPaths > 0xffff {
		return errors.New("Destination port plus number of paths cannot exceed 65535")
	}
	if d.MinTTL == 0 {
		return errors.New("Minimum TTL must be a positive integer")
	}
	if d.MaxTTL < d.MinTTL {
		return errors.New("Invalid maximum TTL, must be greater or equal than minimum TTL")
	}
	if d.Delay < 1 {
		return errors.New("Invalid delay, must be positive")
	}
	return nil
}

// ForgePackets returns a list of packets that will be sent as probes
func (d UDPv4) ForgePackets() []gopacket.Packet {
	packets := make([]gopacket.Packet, 0)
	if d.NumPaths == 0 {
		return packets
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	for ttl := d.MinTTL; ttl <= d.MaxTTL; ttl++ {
		ip := layers.IPv4{
			Version:  4,
			SrcIP:    net.IPv4zero,
			DstIP:    d.Target,
			TTL:      ttl,
			Flags:    layers.IPv4DontFragment,
			Protocol: layers.IPProtocolUDP,
		}
		for dstPort := d.DstPort; dstPort < d.DstPort+d.NumPaths; dstPort++ {
			udp := layers.UDP{
				SrcPort: layers.UDPPort(d.SrcPort),
				DstPort: layers.UDPPort(dstPort),
			}
			udp.SetNetworkLayerForChecksum(&ip)

			// forge the payload. The last two bytes will be adjusted to have a
			// predictable checksum for NAT detection
			payload := []byte{'N', 'S', 'M', 'N', 'C'}
			id := dstPort + uint16(ttl)
			payload = append(payload, byte(id&0xff), byte((id>>8)&0xff))

			// serialize once to compute the UDP checksum, that will be used as
			// IP ID in order to detect NATs
			gopacket.SerializeLayers(buf, opts, &ip, &udp, gopacket.Payload(payload))
			p := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Lazy)
			// extract the UDP checksum and assign it to the IP ID, will be used
			// to keep track of NATs
			u := p.TransportLayer().(*layers.UDP)
			ip.Id = u.Checksum
			// serialize the packet again after manipulating the IP ID
			gopacket.SerializeLayers(buf, opts, &ip, &udp, gopacket.Payload(payload))
			p = gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Lazy)
			packets = append(packets, p)
		}
	}
	return packets
}

// SendReceive sends all the packets to the target address, respecting the configured
// inter-packet delay
func (d UDPv4) SendReceive(packets []gopacket.Packet) ([]probes.Probe, []probes.ProbeResponse, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, nil, err
	}
	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return nil, nil, err
	}
	if err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return nil, nil, err
	}
	var daddrBytes [net.IPv4len]byte
	copy(daddrBytes[:], d.Target.To4())

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
	conn, err := net.Dial("udp4", net.JoinHostPort(d.Target.String(), "0"))
	if err != nil {
		return nil, nil, err
	}
	localAddr := *(conn.LocalAddr()).(*net.UDPAddr)
	conn.Close()
	sent := make([]probes.Probe, 0, len(packets))
	for _, p := range packets {
		daddr := syscall.SockaddrInet4{
			Addr: daddrBytes,
			Port: int(p.TransportLayer().(*layers.UDP).DstPort),
		}
		if err = syscall.Sendto(fd, p.Data(), 0, &daddr); err != nil {
			return nil, nil, err
		}
		sent = append(sent, &ProbeUDPv4{Packet: p, LocalAddr: localAddr.IP, Timestamp: time.Now()})
		time.Sleep(d.Delay)
	}
	if err = <-recvErrors; err != nil {
		return nil, nil, err
	}
	received := <-recvChan
	return sent, received, nil
}

// ListenFor waits for ICMP packets until the timeout expires
func (d UDPv4) ListenFor(howLong time.Duration) ([]probes.ProbeResponse, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
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
			p := gopacket.NewPacket(data[:n], layers.LayerTypeICMPv4, gopacket.Lazy)
			packets = append(packets, &ProbeResponseUDPv4{
				Packet:    p,
				Addr:      (*(addr).(*net.IPAddr)).IP,
				Timestamp: now,
			})
		}
	}
	return packets, nil
}

// Match compares the sent and received packets and finds the matching ones. It
// returns a Results structure.
func (d UDPv4) Match(sent []probes.Probe, received []probes.ProbeResponse) results.Results {
	res := results.Results{
		Flows: make(map[uint16][]results.Probe),
	}

	for _, sp := range sent {
		spu := sp.(*ProbeUDPv4)
		sentIP, err := spu.IPv4Layer()
		if err != nil {
			log.Printf("Error getting IPv4 layer in sent packet: %v", err)
			continue
		}
		sentUDP, err := spu.UDPLayer()
		if err != nil {
			log.Printf("Error getting UDP layer in sent packet: %v", err)
			continue
		}
		probe := results.Probe{
			Sent: results.Packet{
				Timestamp: spu.Timestamp,
				IP: results.IP{
					SrcIP: spu.LocalAddr, // unfortunately gopacket does not compute sentIP.SrcIP,
					DstIP: sentIP.DstIP,
					TTL:   sentIP.TTL,
				},
				UDP: results.UDP{
					SrcPort: uint16(sentUDP.SrcPort),
					DstPort: uint16(sentUDP.DstPort),
				},
			},
		}
		flowID := uint16(sentUDP.DstPort)
		for _, rp := range received {
			rpu := rp.(*ProbeResponseUDPv4)
			icmp, err := rpu.ICMPv4Layer()
			if err != nil {
				log.Printf("Error getting ICMP layer in received packet: %v", err)
				continue
			}
			if icmp.TypeCode.Type() != layers.ICMPv4TypeTimeExceeded &&
				!(icmp.TypeCode.Type() == layers.ICMPv4TypeDestinationUnreachable && icmp.TypeCode.Code() == layers.ICMPv4CodePort) {
				// we want time-exceeded or port-unreachable
				log.Print("Bad ICMP type/code")
				continue
			}
			innerIP, err := rpu.InnerIPv4Layer()
			if err != nil {
				log.Printf("Error getting inner IPv4 layer in received packet: %v", err)
				continue
			}
			if !bytes.Equal(innerIP.DstIP.To4(), d.Target.To4()) {
				// this is not a response to any of our probes, discard it
				continue
			}
			innerUDP, err := rpu.InnerUDPLayer()
			if err != nil {
				log.Printf("Error getting inner UDP layer in received packet: %v", err)
				continue
			}
			if sentUDP.SrcPort != innerUDP.SrcPort || sentUDP.DstPort != innerUDP.DstPort {
				// source and destination portdo not match - it's not for
                // this packet
				continue
			}
			if innerIP.Id != sentIP.Id {
				// the two packets do not belong to the same flow
				continue
			}
			// the two packets belong to the same flow. If the checksum
			// differ there's a NAT
			NATID := innerUDP.Checksum - sentUDP.Checksum
			// TODO this works when the source port is fixed. Allow for variable
			//      source port too
			flowhash, err := computeFlowhash(spu.Packet)
			if err != nil {
				log.Print(err)
				continue
			}
			// gopacket does not export the fields with descriptions :(
			description := "Unknown"
			if icmp.TypeCode.Type() == layers.ICMPv4TypeDestinationUnreachable && icmp.TypeCode.Code() == layers.ICMPv4CodePort {
				description = "Destination port unreachable"
			} else if icmp.TypeCode.Type() == layers.ICMPv4TypeTimeExceeded && icmp.TypeCode.Code() == layers.ICMPv4CodeTTLExceeded {
				description = "TTL expired in transit"
			}
			// This is our packet, let's fill the probe data up
			probe.Flowhash = flowhash
			probe.IsLast = bytes.Equal(rpu.Addr.To4(), d.Target.To4())
			probe.Name = rpu.Addr.String() // TODO compute this field
			probe.RttUsec = uint64(rpu.Timestamp.Sub(spu.Timestamp)) / 1000
			probe.NATID = NATID
			probe.ZeroTTLForwardingBug = (innerIP.TTL == 0)
			probe.Received = &results.Packet{
				Timestamp: rpu.Timestamp,
				ICMP: results.ICMP{
					// XXX it seems that gopacket's ICMP does not support extensions for MPLS..
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
func (d UDPv4) Traceroute() (*results.Results, error) {
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
