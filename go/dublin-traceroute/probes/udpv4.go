package dublintraceroute

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
	"golang.org/x/net/icmp"

	dublintraceroute ".."
)

// UDPv4 is a probe type based on IPv6 and UDP
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

// TODO implement this function
func computeFlowhash(p gopacket.Packet) (uint16, error) {
	if len(p.Layers()) < 2 ||
		p.Layers()[0].LayerType() != layers.LayerTypeIPv4 ||
		p.Layers()[1].LayerType() != layers.LayerTypeUDP {
		return 0, errors.New("Cannot compute flow hash: required a packet with IP and UDP layers")
	}
	var flowhash uint16
	ip := p.Layers()[0].(*layers.IPv4)
	udp := p.Layers()[1].(*layers.UDP)
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

type probeResponse struct {
	Addr   net.IPAddr
	Packet gopacket.Packet
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

// Send sends all the packets to the target address, respecting the configured
// inter-packet delay
func (d UDPv4) SendReceive(packets []gopacket.Packet) ([]probeResponse, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, err
	}
	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return nil, err
	}
	if err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return nil, err
	}
	var daddrBytes [4]byte
	copy(daddrBytes[:], d.Target.To4())

	// spawn the listener
	recvErrors := make(chan error)
	recvChan := make(chan []probeResponse, 1)
	go func(errch chan error, rc chan []probeResponse) {
		howLong := d.Delay*time.Duration(len(packets)) + d.Timeout
		received, err := d.ListenFor(howLong)
		errch <- err
		// TODO pass the rp chan to ListenFor and let it feed packets there
		rc <- received
	}(recvErrors, recvChan)

	for _, p := range packets {
		daddr := syscall.SockaddrInet4{
			Addr: daddrBytes,
			Port: int(p.TransportLayer().(*layers.UDP).DstPort),
		}
		if err = syscall.Sendto(fd, p.Data(), 0, &daddr); err != nil {
			return nil, err
		}
		time.Sleep(d.Delay)
	}
	if err = <-recvErrors; err != nil {
		return nil, err
	}
	received := <-recvChan
	return received, nil
}

// ListenFor waits for ICMP packets (ttl-expired or port-unreachable) until the
// timeout expires
func (d UDPv4) ListenFor(howLong time.Duration) ([]probeResponse, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	packets := make([]probeResponse, 0)
	deadline := time.Now().Add(howLong)
	for {
		if deadline.Sub(time.Now()) <= 0 {
			break
		}
		select {
		default:
			// TODO tune data size
			data := make([]byte, 1024)
			conn.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
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
			packets = append(packets, probeResponse{Packet: p, Addr: *(addr).(*net.IPAddr)})
		}
	}
	return packets, nil
}

// Match compares the sent and received packets and finds the matching ones. It
// returns a Results structure.
func (d UDPv4) Match(sent []gopacket.Packet, received []probeResponse) dublintraceroute.Results {
	results := dublintraceroute.Results{
		Flows: make(map[uint16][]dublintraceroute.Probe),
	}
	// TODO add source node to the results
	for _, rp := range received {
		if len(rp.Packet.Layers()) < 2 {
			// we are looking for packets with two layers - ICMP and an UDP payload
			continue
		}
		if rp.Packet.Layers()[0].LayerType() != layers.LayerTypeICMPv4 {
			// not an ICMP
			continue
		}
		icmp := rp.Packet.Layers()[0].(*layers.ICMPv4)
		if icmp.TypeCode.Type() != layers.ICMPv4TypeTimeExceeded &&
			!(icmp.TypeCode.Type() == layers.ICMPv4TypeDestinationUnreachable && icmp.TypeCode.Code() == layers.ICMPv4CodePort) {
			// we want time-exceeded or port-unreachable
			continue
		}
		// XXX it seems like gopacket's ICMP does not support extensions for MPLS..
		innerPacket := gopacket.NewPacket(icmp.LayerPayload(), layers.LayerTypeIPv4, gopacket.Default)
		if len(innerPacket.Layers()) < 2 {
			// we want the inner packet to have two layers, IP and UDP, i.e.
			// what we have sent
			continue
		}
		innerIP, ok := innerPacket.Layers()[0].(*layers.IPv4)
		if !ok {
			continue
		}
		innerUDP, ok := innerPacket.Layers()[1].(*layers.UDP)
		if !ok {
			continue
		}
		if !bytes.Equal(innerIP.DstIP.To4(), d.Target.To4()) {
			// the destination is not our target, discard it
			continue
		}
		for _, sp := range sent {
			sentIP, ok := sp.Layers()[0].(*layers.IPv4)
			if !ok {
				// invalid sent packet
				log.Print("Invalid sent packet, the first layer is not IPv4")
				continue
			}
			sentUDP, ok := sp.Layers()[1].(*layers.UDP)
			if !ok {
				// invalid sent packet
				log.Print("Invalid sent packet, the second layer is not UDP")
				continue
			}
			if sentUDP.SrcPort != innerUDP.SrcPort || sentUDP.DstPort != innerUDP.DstPort {
				// source and destination port do not match - it's not this
				// packet
				continue
			}
			if innerIP.Id != sentIP.Id {
				// the two packets do not belong to the same flow
				continue
			}
			// the two packets belong to the same flow. If the checksum
			// differ there's a NAT
			// TODO add NAT ID information to detect multiple NATs
			NATID := innerUDP.Checksum - sentUDP.Checksum
			// TODO this works when the source port is fixed. Allow for variable
			//      source port too
			flowID := uint16(sentUDP.DstPort)
			flowhash, err := computeFlowhash(sp)
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
			probe := dublintraceroute.Probe{
				Flowhash: flowhash,
				IsLast:   false, // TODO compute this field
				Name:     "",    // TODO compute this field
				NATID:    NATID,
				RttUsec:  0, // TODO compute this field
				Sent: dublintraceroute.Packet{
					Timestamp: time.Unix(0, 0), // TODO compute this field
					IP: dublintraceroute.IP{
						// TODO get the computed IP or this will be 0.0.0.0
						SrcIP: sentIP.SrcIP,
						DstIP: sentIP.DstIP,
						TTL:   sentIP.TTL,
					},
					UDP: dublintraceroute.UDP{
						SrcPort: uint16(sentUDP.SrcPort),
						DstPort: uint16(sentUDP.DstPort),
					},
				},
				Received: dublintraceroute.Packet{
					Timestamp: time.Unix(0, 0), // TODO compute this field
					ICMP: dublintraceroute.ICMP{
						Type:        icmp.TypeCode.Type(),
						Code:        icmp.TypeCode.Code(),
						Description: description,
					},
					IP: dublintraceroute.IP{
						SrcIP: innerIP.SrcIP,
						DstIP: innerIP.DstIP,
						TTL:   innerIP.TTL,
					},
					UDP: dublintraceroute.UDP{
						SrcPort: uint16(innerUDP.SrcPort),
						DstPort: uint16(innerUDP.DstPort),
					},
				},
				ZeroTTLForwardingBug: innerIP.TTL == 0,
			}
			results.Flows[flowID] = append(results.Flows[flowID], probe)
		}
	}
	return results
}

// Traceroute sends the probes and returns a Results structure or an error
func (d UDPv4) Traceroute() (*dublintraceroute.Results, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	packets := d.ForgePackets()
	received, err := d.SendReceive(packets)
	if err != nil {
		return nil, err
	}

	results := d.Match(packets, received)

	return &results, nil
}
