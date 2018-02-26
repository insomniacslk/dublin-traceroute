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
	Target    net.IP
	SrcPort   uint16
	DstPort   uint16
	NumPaths  uint16
	MinTTL    uint8
	MaxTTL    uint8
	Delay     time.Duration
	Timeout   time.Duration
	BrokenNAT bool
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
			payload := []byte{'N', 'S', 'M', 'N', 'C', 0x00, 0x00}
			// FIXME the payload fixup is yielding the wrong checksum, this
			//       impacts the flow ID correctness
			binary.BigEndian.PutUint16(payload[len(payload)-2:], dstPort+uint16(ttl))

			// serialize once to compute the UDP checksum. Unfortunately
			// gopacket does not export computeChecksum and I don't want to
			// reimplement it.
			// TODO if the performances appear to be impacted by the double
			// serialization, implement a checksum function
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
func (d UDPv4) Send(packets []gopacket.Packet) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return err
	}
	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return err
	}
	if err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return err
	}
	var daddrBytes [4]byte
	copy(daddrBytes[:], d.Target.To4())
	for _, p := range packets {
		daddr := syscall.SockaddrInet4{
			Addr: daddrBytes,
			Port: int(p.TransportLayer().(*layers.UDP).DstPort),
		}
		if err = syscall.Sendto(fd, p.Data(), 0, &daddr); err != nil {
			return err
		}
		time.Sleep(d.Delay)
	}

	return nil
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
			NATID := innerUDP.Checksum
			flowID := sentIP.Id
			probe := dublintraceroute.Probe{
				From:    rp.Addr.IP,
				SrcPort: uint16(innerUDP.SrcPort),
				DstPort: uint16(innerUDP.DstPort),
				TTL:     uint8(sentIP.TTL),
				NATID:   NATID,
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
	sendErrors := make(chan error)
	go func(errch chan error) {
		if err := d.Send(packets); err != nil {
			errch <- err
			return
		}
		errch <- nil
	}(sendErrors)
	// wait enough time for response packets
	howLong := d.Delay*time.Duration(len(packets)) + d.Timeout
	received, err := d.ListenFor(howLong)
	if err != nil {
		return nil, err
	}
	if err = <-sendErrors; err != nil {
		return nil, err
	}

	results := d.Match(packets, received)

	return &results, nil
}
