package probev4

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"syscall"
	"time"

	inet "github.com/insomniacslk/dublin-traceroute/go/dublintraceroute/net"
	"github.com/insomniacslk/dublin-traceroute/go/dublintraceroute/probes"
	"github.com/insomniacslk/dublin-traceroute/go/dublintraceroute/results"
	"golang.org/x/net/icmp"
)

// UDPv4 is a probe type based on IPv4 and UDP
type UDPv4 struct {
	Target     net.IP
	SrcPort    uint16
	DstPort    uint16
	UseSrcPort bool
	NumPaths   uint16
	MinTTL     uint8
	MaxTTL     uint8
	Delay      time.Duration
	Timeout    time.Duration
	// TODO implement broken nat detection
	BrokenNAT bool
}

func computeFlowhash(p *ProbeResponseUDPv4) (uint16, error) {
	if err := p.Validate(); err != nil {
		return 0, err
	}
	var flowhash uint16
	flowhash += uint16(p.InnerIP().DiffServ) + uint16(p.InnerIP().Proto)
	flowhash += binary.BigEndian.Uint16(p.InnerIP().Src.To4()[:2]) + binary.BigEndian.Uint16(p.InnerIP().Src.To4()[2:4])
	flowhash += binary.BigEndian.Uint16(p.InnerIP().Dst.To4()[:2]) + binary.BigEndian.Uint16(p.InnerIP().Dst.To4()[2:4])
	flowhash += uint16(p.InnerUDP().Src) + uint16(p.InnerUDP().Dst)
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
	if d.UseSrcPort {
		if d.SrcPort+d.NumPaths > 0xffff {
			return errors.New("Source port plus number of paths cannot exceed 65535")
		}
	} else {
		if d.DstPort+d.NumPaths > 0xffff {
			return errors.New("Destination port plus number of paths cannot exceed 65535")
		}
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

// Packet generates a probe packet and returns it as bytes.
func (d UDPv4) packet(ttl uint8, src, dst net.IP, srcport, dstport uint16) ([]byte, error) {
	// forge the payload. The last two bytes will be adjusted to have a
	// predictable checksum for NAT detection
	payload := []byte("NSMNC\x00\x00\x00")
	id := uint16(ttl)
	if d.UseSrcPort {
		id += srcport
	} else {
		id += dstport
	}
	payload[6] = byte((id >> 8) & 0xff)
	payload[7] = byte(id & 0xff)

	udph := inet.UDP{
		Src: srcport,
		Dst: dstport,
	}
	iph := inet.IPv4{
		Flags: inet.DontFragment,
		TTL:   int(ttl),
		Proto: inet.ProtoUDP,
		Src:   src,
		Dst:   dst,
	}
	iph.SetNext(&udph)
	udph.SetPrev(&iph)
	udph.SetNext(&inet.Raw{Data: payload})
	udpb, err := udph.Marshal()
	if err != nil {
		return nil, err
	}
	// deserialize the stream to get the computed checksum, to use for the IP ID
	tmp, err := inet.NewUDP(udpb)
	if err != nil {
		return nil, err
	}
	iph.ID = int(tmp.Csum)
	return iph.Marshal()
}

type pkt struct {
	Data []byte
	Port int
}

// Packets returns a channel of packets that will be sent as probes
func (d UDPv4) packets(src, dst net.IP) <-chan pkt {
	numPackets := int(d.NumPaths) * int(d.MaxTTL-d.MinTTL)
	ret := make(chan pkt, numPackets)

	go func() {
		var (
			srcPort, dstPort, basePort uint16
		)
		if d.UseSrcPort {
			basePort = d.SrcPort
		} else {
			basePort = d.DstPort
		}
		for ttl := d.MinTTL; ttl <= d.MaxTTL; ttl++ {
			for port := basePort; port < basePort+d.NumPaths; port++ {
				if d.UseSrcPort {
					srcPort = port
					dstPort = d.DstPort
				} else {
					srcPort = d.SrcPort
					dstPort = port
				}
				packet, err := d.packet(ttl, src, dst, srcPort, dstPort)
				if err != nil {
					log.Printf("Warning: cannot generate packet for ttl=%d srcport=%d dstport=%d: %v",
						ttl, srcPort, dstPort, err,
					)
				} else {
					ret <- pkt{Data: packet, Port: int(dstPort)}
				}
			}
		}
		close(ret)
	}()
	return ret
}

// SendReceive sends all the packets to the target address, respecting the configured
// inter-packet delay
func (d UDPv4) SendReceive() ([]probes.Probe, []probes.ProbeResponse, error) {
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

	numPackets := int(d.NumPaths) * int(d.MaxTTL-d.MinTTL)

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
	conn, err := net.Dial("udp4", net.JoinHostPort(d.Target.String(), "0"))
	if err != nil {
		return nil, nil, err
	}
	localAddr := *(conn.LocalAddr()).(*net.UDPAddr)
	conn.Close()
	sent := make([]probes.Probe, 0, numPackets)
	for p := range d.packets(localAddr.IP, d.Target) {
		daddr := syscall.SockaddrInet4{
			Addr: daddrBytes,
			Port: p.Port,
		}
		if err = syscall.Sendto(fd, p.Data, 0, &daddr); err != nil {
			return nil, nil, err
		}
		sent = append(sent, &ProbeUDPv4{Data: p.Data, LocalAddr: localAddr.IP, Timestamp: time.Now()})
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
			packets = append(packets, &ProbeResponseUDPv4{
				Data:      data[:n],
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
		if err := spu.Validate(); err != nil {
			log.Printf("Invalid probe: %v", err)
			continue
		}
		sentIP := spu.IP()
		sentUDP := spu.UDP()
		probe := results.Probe{
			Sent: results.Packet{
				Timestamp: spu.Timestamp,
				IP: results.IP{
					SrcIP: spu.LocalAddr,
					DstIP: sentIP.Dst,
					TTL:   uint8(sentIP.TTL),
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
			rpu := rp.(*ProbeResponseUDPv4)
			if err := rpu.Validate(); err != nil {
				log.Printf("Invalid probe response: %v", err)
				continue
			}
			if !rpu.Matches(spu) {
				continue
			}

			// the two packets belong to the same flow. If the checksum
			// differ there's a NAT
			NATID := rpu.InnerUDP().Csum - sentUDP.Csum
			// TODO this works when the source port is fixed. Allow for variable
			//      source port too
			flowhash, err := computeFlowhash(rpu)
			if err != nil {
				log.Print(err)
				continue
			}
			description := "Unknown"
			if rpu.ICMP().Type == inet.ICMPDestUnreachable && rpu.ICMP().Code == 3 {
				description = "Destination port unreachable"
			} else if rpu.ICMP().Type == inet.ICMPTimeExceeded && rpu.ICMP().Code == 0 {
				description = "TTL expired in transit"
			}
			// This is our packet, let's fill the probe data up
			probe.Flowhash = flowhash
			probe.IsLast = bytes.Equal(rpu.Addr.To4(), d.Target.To4())
			probe.Name = rpu.Addr.String() // TODO compute this field
			probe.RttUsec = uint64(rpu.Timestamp.Sub(spu.Timestamp)) / 1000
			probe.NATID = NATID
			probe.ZeroTTLForwardingBug = (rpu.InnerIP().TTL == 0)
			probe.Received = &results.Packet{
				Timestamp: rpu.Timestamp,
				ICMP: results.ICMP{
					Type:        uint8(rpu.ICMP().Type),
					Code:        uint8(rpu.ICMP().Code),
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
func (d UDPv4) Traceroute() (*results.Results, error) {
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
