package probev6

import (
	"os"
	"encoding/binary"
	"errors"
	"net"
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
		for dstPort := d.DstPort; dstPort <= d.DstPort+d.NumPaths; dstPort++ {
			udp := layers.UDP{
				SrcPort: layers.UDPPort(d.SrcPort),
				DstPort: layers.UDPPort(dstPort),
			}
			udp.SetNetworkLayerForChecksum(&ip)
			ip.Length += 8 // UDP header size

			// forge payload
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
	conn, err := icmp.ListenPacket("ip6:icmp", "::")
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
	// TODO implement Match
	return results.Results{}
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
