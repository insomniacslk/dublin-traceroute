package dublintraceroute

import (
	"encoding/binary"
	"errors"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/insomniacslk/dublin-traceroute/go/dublintraceroute"
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
			payload := []byte{'N', 'S', 'M', 'N', 'C', 0x00, 0x00}
			ip.Length += uint16(len(payload))
			binary.BigEndian.PutUint16(payload[len(payload)-2:], dstPort+uint16(hopLimit))

			gopacket.SerializeLayers(buf, opts, &ip, &udp, gopacket.Payload(payload))
			p := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv6, gopacket.Lazy)
			packets = append(packets, p)
		}
	}
	return packets
}

func (d UDPv6) SendPackets(packets []gopacket.Packet) error {
	for _, p := range packets {
		log.Print(p)
	}
	return nil
}

func (d UDPv6) Listen() ([]gopacket.Packet, error) {
	return nil, nil
}

func (d UDPv6) Match(sent, received []gopacket.Packet) dublintraceroute.Results {
	return dublintraceroute.Results{}
}

// Traceroute sends the probes and returns a Results structure or an error
func (d UDPv6) Traceroute() (*dublintraceroute.Results, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	packets := d.ForgePackets()
	if err := d.SendPackets(packets); err != nil {
		return nil, err
	}
	received, err := d.Listen()
	if err != nil {
		return nil, err
	}
	results := d.Match(packets, received)

	return &results, nil
}
