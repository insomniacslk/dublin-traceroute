package probev6

import (
	"errors"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ProbeUDPv6 represents a sent probe packet with its metadata
type ProbeUDPv6 struct {
	Packet gopacket.Packet
	// time the packet is set at
	Timestamp time.Time
	// local address of the packet sender
	LocalAddr net.IP
}

func (p ProbeUDPv6) Validate() error {
	if len(p.Packet.Layers()) < 2 {
		return errors.New("Invalid Probe: less than 2 layers found")
	}
	if _, ok := p.Packet.Layers()[0].(*layers.IPv4); !ok {
		return errors.New("Invalid ProbeResponse: first layer is not IPv4")
	}
	if _, ok := p.Packet.Layers()[1].(*layers.UDP); !ok {
		return errors.New("Invalid ProbeResponse: second layer is not UDP")
	}
	return nil
}

// ProbeResponseUDPv6 represents a received probe response with its metadata
type ProbeResponseUDPv6 struct {
	Packet gopacket.Packet
	// time the packet is received at
	Timestamp time.Time
	// sender IP address
	Addr        net.IP
	innerPacket *gopacket.Packet
}

// Validate verifies that the probe response has the expected structure, and
// returns an error if not
func (pr ProbeResponseUDPv6) Validate() error {
	// TODO implement response validation
	return nil
}
