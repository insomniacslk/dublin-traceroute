package probev6

import (
	"net"
	"time"

	"github.com/google/gopacket"
)

// ProbeUDPv6 represents a sent probe packet with its metadata
type ProbeUDPv6 struct {
	Packet gopacket.Packet
	// time the packet is set at
	Timestamp time.Time
	// local address of the packet sender
	LocalAddr net.IP
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
