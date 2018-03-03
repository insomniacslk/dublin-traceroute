package probes

import (
	"errors"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Probe represents a sent probe packet with its metadata
type Probe struct {
	Packet gopacket.Packet
	// time when the packet is sent
	Timestamp time.Time
	// local address of the packet sender
	LocalAddr net.IP
}

// Validate verifies that the probe has the expected structure, and returns an error if not
func (p Probe) Validate() error {
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

// IPv4Layer returns the IPv4 layer of the probe, expecting it to be the first encountered layer
func (p Probe) IPv4Layer() (*layers.IPv4, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p.Packet.Layers()[0].(*layers.IPv4), nil
}

// UDPLayer returns the UDP layer of the probe, expecting it to be the second encountered layer
func (p Probe) UDPLayer() (*layers.UDP, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p.Packet.Layers()[1].(*layers.UDP), nil
}

// ProbeResponse represents a received probe packet with its metadata
type ProbeResponse struct {
	Packet gopacket.Packet
	// time when the packet is received
	Timestamp time.Time
	// sender IP address
	Addr        net.IP
	innerPacket *gopacket.Packet
}

// Validate verifies that the probe response has the expected structure, and returns an error if not
func (pr *ProbeResponse) Validate() error {
	if len(pr.Packet.Layers()) < 2 {
		return errors.New("Invalid ProbeResponse: less than 2 layers found")
	}
	if _, ok := pr.Packet.Layers()[0].(*layers.ICMPv4); !ok {
		return errors.New("Invalid ProbeResponse: first layer is not ICMPv4")
	}
	if pr.innerPacket == nil {
		icmp := pr.Packet.Layers()[0].(*layers.ICMPv4)
		innerPacket := gopacket.NewPacket(icmp.LayerPayload(), layers.LayerTypeIPv4, gopacket.Default)
		if innerPacket == nil {
			return errors.New("Invalid ProbeResponse: no inner packet found")
		}
		pr.innerPacket = &innerPacket
	}
	if len((*pr.innerPacket).Layers()) < 2 {
		return errors.New("Invalid ProbeResponse: less than 2 layers in the inner packet")
	}
	if _, ok := (*pr.innerPacket).Layers()[0].(*layers.IPv4); !ok {
		return errors.New("Invalid ProbeResponse: first inner layer is not IPv4")
	}
	if _, ok := (*pr.innerPacket).Layers()[1].(*layers.UDP); !ok {
		return errors.New("Invalid ProbeResponse: second inner layer is not UDP")
	}
	return nil
}

// ICMPv4Layer returns the UDP layer of the probe, expecting it to be the
// first encountered layer
func (pr ProbeResponse) ICMPv4Layer() (*layers.ICMPv4, error) {
	if err := pr.Validate(); err != nil {
		return nil, err
	}
	return pr.Packet.Layers()[0].(*layers.ICMPv4), nil
}

// InnerIPv4Layer returns the IP layer of the inner packet of the probe,
// expecting it to be the first encountered layer in the inner packet
func (pr ProbeResponse) InnerIPv4Layer() (*layers.IPv4, error) {
	if err := pr.Validate(); err != nil {
		return nil, err
	}
	return (*pr.innerPacket).Layers()[0].(*layers.IPv4), nil
}

// InnerUDPLayer returns the UDP layer of the inner packet of the probe,
// expecting it to be the second encountered layer in the inner packet
func (pr ProbeResponse) InnerUDPLayer() (*layers.UDP, error) {
	if err := pr.Validate(); err != nil {
		return nil, err
	}
	return (*pr.innerPacket).Layers()[1].(*layers.UDP), nil
}
