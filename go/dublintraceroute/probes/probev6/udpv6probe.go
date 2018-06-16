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
	if _, ok := p.Packet.Layers()[0].(*layers.IPv6); !ok {
		return errors.New("Invalid ProbeResponse: first layer is not IPv6")
	}
	if _, ok := p.Packet.Layers()[1].(*layers.UDP); !ok {
		return errors.New("Invalid ProbeResponse: second layer is not UDP")
	}
	return nil
}

// IPv6Layer returns the IPv6 layer of the probe, expecting it to be the first
// encountered layer
func (p *ProbeUDPv6) IPv6Layer() (*layers.IPv6, error) {
    if err := p.Validate(); err != nil {
        return nil, err
    }
    return p.Packet.Layers()[0].(*layers.IPv6), nil
}

// UDPLayer returns the UDP layer of the probe, expecting it to be the second
// encountered layer
func (p *ProbeUDPv6) UDPLayer() (*layers.UDP, error) {
    if err := p.Validate(); err != nil {
        return nil, err
    }
    return p.Packet.Layers()[1].(*layers.UDP), nil
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
func (pr *ProbeResponseUDPv6) Validate() error {
    if len(pr.Packet.Layers()) < 2 {
        return errors.New("Invalid ProbeResponse: less than 2 layers found")
    }
    if _, ok := pr.Packet.Layers()[0].(*layers.ICMPv6); !ok {
        return errors.New("Invalid ProbeResponse: first layer is not ICMPv6")
    }
    if pr.innerPacket == nil {
        icmp := pr.Packet.Layers()[0].(*layers.ICMPv6)
        innerPacket := gopacket.NewPacket(icmp.LayerPayload(), layers.LayerTypeIPv6, gopacket.Default)
        if innerPacket == nil {
            return errors.New("Invalid ProbeResponse: no inner packet found")
        }
        pr.innerPacket = &innerPacket
    }
    if len((*pr.innerPacket).Layers()) < 2 {
        return errors.New("Invalid ProbeResponse: less than 2 layers in the inner packet")
    }
    if _, ok := (*pr.innerPacket).Layers()[0].(*layers.IPv6); !ok {
        return errors.New("Invalid ProbeResponse: first inner layer is not IPv6")
    }
    if _, ok := (*pr.innerPacket).Layers()[1].(*layers.UDP); !ok {
        return errors.New("Invalid ProbeResponse: second inner layer is not UDP")
    }
    return nil
}

// ICMPv6Layer returns the ICMPv6 layer of the probe, expecting it to be the
// first encountered layer
func (pr *ProbeResponseUDPv6) ICMPv6Layer() (*layers.ICMPv6, error) {
    if err := pr.Validate(); err != nil {
        return nil, err
    }
    return pr.Packet.Layers()[0].(*layers.ICMPv6), nil
}

// InnerIPv6Layer returns the IP layer of the inner packet of the probe,
// expecting it to be the first encountered layer in the inner packet
func (pr *ProbeResponseUDPv6) InnerIPv6Layer() (*layers.IPv6, error) {
    if err := pr.Validate(); err != nil {
        return nil, err
    }
    return (*pr.innerPacket).Layers()[0].(*layers.IPv6), nil
}

// InnerUDPLayer returns the UDP layer of the inner packet of the probe,
// expecting it to be the second encountered layer in the inner packet
func (pr *ProbeResponseUDPv6) InnerUDPLayer() (*layers.UDP, error) {
    if err := pr.Validate(); err != nil {
        return nil, err
    }
    return (*pr.innerPacket).Layers()[1].(*layers.UDP), nil
}
