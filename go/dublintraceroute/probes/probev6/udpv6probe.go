package probev6

import (
	"errors"
	"net"
	"time"

	inet "github.com/insomniacslk/dublin-traceroute/go/dublintraceroute/net"
)

// ProbeUDPv6 represents a sent probe packet with its metadata
type ProbeUDPv6 struct {
	Data       []byte
	HopLimit   int
	PayloadLen int
	udp        *inet.UDP
	// time the packet is set at
	Timestamp time.Time
	// local address of the packet sender
	LocalAddr, RemoteAddr net.IP
}

// Validate verifies that the probe has the expected structure, and returns an error if not
func (p *ProbeUDPv6) Validate() error {
	if p.udp == nil {
		// decode packet
		udp, err := inet.NewUDP(p.Data)
		if err != nil {
			return err
		}
		p.udp = udp
	}
	return nil
}

// UDP returns the UDP layer of the probe. If not decoded yet, will return nil.
func (p ProbeUDPv6) UDP() *inet.UDP {
	return p.udp
}

// ProbeResponseUDPv6 represents a received probe response with its metadata
type ProbeResponseUDPv6 struct {
	Data    []byte
	icmp    *inet.ICMPv6
	innerIP *inet.IPv6
	// time the packet is received at
	Timestamp time.Time
	// sender IP address
	Addr net.IP
}

// Validate verifies that the probe response has the expected structure, and
// returns an error if not
func (pr *ProbeResponseUDPv6) Validate() error {
	if pr.icmp == nil {
		// decode packet
		icmp, err := inet.NewICMPv6(pr.Data)
		if err != nil {
			return err
		}
		pr.icmp = icmp
	}
	var l inet.Layer
	if l = pr.icmp.Next(); l == nil {
		return errors.New("ICMPv6 layer has no payload")
	}
	raw, ok := l.(*inet.Raw)
	if !ok {
		return errors.New("no payload in ICMPv6 layer")
	}
	var ip inet.IPv6
	ip.IPinICMP = true
	if err := ip.Unmarshal(raw.Data); err != nil {
		return err
	}
	pr.innerIP = &ip
	l = pr.innerIP.Next()
	if l == nil {
		return errors.New("inner IPv6 layer has no payload")
	}
	if _, ok := l.(*inet.UDP); !ok {
		return errors.New("inner IPv6 layer has no UDP layer")
	}
	return nil
}

// ICMPv6 returns the ICMPv6 layer of the probe, expecting it to be the
// first encountered layer
func (pr *ProbeResponseUDPv6) ICMPv6() *inet.ICMPv6 {
	return pr.icmp
}

// InnerIP returns the IP layer of the inner packet of the probe,
// expecting it to be the first encountered layer in the inner packet
func (pr *ProbeResponseUDPv6) InnerIP() *inet.IPv6 {
	return pr.innerIP
}

// InnerUDP returns the UDP layer of the inner packet of the probe,
// expecting it to be the second encountered layer in the inner packet
func (pr *ProbeResponseUDPv6) InnerUDP() *inet.UDP {
	if pr.innerIP == nil {
		return nil
	}
	u, ok := pr.innerIP.Next().(*inet.UDP)
	if !ok {
		return nil
	}
	return u
}
