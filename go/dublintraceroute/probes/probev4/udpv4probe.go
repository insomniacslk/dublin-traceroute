package probev4

import (
	"bytes"
	"errors"
	"net"
	"time"

	inet "github.com/insomniacslk/dublin-traceroute/go/dublintraceroute/net"
)

// ProbeUDPv4 represents a sent probe packet with its metadata
type ProbeUDPv4 struct {
	Data []byte
	ip   *inet.IPv4
	// time the packet is sent at
	Timestamp time.Time
	// local address of the packet sender
	LocalAddr net.IP
}

// Validate verifies that the probe has the expected structure, and returns an error if not
func (p *ProbeUDPv4) Validate() error {
	if p.ip == nil {
		// decode packet
		ip, err := inet.NewIPv4(p.Data)
		if err != nil {
			return err
		}
		p.ip = ip
	}
	l := p.ip.Next()
	if l == nil {
		return errors.New("IP layer has no payload")
	}
	if _, ok := l.(*inet.UDP); !ok {
		return errors.New("no UDP layer")
	}
	return nil
}

// IP returns the IP layer of the probe. If not decoded yet, will return nil.
func (p ProbeUDPv4) IP() *inet.IPv4 {
	return p.ip
}

// UDP returns the UDP layer of the probe. If not decoded yet, will return nil.
func (p ProbeUDPv4) UDP() *inet.UDP {
	if p.ip == nil {
		return nil
	}
	u, ok := p.ip.Next().(*inet.UDP)
	if !ok {
		return nil
	}
	return u
}

// ProbeResponseUDPv4 represents a received probe response with its metadata
type ProbeResponseUDPv4 struct {
	Data    []byte
	icmp    *inet.ICMP
	innerIP *inet.IPv4
	// time the packet is received at
	Timestamp time.Time
	// sender IP address
	Addr net.IP
}

// Validate verifies that the probe response has the expected structure, and returns an error if not
func (pr *ProbeResponseUDPv4) Validate() error {
	if pr.icmp == nil {
		// decode packet
		icmp, err := inet.NewICMP(pr.Data)
		if err != nil {
			return err
		}
		pr.icmp = icmp
	}
	var l inet.Layer
	if l = pr.icmp.Next(); l == nil {
		return errors.New("ICMP layer has no payload")
	}
	raw, ok := l.(*inet.Raw)
	if !ok {
		return errors.New("no payload in ICMP layer")
	}
	var ip inet.IPv4
	ip.IPinICMP = true
	if err := ip.Unmarshal(raw.Data); err != nil {
		return err
	}
	pr.innerIP = &ip
	l = pr.innerIP.Next()
	if l == nil {
		return errors.New("inner IP layer has no payload")
	}
	if _, ok := l.(*inet.UDP); !ok {
		return errors.New("inner IP layer has no UDP layer")
	}
	return nil
}

// ICMP returns the ICMP layer of the probe response. If not decoded yet, will return nil.
func (pr ProbeResponseUDPv4) ICMP() *inet.ICMP {
	return pr.icmp
}

// InnerIP returns the inner IP layer of the probe response. If not decoded yet, will return nil.
func (pr ProbeResponseUDPv4) InnerIP() *inet.IPv4 {
	return pr.innerIP
}

// InnerUDP returns the UDP layer of the probe. If not decoded yet, will return nil.
func (pr ProbeResponseUDPv4) InnerUDP() *inet.UDP {
	if pr.innerIP == nil {
		return nil
	}
	u, ok := pr.innerIP.Next().(*inet.UDP)
	if !ok {
		return nil
	}
	return u
}

// Matches returns true if this probe response matches a given probe. Both
// probes must have been already validated with Validate, this function may
// panic otherwise.
func (pr ProbeResponseUDPv4) Matches(p *ProbeUDPv4) bool {
	if p == nil {
		return false
	}
	if pr.icmp.Type != inet.ICMPTimeExceeded && !(pr.icmp.Type == inet.ICMPDestUnreachable && pr.icmp.Code == 3) {
		// we want time-exceeded or port-unreachable
		return false
	}
	if !bytes.Equal(pr.InnerIP().Dst.To4(), p.IP().Dst.To4()) {
		return false
	}
	if p.UDP().Src != pr.InnerUDP().Src || p.UDP().Dst != pr.InnerUDP().Dst {
		// source and destination ports do not match
		return false
	}
	if pr.InnerIP().ID != p.IP().ID {
		// the two packets do not belong to the same flow
		return false
	}
	return true
}
