package main

import (
	"errors"
	"fmt"

	inet "github.com/insomniacslk/dublin-traceroute/go/dublintraceroute/net"
)

// ErrNoMatch signals a packet not matching the desired criteria.
var ErrNoMatch = errors.New("packet not matching")

// forgeReplyv4 forges a reply for the provided input, assuming that this
// is UDP over IPv4.
// If the packet doesn't match in the configuration, an ErrNoMatch is
// returned.
func forgeReplyv4(cfg *Config, payload []byte) (*inet.IPv4, error) {
	p, err := inet.NewIPv4(payload)
	if err != nil {
		return nil, err
	}
	nextLayer := p.Next()
	if nextLayer == nil {
		return nil, errors.New("invalid nil next layer")
	}
	pu, ok := nextLayer.(*inet.UDP)
	if !ok {
		return nil, fmt.Errorf("invalid next layer, got %T, want *inet.UDP", nextLayer)
	}
	log.Debugf("Matching packet: %+v >> %+v", p, p.Next())
	var match *Probe
	for _, c := range *cfg {
		if p.Dst.Equal(c.Dst) &&
			(c.Src == nil || p.Src.Equal(*c.Src)) &&
			int(c.TTL) == p.TTL &&
			c.DstPort == pu.Dst &&
			(c.SrcPort == nil || *c.SrcPort == pu.Src) {
			match = &c
			break
		}
	}
	if match == nil {
		return nil, ErrNoMatch
	}
	log.Debugf("Found match %+v", *match)
	dst := p.Src
	if match.Reply.Dst != nil {
		dst = *match.Reply.Dst
	}
	ip := inet.IPv4{
		Version:   inet.Version4,
		HeaderLen: 5,
		TotalLen:  inet.MinIPv4HeaderLen + inet.UDPHeaderLen + len(payload),
		TTL:       64, // dummy value, good enough for a reply
		Proto:     inet.ProtoICMP,
		Src:       match.Reply.Src,
		Dst:       dst,
	}
	icmp := inet.ICMP{
		Type: inet.ICMPType(match.Reply.IcmpType),
		Code: inet.ICMPCode(match.Reply.IcmpCode),
	}
	rawBytes := payload
	if match.Reply.Payload != nil {
		rawBytes = match.Reply.Payload
	} else {
		rawBytes = payload
	}
	raw, err := inet.NewRaw(rawBytes)
	if err != nil {
		return nil, err
	}
	ip.SetNext(&icmp)
	icmp.SetNext(raw)
	return &ip, nil
}
