package net

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// TODO implement multi-part ICMP, https://tools.ietf.org/html/rfc4884
//      and MPLS extensions, https://tools.ietf.org/html/rfc4950

// ICMP is an ICMPv4 packet
type ICMP struct {
	Type     ICMPType
	Code     ICMPCode
	Checksum uint16
	// See RFC792, RFC4884, RFC4950.
	Unused uint32
	next   Layer
}

// ICMPHeaderLen is the ICMPv4 header length
var ICMPHeaderLen = 8

// ICMPType defines ICMP types
type ICMPType uint8

// ICMP types
var (
	ICMPEchoReply                     ICMPType
	ICMPDestUnreachable               ICMPType = 3
	ICMPSourceQuench                  ICMPType = 4
	ICMPRedirect                      ICMPType = 5
	ICMPAlternateHostAddr             ICMPType = 6
	ICMPEchoRequest                   ICMPType = 8
	ICMPRouterAdv                     ICMPType = 9
	ICMPRouterSol                     ICMPType = 10
	ICMPTimeExceeded                  ICMPType = 11
	ICMPParamProblem                  ICMPType = 12
	ICMPTimestampReq                  ICMPType = 13
	ICMPTimestampReply                ICMPType = 14
	ICMPAddrMaskReq                   ICMPType = 17
	ICMPAddrMaskReply                 ICMPType = 18
	ICMPTraceroute                    ICMPType = 30
	ICMPConversionErr                 ICMPType = 31
	ICMPMobileHostRedirect            ICMPType = 32
	ICMPIPv6WhereAreYou               ICMPType = 33
	ICMPIPv6IAmHere                   ICMPType = 34
	ICMPMobileRegistrationReq         ICMPType = 35
	ICMPMobileRegistrationReply       ICMPType = 36
	ICMPDomainNameReq                 ICMPType = 37
	ICMPDomainNameReply               ICMPType = 38
	ICMPSkipAlgoDiscoveryProtocol     ICMPType = 39
	ICMPPhoturis                      ICMPType = 40
	ICMPExperimentalMobilityProtocols ICMPType = 41
)

// ICMPCode defines ICMP types
type ICMPCode uint8

// TODO map ICMP codes, see https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes

// NewICMP constructs a new ICMP header from a sequence of bytes
func NewICMP(b []byte) (*ICMP, error) {
	var i ICMP
	if err := i.Unmarshal(b); err != nil {
		return nil, err
	}
	return &i, nil
}

// Next returns the next layer
func (i ICMP) Next() Layer {
	return i.next
}

// SetNext sets the next layer
func (i *ICMP) SetNext(l Layer) {
	i.next = l
}

// Marshal serializes the layer
func (i ICMP) Marshal() ([]byte, error) {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, i.Type)
	binary.Write(&b, binary.BigEndian, i.Code)
	var (
		payload []byte
		err     error
	)
	if i.next != nil {
		payload, err = i.next.Marshal()
		if err != nil {
			return nil, err
		}
	}
	// compute checksum
	i.Checksum = 0
	var bc bytes.Buffer
	binary.Write(&bc, binary.BigEndian, i.Type)
	binary.Write(&bc, binary.BigEndian, i.Code)
	binary.Write(&bc, binary.BigEndian, payload)
	i.Checksum = checksum(bc.Bytes())
	binary.Write(&b, binary.BigEndian, i.Checksum)
	// TODO implement multipart, RFC4884, RFC4950
	binary.Write(&b, binary.BigEndian, i.Unused)
	return b.Bytes(), nil
}

// Unmarshal deserializes the layer
func (i *ICMP) Unmarshal(b []byte) error {
	if len(b) < ICMPHeaderLen {
		return errors.New("short icmp header")
	}
	i.Type = ICMPType(b[0])
	i.Code = ICMPCode(b[1])
	i.Checksum = binary.BigEndian.Uint16(b[2:4])
	// TODO parse ICMP multi-part
	payload := b[ICMPHeaderLen:]
	if len(payload) > 0 {
		i.next = &Raw{Data: payload}
	}
	return nil
}
