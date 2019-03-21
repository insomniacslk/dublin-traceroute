package net

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// ICMPv6 is an ICMPv6 packet
type ICMPv6 struct {
	Type     ICMPType
	Code     ICMPCode
	Checksum uint16
	// See RFC792, RFC4884, RFC4950.
	Unused uint32
	next   Layer
}

// ICMPv6HeaderLen is the ICMPv6 header length
var ICMPv6HeaderLen = 8

// ICMPv6Type defines ICMP types
type ICMPv6Type uint8

// ICMP types
var (
	ICMPv6DestUnreachable                              ICMPv6Type = 1
	ICMPv6PacketTooBig                                 ICMPv6Type = 2
	ICMPv6TimeExceeded                                 ICMPv6Type = 3
	ICMPv6ParameterProblem                             ICMPv6Type = 4
	ICMPv6EchoRequest                                  ICMPv6Type = 128
	ICMPv6EchoReply                                    ICMPv6Type = 129
	ICMPv6GroupMembershipQuery                         ICMPv6Type = 130
	ICMPv6GroupMembershipReport                        ICMPv6Type = 131
	ICMPv6GroupMembershipReduction                     ICMPv6Type = 132
	ICMPv6RouterSolicitation                           ICMPv6Type = 133
	ICMPv6RouterAdvertisement                          ICMPv6Type = 134
	ICMPv6NeighborAdvertisement                        ICMPv6Type = 135
	ICMPv6NeighborSolicitation                         ICMPv6Type = 136
	ICMPv6Redirect                                     ICMPv6Type = 137
	ICMPv6RouterRenumbering                            ICMPv6Type = 138
	ICMPv6ICMPNodeInformationQuery                     ICMPv6Type = 139
	ICMPv6ICMPNodeInformationResponse                  ICMPv6Type = 140
	ICMPv6InverseNeighborDiscoverySolicitationMessage  ICMPv6Type = 141
	ICMPv6InverseNeighborDiscoveryAdvertisementMessage ICMPv6Type = 142
	ICMPv6MLDv2MulticastListenerReport                 ICMPv6Type = 143
	ICMPv6HomeAgentAddressDiscoveryRequestMessage      ICMPv6Type = 144
	ICMPv6HomeAgentAddressDiscoveryReplyMessage        ICMPv6Type = 145
	ICMPv6MobilePrefixSolicitation                     ICMPv6Type = 146
	ICMPv6MobilePrefixAdvertisement                    ICMPv6Type = 147
	ICMPv6CertificationPathSolicitation                ICMPv6Type = 148
	ICMPv6CertificationPathAdvertisement               ICMPv6Type = 149
	ICMPv6ExperimentalMobilityProtocols                ICMPv6Type = 150
	ICMPv6MulticastRouterAdvertisement                 ICMPv6Type = 151
	ICMPv6MulticastRouterSolicitation                  ICMPv6Type = 152
	ICMPv6MulticastRouterTermination                   ICMPv6Type = 153
	ICMPv6FMIPv6Messages                               ICMPv6Type = 154
)

// ICMPv6Code defines ICMP types
type ICMPv6Code uint8

// TODO map ICMP codes, see https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes

// NewICMPv6 constructs a new ICMPv6 header from a sequence of bytes
func NewICMPv6(b []byte) (*ICMPv6, error) {
	var i ICMPv6
	if err := i.Unmarshal(b); err != nil {
		return nil, err
	}
	return &i, nil
}

// Next returns the next layer
func (i ICMPv6) Next() Layer {
	return i.next
}

// SetNext sets the next layer
func (i *ICMPv6) SetNext(l Layer) {
	i.next = l
}

// Marshal serializes the layer
func (i ICMPv6) Marshal() ([]byte, error) {
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
	binary.Write(&b, binary.BigEndian, i.Unused)
	return b.Bytes(), nil
}

// Unmarshal deserializes the layer
func (i *ICMPv6) Unmarshal(b []byte) error {
	if len(b) < ICMPv6HeaderLen {
		return errors.New("short icmpv6 header")
	}
	i.Type = ICMPType(b[0])
	i.Code = ICMPCode(b[1])
	i.Checksum = binary.BigEndian.Uint16(b[2:4])
	// TODO parse ICMP extensions
	payload := b[ICMPv6HeaderLen:]
	if len(payload) > 0 {
		i.next = &Raw{Data: payload}
	}
	return nil
}
