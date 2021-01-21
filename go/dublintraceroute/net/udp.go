/* SPDX-License-Identifier: BSD-2-Clause */

package net

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// UDPHeaderLen is the UDP header length
var UDPHeaderLen = 8

// UDP is the UDP header
type UDP struct {
	Src  uint16
	Dst  uint16
	Len  uint16
	Csum uint16
	next Layer
	// UDP also needs the previous layer to compute the pseudoheader checksum
	prev Layer
}

// NewUDP constructs a new UDP header from a sequence of bytes.
func NewUDP(b []byte) (*UDP, error) {
	var h UDP
	if err := h.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return &h, nil
}

// Next returns the next layer
func (h UDP) Next() Layer {
	return h.next
}

// SetNext sets the next layer
func (h *UDP) SetNext(l Layer) {
	h.next = l
}

// SetPrev stores the previous layer to be used for checksum computation.
func (h *UDP) SetPrev(l Layer) {
	h.prev = l
}

func checksum(b []byte) uint16 {
	var sum uint32

	for ; len(b) >= 2; b = b[2:] {
		sum += uint32(b[0])<<8 | uint32(b[1])
	}
	if len(b) > 0 {
		sum += uint32(b[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	csum := ^uint16(sum)
	if csum == 0 {
		csum = 0xffff
	}
	return csum
}

type pseudoheader struct {
	src, dst    [4]byte
	zero, proto uint8
	ulen        uint16
}

// MarshalBinary serializes the layer
func (h UDP) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, h.Src)
	binary.Write(&buf, binary.BigEndian, h.Dst)
	var (
		payload []byte
		err     error
	)
	if next := h.Next(); next != nil {
		if payload, err = next.MarshalBinary(); err != nil {
			return nil, err
		}
	}
	if h.Len == 0 {
		h.Len = uint16(UDPHeaderLen + len(payload))
	}
	if h.Len < 8 || h.Len > 0xffff-20 {
		return nil, errors.New("invalid udp header len")
	}
	binary.Write(&buf, binary.BigEndian, h.Len)
	if h.Csum == 0 {
		prev := h.prev
		// TODO implement IPv6 too
		if iph, ok := prev.(*IPv4); ok {
			var b bytes.Buffer
			// pseudoheader
			p := pseudoheader{
				proto: uint8(iph.Proto),
				ulen:  h.Len,
			}
			if iph.Src != nil {
				copy(p.src[:], iph.Src.To4())
			}
			if iph.Dst != nil {
				copy(p.dst[:], iph.Dst.To4())
			}
			binary.Write(&b, binary.BigEndian, &p)
			// udp header
			binary.Write(&b, binary.BigEndian, h.Src)
			binary.Write(&b, binary.BigEndian, h.Dst)
			binary.Write(&b, binary.BigEndian, h.Len)
			// payload
			binary.Write(&b, binary.BigEndian, payload)

			h.Csum = checksum(b.Bytes())
		}
	}
	binary.Write(&buf, binary.BigEndian, h.Csum)
	ret := append(buf.Bytes(), payload...)
	return ret, nil
}

// UnmarshalBinary deserializes the raw bytes to an UDP header
func (h *UDP) UnmarshalBinary(b []byte) error {
	if len(b) < UDPHeaderLen {
		return errors.New("short udp header")
	}
	h.Src = binary.BigEndian.Uint16(b[:2])
	h.Dst = binary.BigEndian.Uint16(b[2:4])
	h.Len = binary.BigEndian.Uint16(b[4:6])
	h.Csum = binary.BigEndian.Uint16(b[6:8])
	return nil
}
