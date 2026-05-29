/* SPDX-License-Identifier: BSD-2-Clause */

package net

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUDPMarshalBinary(t *testing.T) {
	want := []byte{
		0x12, 0x34, // src port
		0x23, 0x45, // dst port
		0x00, 0x08, // len
		0x00, 0x00, // csum
	}
	udp := UDP{
		Src:  0x1234,
		Dst:  0x2345,
		Len:  8,
		Csum: 0,
	}
	b, err := udp.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, want, b)
}

func TestUDPMarshalBinaryWithPseudoHeader(t *testing.T) {
	want := []byte{
		0x12, 0x34, // src port
		0x23, 0x45, // dst port
		0x00, 0x08, // len
		0xef, 0xab, // csum
	}
	// IPv4 pseudoheader for src 192.168.10.1, dst 8.8.8.8, proto UDP, UDP
	// length 8: src(4) | dst(4) | zero(1) | proto(1) | length(2). The checksum
	// is now computed from UDP.PseudoHeader rather than from a chained IPv4
	// layer.
	pseudoHeader := []byte{
		192, 168, 10, 1,
		8, 8, 8, 8,
		0, byte(ProtoUDP),
		0x00, 0x08,
	}
	udp := UDP{
		Src:          0x1234,
		Dst:          0x2345,
		Len:          8,
		Csum:         0,
		PseudoHeader: pseudoHeader,
	}
	b, err := udp.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, want, b)
}

func TestUDPUnmarshalBinary(t *testing.T) {
	b := []byte{
		0x12, 0x34, // src port
		0x23, 0x45, // dst port
		0x00, 0x08, // len
		0xff, 0x35, // csum
	}
	var u UDP
	err := u.UnmarshalBinary(b)
	require.NoError(t, err)
	assert.Equal(t, uint16(0x1234), u.Src)
	assert.Equal(t, uint16(0x2345), u.Dst)
	assert.Equal(t, uint16(8), u.Len)
	assert.Equal(t, uint16(0xff35), u.Csum)
}
