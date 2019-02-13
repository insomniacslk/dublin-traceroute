package net

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestICMPMarshal(t *testing.T) {
	want := []byte{
		11, // ICMP time exceeded
		0,
		0xf4, 0xff, // checksum
		0, 0, 0, 0, // unused
	}
	icmp := ICMP{
		Type: ICMPTimeExceeded,
		Code: 0,
	}
	b, err := icmp.Marshal()
	require.NoError(t, err)
	require.Equal(t, want, b)
}

func TestICMPUnmarshal(t *testing.T) {
	b := []byte{
		11, // ICMP time exceeded
		0,
		0xf4, 0xff, // checksum
		0, 0, 0, 0, // unused
		// payload
		0xde, 0xad, 0xc0, 0xde,
	}
	var i ICMP
	err := i.Unmarshal(b)
	require.NoError(t, err)
	assert.Equal(t, ICMPTimeExceeded, i.Type)
	assert.Equal(t, ICMPCode(0), i.Code)
}
