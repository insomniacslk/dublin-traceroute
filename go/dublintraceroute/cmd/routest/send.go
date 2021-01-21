/* SPDX-License-Identifier: BSD-2-Clause */

package main

import (
	"net"
	"syscall"

	inet "github.com/insomniacslk/dublin-traceroute/go/dublintraceroute/net"
	"golang.org/x/sys/unix"
)

// Send4 sends an IPv4 packet to its destination.
func Send4(ifname string, ip *inet.IPv4) error {
	data, err := ip.MarshalBinary()
	if err != nil {
		return err
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return err
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return err
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return err
	}
	if ifname != "" {
		if err := unix.BindToDevice(fd, ifname); err != nil {
			return err
		}
	}

	var daddrBytes [net.IPv4len]byte
	copy(daddrBytes[:], ip.Src.To4())
	daddr := syscall.SockaddrInet4{
		Addr: daddrBytes,
		Port: 33434,
	}
	return syscall.Sendto(fd, data, 0, &daddr)
}
