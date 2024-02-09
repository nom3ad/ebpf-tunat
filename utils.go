package main

import (
	"encoding/binary"
	"log"
	"net"
	"net/netip"
	"unsafe"

	"github.com/pkg/errors"
)

var nativeEndian binary.ByteOrder

func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		panic("Could not determine native entireness.")
	}
}

func GetHostEndian() binary.ByteOrder {
	return nativeEndian
}

func ParseIP4HostAddr(addr string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		ips, err := net.LookupIP(addr)
		if err != nil {
			return ip, errors.Wrap(err, "failed to resolve to ip4 address")
		}
		log.Printf("Resolved %s to %v", addr, ips)
		found := false
		for _, _ip := range ips {
			if _ip.To4() != nil {
				ip = netip.AddrFrom4([4]byte(_ip.To4()))
				found = true
				break
			}
		}
		if !found {
			return ip, errors.New("no IP4 address found")
		}
	}
	if !ip.IsValid() || !ip.Is4() || ip.IsUnspecified() {
		return ip, errors.New("invalid IP4 Host address")
	}
	return ip, nil
}
