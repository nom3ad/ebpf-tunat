package main

import (
	"fmt"
	"net/netip"
	"strings"
)

type MapEntry struct {
	ServiceIP netip.Addr
	NodeIP    netip.Addr
	PodIP     netip.Addr
}

func (e MapEntry) String() string {
	return fmt.Sprintf("%s/%s=%s", e.ServiceIP, e.NodeIP, e.PodIP)
}

func parseMapString(mapString string) ([]MapEntry, error) {
	var entries []MapEntry
	for _, s := range strings.Split(mapString, ",") {
		parts := strings.SplitN(s, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid entry: %s", s)
		}
		sip, err := ParseIP4HostAddr(parts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid Service address: %s | %v", parts[0], err)
		}
		parts = strings.SplitN(parts[1], "/", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid entry: %s", s)
		}
		nip, err := ParseIP4HostAddr(parts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid Node address: %s | %v", parts[0], err)
		}
		pip, err := ParseIP4HostAddr(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid Pod address: %s | %v", parts[1], err)
		}
		entries = append(entries, MapEntry{
			ServiceIP: sip,
			NodeIP:    nip,
			PodIP:     pip,
		})
	}
	return entries, nil
}

// var sourceIP netip.Addr
// if *sourceIPString != "" {
// 	sourceIP, err = ParseIP4HostAddr(*sourceIPString)
// 	if err != nil {
// 		return nil, fmt.Errorf("invalid source IP address: %s | %v", *sourceIPString, err)
// 	}
// }

// ebpfMgr, err := NewEBPFManager(*ifaceName, serviceRegistry, sourceIP)
// if err != nil {
// 	panic("Failed to create EBPF manager: " + err.Error())
// }
