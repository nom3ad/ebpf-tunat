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

type ParsedMapString struct {
	ToAdd    []MapEntry
	ToRemove []MapEntry
}

func (e MapEntry) String() string {
	return fmt.Sprintf("%s/%s=%s", e.ServiceIP, e.NodeIP, e.PodIP)
}

// sip:nip/pip
// sip:nip
// -sip
func parseMapString(mapString string) (*ParsedMapString, error) {
	var entries ParsedMapString
	for _, s := range strings.Split(mapString, ",") {
		if s[0] == '-' {
			s = s[1:]
			sip, err := ParseIP4HostAddr(strings.Split(s, ":")[0])
			if err != nil {
				return nil, fmt.Errorf("invalid Service address: %s | %v", s, err)
			}
			entries.ToRemove = append(entries.ToRemove, MapEntry{ServiceIP: sip})
			continue
		}
		if s[0] == '+' {
			s = s[1:]
		}
		parts := strings.SplitN(s, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid entry: %s", s)
		}
		sip, err := ParseIP4HostAddr(parts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid Service address: %s | %v", parts[0], err)
		}
		parts = strings.SplitN(parts[1], "/", 2)
		nip, err := ParseIP4HostAddr(parts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid Node address: %s | %v", parts[0], err)
		}
		var pip netip.Addr
		if len(parts) == 2 {
			pip, err = ParseIP4HostAddr(parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid Pod address: %s | %v", parts[1], err)
			}
		} else if len(parts) == 1 {
			pip = sip
		} else {
			return nil, fmt.Errorf("invalid entry: %s", s)
		}
		entries.ToAdd = append(entries.ToAdd, MapEntry{
			ServiceIP: sip,
			NodeIP:    nip,
			PodIP:     pip,
		})
	}
	return &entries, nil
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
