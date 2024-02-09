package main

import (
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/pkg/errors"
)

type ServiceInfo struct {
	RegisteredAt time.Time
	ID           string
	ServiceIP    netip.Addr
	NodeIP       netip.Addr
	PodIP        netip.Addr
	Domains      []string
}

type SvcUpdateEvent struct {
	EventType string
	Service   ServiceInfo
}

type ServiceRegistry struct {
	services map[string]ServiceInfo

	updateChans []chan<- SvcUpdateEvent
}

func getNodeIP() (net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil
	}

	for _, iface := range ifaces {
		if (iface.Flags & net.FlagUp) != 0 {
			addrs, err := iface.Addrs()
			if err != nil {
				return nil, err
			}

			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
					return ipNet.IP, nil
				}
			}
		}
	}

	return nil, errors.New("No IP address")
}

func NewServiceRegistry() (*ServiceRegistry, error) {
	sm := ServiceRegistry{
		services: make(map[string]ServiceInfo),
	}
	return &sm, nil
}

func (r ServiceRegistry) AddUpdateChan(ch chan<- SvcUpdateEvent) func() {
	r.updateChans = append(r.updateChans, ch)
	return func() {
		for i, c := range r.updateChans {
			if c == ch {
				r.updateChans = append(r.updateChans[:i], r.updateChans[i+1:]...)
				break
			}
		}
	}
}

func (r ServiceRegistry) Add(s ServiceInfo) {
	s.RegisteredAt = time.Now()
	r.services[s.ID] = s
	for _, ch := range r.updateChans {
		ch <- SvcUpdateEvent{EventType: "add", Service: s}
	}
}

func (r ServiceRegistry) Remove(id string) {
	if s, ok := r.services[id]; ok {
		delete(r.services, id)
		for _, ch := range r.updateChans {
			ch <- SvcUpdateEvent{EventType: "remove", Service: s}
		}
	}
}

func (r ServiceRegistry) Get(id string) *ServiceInfo {
	s, ok := r.services[id]
	if !ok {
		return nil
	}
	return &s
}

func (r ServiceRegistry) GetAll() []ServiceInfo {
	var all []ServiceInfo
	for _, s := range r.services {
		all = append(all, s)
	}
	return all
}

func isDomainMatches(domain, entry string) bool {
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	if !strings.HasSuffix(entry, ".") {
		entry = entry + "."
	}
	if domain == entry {
		return true
	}
	if strings.HasPrefix(entry, "*.") {
		base := entry[1:]
		if strings.HasSuffix(domain, base) && !strings.ContainsAny(strings.TrimSuffix(domain, base), ".") {
			return true
		}
	}
	return false
}

func (r ServiceRegistry) getByDomain(domain string) *ServiceInfo {
	for _, s := range r.services {
		for _, d := range s.Domains {
			if isDomainMatches(domain, d) {
				return &s
			}
		}
	}
	return nil
}
