package main

// https://pkg.go.dev/github.com/libopenstorage/gossip#section-readme
// https://pkg.go.dev/github.com/hashicorp/memberlist

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
)

type dnsHandler struct {
	serviceRegistry *ServiceRegistry
}

func NewDnsHandler(s *ServiceRegistry) *dnsHandler {
	return &dnsHandler{
		serviceRegistry: s,
	}
}

func (h *dnsHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true
	for _, q := range r.Question {
		log.Printf("Query for %s\n", q.Name)
		if q.Qtype != dns.TypeA || q.Qtype != dns.TypeTXT {
			msg.SetRcode(r, dns.RcodeNotImplemented)
		}
		s := h.serviceRegistry.getByDomain(q.Name)
		if s != nil {
			var rrString string
			if q.Qtype == dns.TypeA {
				rrString = fmt.Sprintf("%s A %s", q.Name, s.ServiceIP)
			} else if q.Qtype == dns.TypeTXT {
				rrString = fmt.Sprintf("%s TXT id=%s,sip=%s,nip=%s,pip=%s", q.Name, s.ID, s.ServiceIP, s.NodeIP, s.PodIP)
			}
			rr, err := dns.NewRR(rrString)
			if err == nil {
				msg.Answer = append(msg.Answer, rr)
			}
		} else {
			msg.SetRcode(r, dns.RcodeNameError)
		}
	}
	w.WriteMsg(msg)
}
