package main

// https://pkg.go.dev/github.com/libopenstorage/gossip#section-readme
// https://pkg.go.dev/github.com/hashicorp/memberlist

import (
	"flag"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

type delegate struct {
	registry *ServiceRegistry
}

func main() {
	// Define command-line flags
	ifaceName := flag.String("iface", "", "Interface to attach eBPF program to")
	mapString := flag.String("map", "", "ip mapping")
	httpListen := flag.String("httpListen", ":8080", "Address to listen on for HTTP API")
	sourceIPString := flag.String("src-ip", "", "Address to listen on for HTTP API")

	flag.Parse()

	if *ifaceName == "" {
		log.Fatal("iface is required")
	}

	serviceRegistry, err := NewServiceRegistry()
	if err != nil {
		panic("Failed to create service registry: " + err.Error())
	}
	if *mapString != "" {
		for _, s := range strings.Split(*mapString, ",") {
			parts := strings.SplitN(s, "=", 2)
			if len(parts) != 2 {
				log.Fatalf("Invalid entry: %s", s)
			}
			sip, err := ParseIP4HostAddr(parts[0])
			if err != nil {
				log.Fatalf("Invalid Service address: %s | %v", parts[0], err)
			}
			parts = strings.SplitN(parts[1], "/", 2)
			if len(parts) != 2 {
				log.Fatalf("Invalid entry: %s", s)
			}
			nip, err := ParseIP4HostAddr(parts[0])
			if err != nil {
				log.Fatalf("Invalid Node address: %s | %v", parts[0], err)
			}
			pip, err := ParseIP4HostAddr(parts[1])
			if err != nil {
				log.Fatalf("Invalid Pod address: %s | %v", parts[1], err)
			}
			serviceRegistry.Add(ServiceInfo{
				ID:        s,
				ServiceIP: sip,
				NodeIP:    nip,
				PodIP:     pip,
			})
		}
	}

	var sourceIP netip.Addr
	if *sourceIPString != "" {
		sourceIP, err = ParseIP4HostAddr(*sourceIPString)
		if err != nil {
			log.Fatalf("Invalid source IP address: %s | %v", *sourceIPString, err)
		}
	}

	ebpfMgr, err := NewEBPFManager(*ifaceName, serviceRegistry, sourceIP)
	if err != nil {
		panic("Failed to create EBPF manager: " + err.Error())
	}

	dnsServer := &dns.Server{
		Addr:      ":8053",
		Net:       "udp",
		Handler:   NewDnsHandler(serviceRegistry),
		UDPSize:   65535,
		ReusePort: true,
	}

	errCh := make(chan error)

	go func() {
		log.Printf("Starting DNS server on %s\n", dnsServer.Addr)
		err = dnsServer.ListenAndServe()
		if err != nil {
			errCh <- errors.Wrapf(err, "Failed to start DNS server")
		}
	}()

	go func() {
		log.Printf("Starting HTTP server on %s\n", *httpListen)
		apiService := NewAPIService(serviceRegistry)
		err = http.ListenAndServe(*httpListen, apiService)
		if err != nil {
			errCh <- errors.Wrapf(err, "Failed to start HTTP server")
		}
	}()

	go func() {
		err = ebpfMgr.Run()
		if err != nil {
			errCh <- errors.Wrapf(err, "Failed to run EBPF manager")
		}
	}()

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt)

	onExit := func() {
		log.Print("Shutting down DNS server if running")
		dnsServer.Shutdown()
		log.Print("Shutting down EBPF manager")
		ebpfMgr.Shutdown()
	}

	select {
	case err := <-errCh:
		log.Printf("Error: %s\n", err)
	case <-signalCh:
	}
	onExit()
}
