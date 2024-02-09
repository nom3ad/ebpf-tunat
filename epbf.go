package main

import (
	"bytes"
	"embed"
	"encoding/binary"
	"log"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"time"

	// "github.com/dropbox/goebpf"
	"github.com/cilium/ebpf"
	ebpf_link "github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"
)

// "github.com/cilium/ebpf"
// "github.com/cilium/ebpf/link"
// "github.com/cilium/ebpf/perf"

var bpfElfDistPathNameTemplate = "dist/bpf_prog-{variant}.elf"

//go:embed "dist/*.elf"
var bpfBundleInjected embed.FS

const (
	StateIndexIngressPacketCount uint32 = iota
	StateIndexEgressPacketCount
	StateIndexSourceIP
)

type progObjs struct {
	XdpIngressProg  *ebpf.Program `ebpf:"tunat_xdp_ingress"`
	TcEgressProg    *ebpf.Program `ebpf:"tunat_tc_egress"`
	TcIngressProg   *ebpf.Program `ebpf:"tunat_tc_ingress"`
	CountersMap     *ebpf.Map     `ebpf:"tunat_state_map"`
	SvcToNodePodMap *ebpf.Map     `ebpf:"tunat_svc_to_node_pod_map"`
	NodePodToSvcMap *ebpf.Map     `ebpf:"tunat_node_pod_to_svc_map"`
}

type Closer interface {
	Close() error
}

type CloserFunc func() error

func (cf CloserFunc) Close() error {
	return cf()
}

type EbpfManager struct {
	spec       *ebpf.CollectionSpec
	iface      *net.Interface
	xdgLink    ebpf_link.Link
	objs       progObjs
	sm         *ServiceRegistry
	closers    []Closer
	hostEndian binary.ByteOrder
}

func NewEBPFManager(ifaceName string, sm *ServiceRegistry, sourceIP netip.Addr) (*EbpfManager, error) {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, errors.Wrapf(err, "failed to remove memlock")
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to find interface %s", ifaceName)
	}
	log.Printf("Found interface: %v", iface)
	variant := os.Getenv("BPF_PROG_VARIANT")
	hostEndian := GetHostEndian()
	if variant == "" {
		variant = "l3"
		if iface.HardwareAddr != nil {
			variant = "l2"
		}
		if hostEndian == binary.BigEndian {
			variant += ".eb"
		} else {
			variant += ".el"
		}
	}
	bpfElfBinaryPath := strings.Replace(bpfElfDistPathNameTemplate, "{variant}", variant, 1)
	log.Printf("Loading ebpf elf %s\n", bpfElfBinaryPath)
	fBytes, err := bpfBundleInjected.ReadFile(bpfElfBinaryPath)
	if err != nil {
		return nil, errors.Wrapf(err, "open failed %s", bpfElfBinaryPath)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(fBytes))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load ebpf elf %s", bpfElfBinaryPath)
	}

	for k, m := range spec.Maps {
		log.Printf("BPF Map: %s = %v\n", k, m)
	}
	for k, p := range spec.Programs {
		log.Printf("BPF Program: %s@%s typ=%s, ins=%d sz=%dB bo=%s\n", k, p.SectionName, p.Type, len(p.Instructions), p.Instructions.Size(), p.ByteOrder)
		if os.Getenv("DEBUG") == "1" {
			log.Printf("%v", p)
		}
	}

	var objs progObjs

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, errors.Wrapf(err, "failed to load and assign ebpf objects from %s", bpfElfBinaryPath)
	}
	em := EbpfManager{
		iface:      iface,
		spec:       spec,
		objs:       objs,
		sm:         sm,
		hostEndian: hostEndian,
	}
	em.closers = append(em.closers, objs.TcEgressProg)
	em.closers = append(em.closers, objs.XdpIngressProg)
	em.closers = append(em.closers, objs.CountersMap)
	em.closers = append(em.closers, objs.SvcToNodePodMap)
	em.closers = append(em.closers, objs.NodePodToSvcMap)

	if sourceIP.IsValid() {
		log.Printf("Setting source IP address in BPF map: %s", sourceIP)
		err = objs.CountersMap.Update(StateIndexSourceIP, uint64(em.hostEndian.Uint32(sourceIP.AsSlice())), ebpf.UpdateAny)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to set source IP address in BPF map")
		}
	}

	return &em, nil
}

func (em *EbpfManager) getProgramGivenName(fieldName string) string {
	o := reflect.TypeOf(em.objs)
	f, ok := o.FieldByName(fieldName)
	if !ok {
		panic("Invalid bpf field name: " + fieldName)
	}
	tag := f.Tag.Get("ebpf")
	if tag == "" {
		panic("Invalid bpf field: " + fieldName)
	}
	return tag
}

func (em *EbpfManager) Run() error {

	if os.Getenv("USE_XDP") == "1" {

		xdpIngressProgName := em.getProgramGivenName("XdpIngressProg")
		log.Printf("Attaching xdp program %s to interface %s\n", xdpIngressProgName, em.iface)
		xdgOpts := ebpf_link.XDPOptions{
			Program:   em.objs.XdpIngressProg,
			Interface: em.iface.Index,
		}
		xdgLink, err := ebpf_link.AttachXDP(xdgOpts)
		if err != nil {
			return errors.Wrapf(err, "failed to attach xdp program %s to interface %s", xdpIngressProgName, em.iface)
		}
		em.xdgLink = xdgLink
		em.closers = append(em.closers, xdgLink)
	} else {
		tcIngressProgName := em.getProgramGivenName("TcIngressProg")
		log.Printf("Attaching tc program %s to interface %s\n", tcIngressProgName, em.iface)
		tcIngressOpts := TCAttachOptions{
			Program:     em.objs.TcIngressProg,
			ProgramName: tcIngressProgName,
			Interface:   em.iface.Index,
			IsIngress:   true,
		}
		remove, err := AttachTC(tcIngressOpts)
		if err != nil {
			return errors.Wrapf(err, "failed to attach tc program %s to interface %s", tcIngressProgName, em.iface)
		}
		em.closers = append(em.closers, remove)
	}

	tcEgressProgName := em.getProgramGivenName("TcEgressProg")
	log.Printf("Attaching tc program %s to interface %s\n", tcEgressProgName, em.iface)
	tcEgressOpts := TCAttachOptions{
		Program:     em.objs.TcEgressProg,
		ProgramName: tcEgressProgName,
		Interface:   em.iface.Index,
		IsIngress:   false,
	}
	remove, err := AttachTC(tcEgressOpts)
	if err != nil {
		return errors.Wrapf(err, "failed to attach tc program %s to interface %s", tcEgressProgName, em.iface)
	}
	em.closers = append(em.closers, remove)

	svcUpdateChan := make(chan SvcUpdateEvent)
	em.sm.AddUpdateChan(svcUpdateChan)
	for _, s := range em.sm.GetAll() {
		em.onAddService(s)
	}

	ticker := time.NewTicker(2 * time.Second)
	for {
		select {
		case <-ticker.C:
			var ingressCount, egressCount uint64
			var err error
			err = em.objs.CountersMap.Lookup(StateIndexIngressPacketCount, &ingressCount)
			if err != nil {
				log.Fatal("Ingress counter Map lookup:", err)
			}
			err = em.objs.CountersMap.Lookup(StateIndexEgressPacketCount, &egressCount)
			if err != nil {
				log.Fatal("Egress counter Map lookup:", err)
			}
			log.Printf("Stats: Ingress: %d, Egress: %d", ingressCount, egressCount)
		case svcUpdate := <-svcUpdateChan:
			log.Printf("Service update: %v", svcUpdate)
			if svcUpdate.EventType == "add" {
				em.onAddService(svcUpdate.Service)
			}
			if svcUpdate.EventType == "remove" {
				em.onRemoveService(svcUpdate.Service)
			}
		}
	}
}

func (em *EbpfManager) onAddService(s ServiceInfo) {
	k := em.hostEndian.Uint32(s.ServiceIP.AsSlice())
	v := uint64(em.hostEndian.Uint32(s.NodeIP.AsSlice()))
	v <<= 32
	v |= uint64(em.hostEndian.Uint32(s.PodIP.AsSlice()))
	log.Printf("Adding service entry in BPF map %s | %s=%s/%s | %d:%d", s.ID, s.ServiceIP, s.NodeIP, s.PodIP, k, v)
	err := em.objs.SvcToNodePodMap.Update(k, v, ebpf.UpdateAny)
	if err != nil {
		log.Printf("Failed to add service entry from SvcToNodePodMap BPF map: %v", err)
		return
	}
	err = em.objs.NodePodToSvcMap.Update(v, k, ebpf.UpdateAny)
	if err != nil {
		log.Printf("Failed to add service entry from NodePodToSvcMap BPF map: %v", err)
	}
}

func (em *EbpfManager) onRemoveService(s ServiceInfo) {
	k := em.hostEndian.Uint32(s.ServiceIP.AsSlice())
	var v uint64
	log.Printf("Removing service entry in BPF map %s | %d", s.ID, k)
	err := em.objs.SvcToNodePodMap.LookupAndDelete(k, &v)
	if err != nil {
		log.Printf("Failed to remove service entry from SvcToNodePodMap BPF map: %v", err)
		return
	}
	err = em.objs.NodePodToSvcMap.Delete(v)
	if err != nil {
		log.Printf("Failed to remove service entry  from NodePodToSvcMap BPF map: %v", err)
	}

}

func (em *EbpfManager) Shutdown() error {
	for _, c := range em.closers {
		err := c.Close()
		if err != nil {
			log.Printf("Failed to close resource: %v", err)
		}
	}
	return nil
}
