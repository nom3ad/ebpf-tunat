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
	closers    []Closer
	hostEndian binary.ByteOrder
	pinPath    string
}

func NewEBPFManager(ifaceName string) (*EbpfManager, error) {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, errors.Wrapf(err, "failed to remove memlock")
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to find interface %s", ifaceName)
	}
	log.Printf("Found interface: %v", iface)

	pinPath := "/sys/fs/bpf"
	// if err := os.Mkdir(pinPath, 0755); err != nil {
	// 	if !os.IsExist(err) {
	// 		return nil, errors.Wrapf(err, "failed to create bpf pin path %s", pinPath)
	// 	}
	// }

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

	maps := []string{"tunat_state_map", "tunat_svc_to_node_pod_map", "tunat_node_pod_to_svc_map"}
	for _, m := range maps {
		log.Println(spec.Maps, spec.Maps[m].Pinning)
		spec.Maps[m].Name = m + "_" + iface.Name
		spec.Maps[m].Pinning = ebpf.PinByName
	}
	panic("ddd")
	em := EbpfManager{
		iface:      iface,
		spec:       spec,
		hostEndian: hostEndian,
		pinPath:    pinPath,
	}

	return &em, nil
}

func (em *EbpfManager) SetSourceIP(ip netip.Addr) error {
	log.Printf("Setting source IP address in BPF map: %s", ip)
	return em.objs.CountersMap.Update(StateIndexSourceIP, uint64(em.hostEndian.Uint32(ip.AsSlice())), ebpf.UpdateAny)
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

func (em *EbpfManager) Attach() error {

	var objs progObjs
	if err := em.spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: em.pinPath,
		},
	}); err != nil {
		return errors.Wrapf(err, "failed to load and assign ebpf objects")
	}
	log.Printf("Created ebpf manager: %v", em)
	em.objs = objs
	em.closers = append(em.closers, objs.TcEgressProg)
	// em.closers = append(em.closers, objs.XdpIngressProg)
	em.closers = append(em.closers, objs.CountersMap)
	em.closers = append(em.closers, objs.SvcToNodePodMap)
	em.closers = append(em.closers, objs.NodePodToSvcMap)

	if os.Getenv("USE_XDP") == "1" {
		xdpIngressProgName := em.getProgramGivenName("XdpIngressProg")
		log.Printf("Attaching xdp program %s to interface %v\n", xdpIngressProgName, *em.iface)
		xdgOpts := ebpf_link.XDPOptions{
			// Program:   em.objs.XdpIngressProg,
			Interface: em.iface.Index,
		}
		xdgLink, err := ebpf_link.AttachXDP(xdgOpts)
		if err != nil {
			return errors.Wrapf(err, "failed to attach xdp program %s to interface %v", xdpIngressProgName, em.iface)
		}
		em.xdgLink = xdgLink
		em.closers = append(em.closers, xdgLink)
	} else {
		tcIngressProgName := em.getProgramGivenName("TcIngressProg")
		log.Printf("Attaching tc program %s to interface %v\n", tcIngressProgName, em.iface)
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
	return nil
}

func (em *EbpfManager) MapWatch() error {
	ticker := time.NewTicker(2 * time.Second)
	for {
		<-ticker.C
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
	}
}

func (em *EbpfManager) MapInsert(entries ...MapEntry) error {
	for _, it := range entries {
		k := em.hostEndian.Uint32(it.ServiceIP.AsSlice())
		v := uint64(em.hostEndian.Uint32(it.NodeIP.AsSlice()))
		v <<= 32
		v |= uint64(em.hostEndian.Uint32(it.PodIP.AsSlice()))
		log.Printf("Adding service entry in BPF map %s | %d:%d", it, k, v)
		err := em.objs.SvcToNodePodMap.Update(k, v, ebpf.UpdateAny)
		if err != nil {
			log.Printf("Failed to add service entry from SvcToNodePodMap BPF map: %v", err)
			return err
		}
		err = em.objs.NodePodToSvcMap.Update(v, k, ebpf.UpdateAny)
		if err != nil {
			log.Printf("Failed to add service entry from NodePodToSvcMap BPF map: %v", err)
		}
	}
	return nil
}

func (em *EbpfManager) MapRemove(entries ...MapEntry) error {
	for _, it := range entries {
		k := em.hostEndian.Uint32(it.ServiceIP.AsSlice())
		var v uint64
		log.Printf("Removing service entry in BPF map %s | %d", it, k)
		err := em.objs.SvcToNodePodMap.LookupAndDelete(k, &v)
		if err != nil {
			log.Printf("Failed to remove service entry from SvcToNodePodMap BPF map: %v", err)
			return err
		}
		err = em.objs.NodePodToSvcMap.Delete(v)
		if err != nil {
			log.Printf("Failed to remove service entry  from NodePodToSvcMap BPF map: %v", err)
		}
	}
	return nil
}
