package main

import (
	"bytes"
	"embed"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

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

type Ipv4BEInt uint32

func (i Ipv4BEInt) AsAddr() netip.Addr {
	return netip.AddrFrom4([4]byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)})
}

func IpAddrToBEInt(ip netip.Addr) Ipv4BEInt {
	return Ipv4BEInt(GetHostEndian().Uint32(ip.AsSlice()))
}

type SvcMapEntry struct {
	ServiceIP Ipv4BEInt
}
type NodePodMapEntry struct {
	// Order is important here
	PodIP  Ipv4BEInt
	NodeIP Ipv4BEInt
}

type progObjs struct {
	XdpIngressProg  *ebpf.Program `ebpf:"tunat_xdp_ingress"`
	TcEgressProg    *ebpf.Program `ebpf:"tunat_tc_egress"`
	TcIngressProg   *ebpf.Program `ebpf:"tunat_tc_ingress"`
	StateMap        *ebpf.Map     `ebpf:"tunat_state_map"`
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
	spec    *ebpf.CollectionSpec
	iface   *net.Interface
	closers []Closer
	pinPath string

	stateMap        *ebpf.Map
	svcToNodePodMap *ebpf.Map
	nodePodToSvcMap *ebpf.Map
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

	pinPath := "/sys/fs/bpf/tunat"
	if err := os.Mkdir(pinPath, 0755); err != nil {
		if !os.IsExist(err) {
			return nil, errors.Wrapf(err, "failed to create bpf pinpath %s", pinPath)
		}
	}

	variant := os.Getenv("BPF_PROG_VARIANT")
	if variant == "" {
		variant = "l3"
		if iface.HardwareAddr != nil {
			variant = "l2"
		}
		if GetHostEndian() == binary.BigEndian {
			variant += ".eb"
		} else {
			variant += ".el"
		}
	}
	bpfElfBinaryPath := strings.Replace(bpfElfDistPathNameTemplate, "{variant}", variant, 1)
	log.Printf("Loading ebpf elf %s", bpfElfBinaryPath)
	fBytes, err := bpfBundleInjected.ReadFile(bpfElfBinaryPath)
	if err != nil {
		return nil, errors.Wrapf(err, "open failed %s", bpfElfBinaryPath)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(fBytes))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load ebpf elf %s", bpfElfBinaryPath)
	}

	for k, m := range spec.Maps {
		log.Printf("BPF Map: %s = %v", k, m)
	}
	for k, p := range spec.Programs {
		log.Printf("BPF Program: %s@%s typ=%s, ins=%d sz=%dB bo=%s", k, p.SectionName, p.Type, len(p.Instructions), p.Instructions.Size(), p.ByteOrder)
		if os.Getenv("DEBUG") == "1" {
			log.Printf("%v", p)
		}
	}

	maps := []string{"tunat_state_map", "tunat_svc_to_node_pod_map", "tunat_node_pod_to_svc_map"}
	for _, m := range maps {
		spec.Maps[m].Name = m + "_" + iface.Name
		spec.Maps[m].Pinning = ebpf.PinByName
	}
	em := EbpfManager{
		iface:   iface,
		spec:    spec,
		pinPath: pinPath,
	}

	return &em, nil
}

func (em *EbpfManager) getOrLoadStateMap() (*ebpf.Map, error) {
	if em.stateMap == nil {
		spec := em.spec.Maps["tunat_state_map"]
		m, err := ebpf.NewMapWithOptions(spec, ebpf.MapOptions{PinPath: em.pinPath})
		if err != nil {
			return nil, errors.Wrapf(err, "failed to load tunat_state_map")
		}
		em.stateMap = m
	}
	return em.stateMap, nil
}
func (em *EbpfManager) getOrLoadSvcToNodePodMap() (*ebpf.Map, error) {
	if em.svcToNodePodMap == nil {
		spec := em.spec.Maps["tunat_svc_to_node_pod_map"]
		m, err := ebpf.NewMapWithOptions(spec, ebpf.MapOptions{PinPath: em.pinPath})
		if err != nil {
			return nil, errors.Wrapf(err, "failed to load tunat_svc_to_node_pod_map")
		}
		em.svcToNodePodMap = m
	}
	return em.svcToNodePodMap, nil
}
func (em *EbpfManager) getOrLoadNodePodToSvcMap() (*ebpf.Map, error) {
	if em.nodePodToSvcMap == nil {
		spec := em.spec.Maps["tunat_node_pod_to_svc_map"]
		m, err := ebpf.NewMapWithOptions(spec, ebpf.MapOptions{PinPath: em.pinPath})
		if err != nil {
			return nil, errors.Wrapf(err, "failed to load tunat_node_pod_to_svc_map")
		}
		em.nodePodToSvcMap = m
	}
	return em.nodePodToSvcMap, nil
}

func (em *EbpfManager) SetSourceIP(ip netip.Addr) error {
	stateMap, err := em.getOrLoadStateMap()
	if err != nil {
		return err
	}
	log.Printf("Setting source IP address in BPF map: %s", ip)
	return stateMap.Update(StateIndexSourceIP, uint64(IpAddrToBEInt(ip)), ebpf.UpdateAny)
}

func (em *EbpfManager) getProgramGivenName(fieldName string) string {
	o := reflect.TypeOf(progObjs{})
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

	em.stateMap = objs.StateMap
	em.svcToNodePodMap = objs.SvcToNodePodMap
	em.nodePodToSvcMap = objs.NodePodToSvcMap

	em.closers = append(em.closers, objs.TcEgressProg)
	// em.closers = append(em.closers, objs.XdpIngressProg)
	em.closers = append(em.closers, objs.StateMap)
	em.closers = append(em.closers, objs.SvcToNodePodMap)
	em.closers = append(em.closers, objs.NodePodToSvcMap)

	if os.Getenv("USE_XDP") == "1" {
		xdpIngressProgName := em.getProgramGivenName("XdpIngressProg")
		log.Printf("Attaching xdp program %s to interface %v", xdpIngressProgName, *em.iface)
		xdgOpts := ebpf_link.XDPOptions{
			Program:   objs.XdpIngressProg,
			Interface: em.iface.Index,
		}
		xdgLink, err := ebpf_link.AttachXDP(xdgOpts)
		if err != nil {
			return errors.Wrapf(err, "failed to attach xdp program %s to interface %v", xdpIngressProgName, em.iface)
		}
		em.closers = append(em.closers, xdgLink)
	} else {
		tcIngressProgName := em.getProgramGivenName("TcIngressProg")
		log.Printf("Attaching tc program %s to interface %v", tcIngressProgName, em.iface)
		tcIngressOpts := TCAttachOptions{
			Program:     objs.TcIngressProg,
			ProgramName: tcIngressProgName,
			Interface:   em.iface.Index,
			IsIngress:   true,
		}
		remove, err := AttachTC(tcIngressOpts)
		if err != nil {
			return errors.Wrapf(err, "failed to attach tc program %s to interface %v", tcIngressProgName, em.iface)
		}
		em.closers = append(em.closers, remove)
	}

	tcEgressProgName := em.getProgramGivenName("TcEgressProg")
	log.Printf("Attaching tc program %s to interface %v", tcEgressProgName, em.iface)
	tcEgressOpts := TCAttachOptions{
		Program:     objs.TcEgressProg,
		ProgramName: tcEgressProgName,
		Interface:   em.iface.Index,
		IsIngress:   false,
	}
	remove, err := AttachTC(tcEgressOpts)
	if err != nil {
		return errors.Wrapf(err, "failed to attach tc program %s to interface %v", tcEgressProgName, em.iface)
	}
	em.closers = append(em.closers, remove)
	return nil
}

func (em *EbpfManager) DumpMap() error {
	svcToNodePodMap, err := em.getOrLoadSvcToNodePodMap()
	if err != nil {
		return err
	}
	iter := svcToNodePodMap.Iterate()
	var key SvcMapEntry
	var value NodePodMapEntry
	i := 0
	for iter.Next(&key, &value) {
		i += 1
		fmt.Printf("%d] %s : %s/%s\n", i, key.ServiceIP.AsAddr(), value.NodeIP.AsAddr(), value.PodIP.AsAddr())
	}
	return nil
}

func (em *EbpfManager) MapWatch() error {
	ticker := time.NewTicker(2 * time.Second)
	stateMap, err := em.getOrLoadStateMap()
	if err != nil {
		return err
	}
	for {
		<-ticker.C
		var ingressCount, egressCount uint64
		var err error
		err = stateMap.Lookup(StateIndexIngressPacketCount, &ingressCount)
		if err != nil {
			return errors.Wrapf(err, "ingress counter Map lookup:")
		}
		err = stateMap.Lookup(StateIndexEgressPacketCount, &egressCount)
		if err != nil {
			return errors.Wrapf(err, "egress counter Map lookup:")
		}
		fmt.Printf("{\"ingress\": %d, \"egress\": %d}\n", ingressCount, egressCount)
	}
}

func (em *EbpfManager) MapInsert(entries ...MapEntry) error {
	svcToNodePodMap, err := em.getOrLoadSvcToNodePodMap()
	if err != nil {
		return err
	}
	nodePodToSvcMap, err := em.getOrLoadNodePodToSvcMap()
	if err != nil {
		return err
	}
	for _, it := range entries {
		k := SvcMapEntry{ServiceIP: IpAddrToBEInt(it.ServiceIP)}
		v := NodePodMapEntry{PodIP: IpAddrToBEInt(it.PodIP), NodeIP: IpAddrToBEInt(it.NodeIP)}
		log.Printf("Adding service entry in BPF map %s | %d:%d", it, k, v)
		err := svcToNodePodMap.Update(k, v, ebpf.UpdateAny)
		if err != nil {
			log.Printf("Failed to add service entry from SvcToNodePodMap BPF map: %v", err)
			return err
		}
		err = nodePodToSvcMap.Update(v, k, ebpf.UpdateAny)
		if err != nil {
			log.Printf("Failed to add service entry from NodePodToSvcMap BPF map: %v", err)
		}
	}
	return nil
}

func (em *EbpfManager) MapRemove(entries ...MapEntry) error {
	svcToNodePodMap, err := em.getOrLoadSvcToNodePodMap()
	if err != nil {
		return err
	}
	nodePodToSvcMap, err := em.getOrLoadNodePodToSvcMap()
	if err != nil {
		return err
	}
	for _, it := range entries {
		k := IpAddrToBEInt(it.ServiceIP)
		var v uint64
		log.Printf("Removing service entry in BPF map %s | %d", it, k)
		err := svcToNodePodMap.LookupAndDelete(k, &v)
		if err != nil {
			log.Printf("Failed to remove service entry from SvcToNodePodMap BPF map: %v", err)
			return err
		}
		err = nodePodToSvcMap.Delete(v)
		if err != nil {
			log.Printf("Failed to remove service entry  from NodePodToSvcMap BPF map: %v", err)
		}
	}
	return nil
}
