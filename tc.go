package main

import (
	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type TCAttachOptions struct {
	Program     *ebpf.Program
	ProgramName string
	Interface   int
	IsIngress   bool
}

func AttachTC(opts TCAttachOptions) (CloserFunc, error) {
	// https://fedepaol.github.io/blog/2023/04/06/ebpf-tc-filters-for-egress-traffic/
	// https://github.com/cilium/ebpf/discussions/769
	// https://d0u9.io/use-cilium-ebpf-to-compile-and-load-tc-bpf-code/
	qdiscAttrs := netlink.QdiscAttrs{
		LinkIndex: opts.Interface,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: qdiscAttrs,
		QdiscType:  "clsact",
	}
	if err := netlink.QdiscReplace(qdisc); err != nil {
		if err != nil {
			return nil, errors.Wrapf(err, "cannot add clsact qdisc")
		}
	}

	filterAttrs := netlink.FilterAttrs{
		LinkIndex: opts.Interface,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}
	if opts.IsIngress {
		filterAttrs.Parent = netlink.HANDLE_MIN_INGRESS
	}

	filter := &netlink.BpfFilter{
		FilterAttrs:  filterAttrs,
		Fd:           opts.Program.FD(),
		Name:         opts.ProgramName,
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filter); err != nil {
		return nil, errors.Wrapf(err, "cannot attach bpf object to filter")
	}

	remove := func() error {
		return netlink.FilterDel(filter)
	}

	return remove, nil
}
