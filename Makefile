GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
CLANG := clang
CLANG_INCLUDE := -I.

EBPF_SOURCE_C := bpf_prog.c
EBPF_SOURCE_H := include/bpf_prog.h
BIN_DIST_OUT := dist/tunat

BUILD_WITH_LOG_DEBUG ?= $(DEBUG)
CLANG_ARGS := -DBUILD_WITH_LOG_DEBUG=$(BUILD_WITH_LOG_DEBUG)

TEST_INTERFACE := wg0
TEST_INTERFACE_IP ?= $(shell ip addr show $(TEST_INTERFACE) | grep -oP 'inet \K[\d.]+')
TEST_NAT_MAP ?= "10.208.1.2=10.101.0.31/10.32.3.69"

# run: ebpf
# 	go run *.go

run: build
	sudo setcap cap_net_admin,cap_sys_admin+ep $(BIN_DIST_OUT)
	$(BIN_DIST_OUT) -iface $(TEST_INTERFACE) --src-ip $(TEST_INTERFACE_IP) -map $(TEST_NAT_MAP)

build: ebpf
	# go generate && go build
	CGO_ENABLED=0 go build -o $(BIN_DIST_OUT) .

ebpf: $(EBPF_SOURCE_C) $(EBPF_SOURCE_H)
	@set -e -o pipefail; \
	mkdir -p dist; \
	for l in l2 l3; do \
		for e in el eb; do \
			bpf_target=bpf$$e; \
			bin_out=dist/bpf_prog-$$l.$$e.elf; \
			clang -target $$bpf_target -Wall -O2 -Wno-unused-function -emit-llvm -DBUILD_TARGET_IFACE_LAYER=$${l#l} -g $(CLANG_ARGS) -Iinclude -c $(EBPF_SOURCE_C) -o - | \
				llc -march=$$bpf_target -mcpu=probe -filetype=obj -o $$bin_out; \
		done;\
	done; \
	ls -lh dist/*.elf

$(EBPF_SOURCE_H):

clean:
	$(GOCLEAN)
	rm -rf dist

agent:
	echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
	sudo iptables -t filter -P FORWARD ACCEPT
	sudo ip link add name ipip0 type ipip remote 172.30.0.54
	sudo ip addr add dev ipip0 10.53.65.0/24
	sudo ip link set ipip0 up


watch-bpf:
	sudo watch "xdp-loader status;bpflist;bpftool net"

trace-log:
	sudo cat  /sys/kernel/debug/tracing/trace_pipe

send-udp:
	{ while true;do sleep 1; date; done; } | ncat 10.208.1.2 9090 -u

map-dump:
	sudo bpftool map -j | jq -c  '.[] | select(.name | startswith("tunat"))' 
	sudo bpftool map -j | jq -c  '.[] | select(.name | startswith("tunat")) | .id' | xargs -I{} sh -c 'echo ID={};sudo bpftool map dump id {} | jq -c'