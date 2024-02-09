// +build none

#include <stdint.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>

#include "bpf_prog.h"

// struct svc_map_key
// {
//     __be32 s_ip;
// };

// struct svc_map_val
// {
//     __be32 node_ip_addr;
//     __be32 pod_ip_addr;
// };

#ifndef MAX_SVC_MAP_ENTRIES
#define MAX_SVC_MAP_ENTRIES 1024
#endif

#define STATE_MAP_ENTRIES 3
#define STATE_MAP_INDEX_INGRESS_PACKET_COUNT 0
#define STATE_MAP_INDEX_EGRESS_PACKET_COUNT 1
#define STATE_MAP_INDEX_SOURCE_IP 2

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, STATE_MAP_ENTRIES);
} tunat_state_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, MAX_SVC_MAP_ENTRIES);
} tunat_svc_to_node_pod_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);
    __type(value, __u32);
    __uint(max_entries, MAX_SVC_MAP_ENTRIES);
} tunat_node_pod_to_svc_map SEC(".maps");

SEC("xdp_ingress")
int tunat_xdp_ingress(struct xdp_md *xdpmd)
{
    struct iphdr *iph;
    GET_IP_HEADER_OR_GOTO(xdpmd, iph, done);

    // --------- IPIP peeking ----------------
    if (iph->protocol != IPPROTO_IPIP)
        goto done;

    struct iphdr *inner_iph = (void *)(iph + 1);
    ENSURE_BOUND_OR_GOTO(xdpmd, inner_iph, done);

    // --------- Service lookup ----------------
    __u32 pod_ip_addr = inner_iph->saddr;
    __u32 node_ip_addr = iph->saddr; // outer ip

    __u64 svc_key = pod_ip_addr | ((__u64)node_ip_addr << 32);
    __u32 *svc_value = bpf_map_lookup_elem(&tunat_node_pod_to_svc_map, &svc_key);
    if (!svc_value)
        goto done; // Not a service IP
    __u32 svc_ip_addr = *svc_value;
    LOG_DEBUG("xdp-ing: service ip: %s / %s -> %s", BE32_TO_IPV4(node_ip_addr), BE32_TO_IPV4(pod_ip_addr), BE32_TO_IPV4(svc_ip_addr));

    // ---------------- IPIP decapsulation ----------------
    bpf_xdp_adjust_head(xdpmd, (void *)inner_iph - (void *)iph);

    // --- SNAT ---
    struct iphdr *decap_iph;
    GET_IP_HEADER_OR_GOTO(xdpmd, decap_iph, done);

    __u32 old_saddr = decap_iph->saddr;
    decap_iph->saddr = svc_ip_addr;

    // --------- L3/L4 checksum update ----------------
    update_ip_checksum(decap_iph, SIZE_OF_IP_HEADER, &decap_iph->check);
    __sum16 *l4_csum_loc = NULL;
    if (decap_iph->protocol == IPPROTO_UDP)
    {
        l4_csum_loc = (void *)decap_iph + SIZE_OF_IP_HEADER + offsetof(struct udphdr, check);
    }
    else if (decap_iph->protocol == IPPROTO_TCP)
    {
        l4_csum_loc = (void *)decap_iph + SIZE_OF_IP_HEADER + offsetof(struct tcphdr, check);
    }
    if (l4_csum_loc != NULL)
    {
        ENSURE_BOUND_OR_GOTO(xdpmd, l4_csum_loc, done);
        //! not working
        __sum16 sum = old_saddr + (~__bpf_ntohs(*(__u16 *)&decap_iph->saddr) & 0xffff);
        sum += __bpf_ntohs(*l4_csum_loc);
        sum = (sum & 0xffff) + (sum >> 16);
        *l4_csum_loc = __bpf_htons(sum + (sum >> 16) - 1);
    }

    // ------ Ingress counter ----------------
    INCR_U32_TO_U64_MAP_VALUE(tunat_state_map, STATE_MAP_INDEX_INGRESS_PACKET_COUNT);

    return XDP_PASS;

done:
    // Try changing this to XDP_DROP and see what happens!
    return XDP_PASS;
}

SEC("tc_ingress")
int tunat_tc_ingress(struct __sk_buff *skb)
{
    struct iphdr *iph;
    GET_IP_HEADER_OR_GOTO(skb, iph, done);

    // --------- IPIP peeking ----------------
    if (iph->protocol != IPPROTO_IPIP)
        goto done;

    struct iphdr *inner_iph = (void *)(iph + 1);
    ENSURE_BOUND_OR_GOTO(skb, inner_iph, done);

    // --------- Service lookup ----------------
    __u32 pod_ip_addr = inner_iph->saddr;
    __u32 node_ip_addr = iph->saddr; // outer ip

    __u64 svc_key = pod_ip_addr | ((__u64)node_ip_addr << 32);
    __u32 *svc_value = bpf_map_lookup_elem(&tunat_node_pod_to_svc_map, &svc_key);
    if (!svc_value)
        goto done; // Not a service IP
    __u32 svc_ip_addr = *svc_value;

    LOG_DEBUG("tc-ing: decap-snat : %s / %s -> %s", BE32_TO_IPV4(node_ip_addr), BE32_TO_IPV4(pod_ip_addr), BE32_TO_IPV4(svc_ip_addr));
    
    // ---------------- IPIP decapsulation ----------------
    bpf_skb_adjust_room(skb, -(__u32)(SIZE_OF_IP_HEADER), BPF_ADJ_ROOM_MAC, 0);

    // --- SNAT ---
    struct iphdr *decap_iph;
    GET_IP_HEADER_OR_GOTO(skb, decap_iph, done);

    __u32 old_saddr = decap_iph->saddr;
    decap_iph->saddr = svc_ip_addr;

    // ----- L3/L4 checksum update ----------------
    int ret = update_checksum_after_ip_nat(skb, decap_iph, old_saddr, svc_ip_addr);
    if (ret)
    {
        LOG_DEBUG("tc-egr: l3/l4 csum replace failed");
        goto done;
    }

    // ------ Ingress counter ----------------
    INCR_U32_TO_U64_MAP_VALUE(tunat_state_map, STATE_MAP_INDEX_INGRESS_PACKET_COUNT);

    return TC_ACT_OK;

done:
    return TC_ACT_OK;
}


SEC("tc_egress")
int tunat_tc_egress(struct __sk_buff *skb)
{

    struct iphdr *iph;
    GET_IP_HEADER_OR_GOTO(skb, iph, done);

    // --------- Service lookup ----------------
    __u32 svc_key = iph->daddr;
    __u64 *svc_value = bpf_map_lookup_elem(&tunat_svc_to_node_pod_map, &svc_key);
    if (!svc_value)
        goto done; // Not a service IP
    __u32 source_ip_key = STATE_MAP_INDEX_SOURCE_IP;
    __u64 *src_ip_addr = bpf_map_lookup_elem(&tunat_state_map, &source_ip_key);

    __u32 node_ip_addr = *svc_value >> 32;
    __u32 pod_ip_addr = *svc_value & 0xFFFFFFFF;

    LOG_DEBUG("tc-egr: dnat-encap: %s -> %s / %s ", BE32_TO_IPV4(iph->daddr), BE32_TO_IPV4(node_ip_addr), BE32_TO_IPV4(pod_ip_addr));

    // --------- DNAT ----------------
    int ret = 0;
    __u32 svc_ip_addr = iph->daddr;
    iph->daddr = pod_ip_addr;

    // --------- L3/L4 checksum update ----------------
    ret = update_checksum_after_ip_nat(skb, iph, svc_ip_addr, pod_ip_addr);
    if (ret)
    {
        LOG_DEBUG("tc-egr: l3/l4 csum replace failed");
        goto done;
    }
    // ---------- IPIP encapsulation ----------------
    ret = bpf_skb_adjust_room(skb, SIZE_OF_IP_HEADER, BPF_ADJ_ROOM_MAC, 0);
    if (ret)
    {
        LOG_DEBUG("tc-egr: skb adjust room failed");
        goto done;
    }

    struct iphdr *outer_iph;
    GET_IP_HEADER_OR_GOTO(skb, outer_iph, done);
    struct iphdr *inner_iph = outer_iph + 1;
    ENSURE_BOUND_OR_GOTO(skb, inner_iph, done);
    outer_iph->version = inner_iph->version;
    outer_iph->ihl = inner_iph->ihl;
    outer_iph->tos = inner_iph->tos;
    outer_iph->tot_len = __bpf_htons(__bpf_ntohs(inner_iph->tot_len) + SIZE_OF_IP_HEADER);
    outer_iph->id = ~inner_iph->id;
    outer_iph->frag_off = 0;
    outer_iph->ttl = 40;
    outer_iph->protocol = IPPROTO_IPIP;
    if (src_ip_addr && *src_ip_addr != 0)
    {
        // LOG_DEBUG("tc-egr: source ip: %s", BE32_TO_IPV4(*src_ip_addr));
        outer_iph->saddr = (__u32)*src_ip_addr;
    }
    else
    {
        outer_iph->saddr = inner_iph->saddr;
    }
    outer_iph->daddr = node_ip_addr;

    // ------- IPIP L3 checksum ----------------
    outer_iph->check = 0;
    __wsum csum_outer = bpf_csum_diff(0, 0, (void *)outer_iph, SIZE_OF_IP_HEADER, 0);
    ret = bpf_l3_csum_replace(skb, GET_DATA_PTR_OFFSET(skb, outer_iph) + offsetof(struct iphdr, check), 0, csum_outer, 0);
    if (ret)
    {
        LOG_DEBUG("tc-egr: l3 csum replace failed");
        goto done;
    }

    // -------- Egress counter ----------------
    INCR_U32_TO_U64_MAP_VALUE(tunat_state_map, STATE_MAP_INDEX_EGRESS_PACKET_COUNT);

    return TC_ACT_OK;
done:
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
