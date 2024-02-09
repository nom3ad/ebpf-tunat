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

#define SIZE_OF_IP_HEADER sizeof(struct iphdr)
#define SIZEOF_ETH_HEADER sizeof(struct ethhdr)

#ifndef BUILD_TARGET_IFACE_LAYER
#error "BUILD_TARGET_IFACE_LAYER must be defined"
#endif


static char *be32_to_ipv4(__be32 ip_value, char *ip_buffer)
{
    __u64 ip_data[4];

    ip_data[3] = ((__u64)(ip_value >> 24) & 0xFF);
    ip_data[2] = ((__u64)(ip_value >> 16) & 0xFF);
    ip_data[1] = ((__u64)(ip_value >> 8) & 0xFF);
    ip_data[0] = ((__u64)ip_value & 0xFF);

    bpf_snprintf(ip_buffer, 16, "%d.%d.%d.%d", ip_data, 4 * sizeof(__u64));
    return ip_buffer;
}

#ifdef BUILD_WITH_LOG_DEBUG
// https://nakryiko.com/posts/bpf-tips-printk/
#define LOG_DEBUG(fmt, ...)                                        \
    ({                                                             \
        char ____fmt[] = fmt;                                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
#else
#define LOG_DEBUG(fmt, ...) \
    ({})
#endif

#define INCR_U32_TO_U64_MAP_VALUE(map, key) ({      \
    __u32 _key = key;                               \
    __u64 *_val = bpf_map_lookup_elem(&map, &_key); \
    if (_val != NULL)                               \
        __sync_fetch_and_add(_val, 1);              \
})

#define BE32_TO_IPV4(ip_value) ({           \
    be32_to_ipv4((ip_value), (char[32]){}); \
})

#define ENSURE_BOUND_OR_GOTO(ctx, data, label) ({         \
    if ((void *)(data + 1) > (void *)(long)ctx->data_end) \
    {                                                     \
        goto label;                                       \
    }                                                     \
})

#define GET_DATA_PTR_OFFSET(ctx, ptr) ((void *)ptr - (void *)(long)ctx->data)

#define GET_IP_HEADER_OR_GOTO(ctx, iph, label) ({ \
    void *_data = (void *)(long)ctx->data;        \
    if (BUILD_TARGET_IFACE_LAYER == 2)            \
    {                                             \
        struct ethhdr *_eth = _data;              \
        ENSURE_BOUND_OR_GOTO(ctx, _eth, label);   \
        if (_eth->h_proto != ETH_P_IP)            \
            goto label;                           \
        iph = (void *)(_eth + 1);                 \
    }                                             \
    else                                          \
    {                                             \
        iph = (void *)(_data);                    \
    }                                             \
    ENSURE_BOUND_OR_GOTO(ctx, iph, label);        \
})

// https://github.com/facebookincubator/katran/blob/main/katran/lib/bpf/csum_helpers.h
// __attribute__((__always_inline__)) static inline void ipv4_csum_inline(
//     void *iph,
//     __u64 *csum)
// {
//     __u16 *next_iph_u16 = (__u16 *)iph;
// #pragma clang loop unroll(full)
//     for (int i = 0; i < sizeof(struct iphdr) >> 1; i++)
//     {
//         *csum += *next_iph_u16++;
//     }
//     *csum = csum_fold_helper(*csum);
// }

// Ref: https://github.com/zebaz/xpress-dns/blob/master/src/xdp_dns_kern.c
// Update IP checksum for IP header, as specified in RFC 1071
// The checksum_location is passed as a pointer. At this location 16 bits need to be set to 0.
static inline void update_ip_checksum(void *data, int len, uint16_t *checksum_location)
{
    uint32_t accumulator = 0;
    int i;
    for (i = 0; i < len; i += 2)
    {
        uint16_t val;
        // If we are currently at the checksum_location, set to zero
        if (data + i == checksum_location)
        {
            val = 0;
        }
        else
        {
            // Else we load two bytes of data into val
            val = *(uint16_t *)(data + i);
        }
        accumulator += val;
    }

    // Add 16 bits overflow back to accumulator (if necessary)
    uint16_t overflow = accumulator >> 16;
    accumulator &= 0x00FFFF;
    accumulator += overflow;

    // If this resulted in an overflow again, do the same (if necessary)
    accumulator += (accumulator >> 16);
    accumulator &= 0x00FFFF;

    // Invert bits and set the checksum at checksum_location
    uint16_t chk = accumulator ^ 0xFFFF;

    *checksum_location = chk;
}

static inline int update_checksum_after_ip_nat(struct __sk_buff *skb, struct iphdr *iph, __u32 from_addr, __u32 to_addr)
{
    int ret = 0;
    // L3 checksum
    __wsum csum_inner_ip = bpf_csum_diff(0, 0, (void *)iph, SIZE_OF_IP_HEADER, 0);
    ret |= bpf_l3_csum_replace(skb, GET_DATA_PTR_OFFSET(skb, iph) + offsetof(struct iphdr, check), 0, csum_inner_ip, 0);

    /* If the IPs have changed we must replace it as part of the pseudo header that is used to calculate L4 csum */
    // __wsum csum_l4_diff = bpf_csum_diff(&from_addr, sizeof(from_addr), &to_addr, sizeof(to_addr), 0);
    GET_IP_HEADER_OR_GOTO(skb, iph, _return);

    __u32 l4_csum_skb_offset = 0;
    __u64 csum_update_flags = 0;
    if (iph->protocol == IPPROTO_UDP)
    {
        l4_csum_skb_offset = GET_DATA_PTR_OFFSET(skb, iph) + SIZE_OF_IP_HEADER + offsetof(struct udphdr, check);
        csum_update_flags |= BPF_F_MARK_MANGLED_0; // a null checksum is left untouched for UDP
    }
    else if (iph->protocol == IPPROTO_TCP)
    {
        l4_csum_skb_offset = GET_DATA_PTR_OFFSET(skb, iph) + SIZE_OF_IP_HEADER + offsetof(struct tcphdr, check);
    }
   
    if (l4_csum_skb_offset)
    {
        // LOG_DEBUG("l4 csum update: offset:%d | %s -> %s\n", l4_csum_skb_offset, BE32_TO_IPV4(from_addr), BE32_TO_IPV4(to_addr));
        ret |= bpf_l4_csum_replace(skb, l4_csum_skb_offset, from_addr, to_addr, csum_update_flags | BPF_F_PSEUDO_HDR | 4);
    }

_return:
    return ret;
}