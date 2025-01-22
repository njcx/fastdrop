//go:build ignore
#include "common.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define DEBUG 1
#ifdef DEBUG
#define bpf_debug(fmt, ...) \
    bpf_trace_printk(fmt, sizeof(fmt), ##__VA_ARGS__)
#else
#define bpf_debug(fmt, ...)
#endif

#define CHECK(data, data_end, ptr, size) \
    if ((void *)(ptr) + (size) > (void *)(data_end)) return XDP_PASS;

struct ip_port_key {
    __u32 ip;
    __u16 port;
};

struct bpf_map_def SEC("maps") drop_ips_ports = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(struct ip_port_key),
        .value_size = sizeof(__u32),
        .max_entries = 1024,
};

static __always_inline int process_l4(struct iphdr *ip, void *data_end,
                                      struct ip_port_key *key) {
    struct tcphdr *tcp;
    struct udphdr *udp;
    void *l4_hdr = (void *)ip + (ip->ihl * 4);

    if (l4_hdr + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;

    if (ip->protocol == IPPROTO_TCP) {
        tcp = (struct tcphdr *)l4_hdr;
        key->port = bpf_ntohs(tcp->dest);
        bpf_debug("TCP Port: %d", key->port);
    } else if (ip->protocol == IPPROTO_UDP) {
        udp = (struct udphdr *)l4_hdr;
        key->port = bpf_ntohs(udp->dest);
        bpf_debug("UDP Port: %d", key->port);
    } else {
        bpf_debug("Not TCP/UDP", 0);
        return -1;
    }

    return 0;
}

static __always_inline void debug_print_ip(__u32 ip)
{
    unsigned char bytes[4];
    bytes[0] = (ip >> 24) & 0xFF;
    bytes[1] = (ip >> 16) & 0xFF;
    bytes[2] = (ip >> 8) & 0xFF;
    bytes[3] = ip & 0xFF;
    bpf_debug("IP: %d.%d", bytes[0], bytes[1]);
    bpf_debug(".%d.%d", bytes[2], bytes[3]);
    bpf_debug("IPX (0x%x)\n", ip);
    bpf_debug("IP: %u\n", ip);

}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    __u32 *drop_flag;
    struct ip_port_key key = {};

    CHECK(data, data_end, eth, sizeof(*eth));
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    ip = (struct iphdr *)(eth + 1);
    CHECK(data, data_end, ip, sizeof(*ip));

    if (ip->version != 4)
        return XDP_PASS;

    if (ip->ihl < 5 || ip->ihl > 15)
        return XDP_PASS;

    if ((void *)ip + (ip->ihl * 4) > data_end)
        return XDP_PASS;


    bpf_debug("Source ");
    debug_print_ip(bpf_ntohl(ip->saddr));
    bpf_debug("Destination ");
    debug_print_ip(bpf_ntohl(ip->daddr));

    key.ip = bpf_ntohl(ip->saddr);
    key.port = 0;

    drop_flag = bpf_map_lookup_elem(&drop_ips_ports, &key);
    if (drop_flag && *drop_flag == 1) {
        return XDP_DROP;
    }

    if (process_l4(ip, data_end, &key) == 0) {
        drop_flag = bpf_map_lookup_elem(&drop_ips_ports, &key);
        if (drop_flag && *drop_flag == 1) {
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";