// drop-port.c — Equivalent of drop-port.lisp in C
//
// Drops TCP packets destined for port 9999. Kept semantically equivalent to
// drop-port.lisp for `make bench`: a single bounds check over the fixed
// eth+ipv4+tcp header chain (no IP options), matching with-tcp's flat
// guard-style parse. Port compares against bpf_htons(9999) so, like
// Whistler's net-order accessor + bswap-compare folding, no runtime swap.
// Compile: clang -O2 -target bpf -c drop-port.c -o drop-port-c.bpf.o

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} drop_count SEC(".maps");

#define BLOCKED_PORT 9999

SEC("xdp")
int drop_port(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)(eth + 1);
    struct tcphdr *tcp = (void *)(ip + 1);

    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
    if (tcp->dest == bpf_htons(BLOCKED_PORT)) {
        __u32 key = 0;
        __u64 *val = bpf_map_lookup_elem(&drop_count, &key);
        if (val)
            __sync_fetch_and_add(val, 1);
        return XDP_DROP;
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
