// synflood-xdp.c — Equivalent of synflood-xdp.lisp in C
//
// Tracks SYN packets per source IP; drops sources over the threshold.
// Kept semantically equivalent to synflood-xdp.lisp for `make bench`:
// single bounds check over the fixed 54-byte header chain, SYN detection
// via (flags & 0x12) == 0x02, raw (non-swapped) src IP as the hash key,
// and the same stat bumps / known-vs-new-IP branch structure.
// Compile: clang -O2 -target bpf -c synflood-xdp.c -o synflood-xdp-c.bpf.o

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 32768);
} syn_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 3);
} syn_stats SEC(".maps");

#define SYN_THRESHOLD 100

static __always_inline void bump_stat(__u32 idx)
{
    __u64 *p = bpf_map_lookup_elem(&syn_stats, &idx);
    if (p)
        __sync_fetch_and_add(p, 1);
}

SEC("xdp")
int synflood(struct xdp_md *ctx)
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

    __u8 flags = ((__u8 *)tcp)[13];
    if ((flags & 0x12) == 0x02) {
        bump_stat(0);
        __u32 src = ip->saddr;
        __u64 *cnt = bpf_map_lookup_elem(&syn_counter, &src);
        if (cnt) {
            if (*cnt > SYN_THRESHOLD) {
                bump_stat(1);
                return XDP_DROP;
            }
            __sync_fetch_and_add(cnt, 1);
        } else {
            bump_stat(2);
            __u64 one = 1;
            bpf_map_update_elem(&syn_counter, &src, &one, BPF_ANY);
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
