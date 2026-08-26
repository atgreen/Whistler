// ratelimit-xdp.c — Equivalent of ratelimit-xdp.lisp in C
//
// Per-source-IP rate limiter: parse eth+ipv4, count per-IP in a hash map,
// drop over threshold. Kept equivalent to ratelimit-xdp.lisp for `make bench`:
// single 34-byte bounds check, ethertype check (no protocol check), raw src IP
// hash key, array stats bumps, same known-vs-new-IP branch structure.
// Compile: clang -O2 -target bpf -c ratelimit-xdp.c -o ratelimit-xdp-c.bpf.o

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 65536);
} ip_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} stats SEC(".maps");

#define DROP_THRESHOLD 1000

static __always_inline void bump_stat(__u32 idx) {
    __u64 *p = bpf_map_lookup_elem(&stats, &idx);
    if (p) __sync_fetch_and_add(p, 1);
}

SEC("xdp")
int ratelimit(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 34 > data_end) return XDP_PASS;
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;
    struct iphdr *ip = (void *)(eth + 1);

    bump_stat(0);
    __u32 src = ip->saddr;
    __u64 *cnt = bpf_map_lookup_elem(&ip_counter, &src);
    if (cnt) {
        if (*cnt > DROP_THRESHOLD) {
            bump_stat(1);
            return XDP_DROP;
        }
        __sync_fetch_and_add(cnt, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&ip_counter, &src, &one, BPF_ANY);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
