// count-xdp.c — Equivalent of count-xdp.lisp in C
//
// Counts every packet passing through an interface using a BPF array map.
// Compile: clang -O2 -target bpf -c count-xdp.c -o count-xdp-c.bpf.o

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_count SEC(".maps");

SEC("xdp")
int count_packets(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&pkt_count, &key);

    if (val)
        __sync_fetch_and_add(val, 1);
    else {
        __u64 init = 1;
        bpf_map_update_elem(&pkt_count, &key, &init, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
