// tail-call-dispatch.c — Equivalent of tail-call-dispatch.lisp (dispatcher) in C
//
// Reads the IP protocol and tail-calls into a per-protocol handler via a
// prog-array. Kept equivalent to the .lisp dispatcher for `make bench`:
// single data+34 bounds check, ethertype check, dispatched-counter bump,
// tail_call, fall-through XDP_PASS. Handlers are loaded separately (not part
// of this program's instruction count).
// Compile: clang -O2 -target bpf -c tail-call-dispatch.c -o tail-call-dispatch-c.bpf.o

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 256);
} jt SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 3);
} proto_stats SEC(".maps");

SEC("xdp")
int xdp_dispatch(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + 34 > data_end)
        return XDP_PASS;
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    struct iphdr *ip = (void *)(eth + 1);
    __u32 proto = ip->protocol;

    __u32 key = 0;
    __u64 *s = bpf_map_lookup_elem(&proto_stats, &key);
    if (s)
        __sync_fetch_and_add(s, 1);

    bpf_tail_call(ctx, &jt, proto);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
