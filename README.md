# Whistler

A Lisp compiling to eBPF.

Whistler is a Common Lisp dialect for writing eBPF programs. It compiles
s-expressions to eBPF bytecode and emits valid ELF object files your kernel
loads directly. The compilation pipeline has zero dependency on C, clang,
or LLVM.

```lisp
(defmap pkt-count :type :array
  :key-size 4 :value-size 8 :max-entries 1)

(defprog count-packets (:type :xdp :license "GPL")
  (incf (getmap pkt-count 0))
  XDP_PASS)
```

This compiles to 11 eBPF instructions and a valid BPF ELF object file.

## Why Whistler

eBPF programs are small, verifier-constrained, and pattern-driven. Whistler
is built for that shape:

- **No C toolchain.** The compiler is self-contained Common Lisp (~7,000 lines).
  No LLVM, no kernel headers, no libelf. The ELF writer is hand-rolled.
- **Real metaprogramming.** eBPF code is full of recurring patterns: parse
  headers, validate packet bounds, look up state. In Whistler, those become
  hygienic macros instead of preprocessor tricks.
- **Compiler-aware abstractions.** Struct accessors, protocol helpers, and map
  operations are part of the language, so the compiler optimizes them
  intentionally rather than recovering patterns after C lowering.
- **Automatic CO-RE.** Struct identity is preserved through the pipeline. CO-RE
  relocations are emitted automatically.
- **Interactive development.** Full REPL. Compile, load, attach, inspect maps,
  iterate — all from one Lisp image.

If you already have a C/libbpf workflow, Whistler is not trying to replace
it wholesale. It targets cases where you want a language and compiler designed
around eBPF itself.

### Side-by-side

| | Whistler | C + clang | BCC (Python) | Aya (Rust) | bpftrace |
|---|---|---|---|---|---|
| Toolchain size | ~3 MB (SBCL) | ~200 MB | ~100 MB | ~500 MB | ~50 MB |
| Compile-time metaprogramming | Full CL macros | `#define` | Python strings | `proc_macro` | none |
| Output | ELF .o | ELF .o | JIT loaded | ELF .o | JIT loaded |
| Self-contained compiler | yes | no (needs LLVM) | no (needs kernel headers) | no (needs LLVM) | no |
| Interactive development | REPL | no | yes | no | yes |
| Code quality vs clang -O2 | matches or beats | baseline | n/a | comparable | n/a |

## Getting started

### Requirements

- [SBCL](http://www.sbcl.org/) (Steel Bank Common Lisp) 2.0+
- Linux with kernel 5.3+ (for bounded loop support)
- [FiveAM](https://github.com/lispci/fiveam) (for tests only)

### Build

```sh
make        # build standalone binary
make test   # run test suite (requires FiveAM)
make repl   # interactive REPL with Whistler loaded
```

### Compile an example

```sh
# Using the REPL:
make repl
* (load "examples/synflood-xdp.lisp")
* (compile-to-elf "synflood.bpf.o")
Compiled 1 program (74 instructions total), 2 maps → synflood.bpf.o

# Or from the command line:
./whistler compile examples/count-xdp.lisp -o count.bpf.o
```

### Load into the kernel

```sh
ip link set dev eth0 xdp obj count.bpf.o sec xdp
bpftool map dump name pkt_count
ip link set dev eth0 xdp off
```

### Permissions

```sh
# Allow BPF program loading and perf event attachment
sudo setcap cap_bpf,cap_perfmon+ep /usr/bin/sbcl

# Allow reading tracepoint format files (for deftracepoint)
sudo chmod a+r /sys/kernel/tracing/events/sched/sched_switch/format
```

### Generate userspace headers

Whistler generates matching struct definitions for your userland code from
the same `defstruct` declarations used in the BPF program:

```sh
./whistler compile probes.lisp --gen c        # C header
./whistler compile probes.lisp --gen c go rust python lisp  # multiple
./whistler compile probes.lisp --gen all      # all supported
```

## Examples

### Packet counter

Whistler: 11 instructions. clang -O2: 11 instructions.

<table>
<tr><th>Whistler</th><th>C + clang</th></tr>
<tr><td valign="top">

```lisp
(defmap pkt-count :type :array
  :key-size 4 :value-size 8
  :max-entries 1)

(defprog count-packets
    (:type :xdp :license "GPL")
  (incf (getmap pkt-count 0))
  XDP_PASS)
```

</td><td valign="top">

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 1);
} pkt_count SEC(".maps");

SEC("xdp")
int count_packets(struct xdp_md *ctx) {
  __u32 key = 0;
  __u64 *val = bpf_map_lookup_elem(
                 &pkt_count, &key);
  if (val)
    __sync_fetch_and_add(val, 1);
  return XDP_PASS;
}
```

</td></tr>
</table>

### Port blocker

Whistler: 25 instructions. clang -O2: 26 instructions.

<table>
<tr><th>Whistler</th><th>C + clang</th></tr>
<tr><td valign="top">

```lisp
(defmap drop-count :type :array
  :key-size 4 :value-size 8
  :max-entries 1)

(defprog drop-port
    (:type :xdp :license "GPL")
  (with-tcp (data data-end tcp)
    (when (= (tcp-dst-port tcp) 9999)
      (incf (getmap drop-count 0))
      (return XDP_DROP)))
  XDP_PASS)
```

</td><td valign="top">

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 1);
} drop_count SEC(".maps");

SEC("xdp")
int drop_port(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *end  = (void *)(long)ctx->data_end;
  if (data + sizeof(struct ethhdr)
      + sizeof(struct iphdr)
      + sizeof(struct tcphdr) > end)
    return XDP_PASS;
  struct ethhdr *eth = data;
  if (eth->h_proto != htons(ETH_P_IP))
    return XDP_PASS;
  struct iphdr *ip = data + sizeof(*eth);
  if (ip->protocol != IPPROTO_TCP)
    return XDP_PASS;
  struct tcphdr *tcp = (void *)ip
                       + sizeof(*ip);
  if (ntohs(tcp->dest) == 9999) {
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(
                   &drop_count, &key);
    if (val)
      __sync_fetch_and_add(val, 1);
    return XDP_DROP;
  }
  return XDP_PASS;
}
```

</td></tr>
</table>

### SYN flood mitigation

Whistler: 65 instructions. clang -O2: 68 instructions.

<table>
<tr><th>Whistler</th><th>C + clang</th></tr>
<tr><td valign="top">

```lisp
(defmap syn-counter :type :hash
  :key-size 4 :value-size 8
  :max-entries 32768)
(defmap syn-stats :type :array
  :key-size 4 :value-size 8
  :max-entries 3)

(defconstant +syn-threshold+ 100)

(defprog synflood
    (:type :xdp :license "GPL")
  (with-tcp (data data-end tcp)
    (when (= (logand (tcp-flags tcp)
                     #x12)
             +tcp-syn+)
      (incf (getmap syn-stats 0))
      (let ((src (ipv4-src-addr
                   (+ data
                      +eth-hdr-len+))))
        (if-let (p (map-lookup
                     syn-counter src))
          (if (> (load u64 p 0)
                 +syn-threshold+)
            (progn
              (incf (getmap syn-stats 1))
              (return XDP_DROP))
            (atomic-add p 0 1))
          (progn
            (incf (getmap syn-stats 2))
            (setf (getmap syn-counter
                          src) 1))))))
  XDP_PASS)
```

</td><td valign="top">

```c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "GPL";

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

static void bump_stat(void *map, __u32 idx) {
  __u64 *val = bpf_map_lookup_elem(
                 map, &idx);
  if (val)
    __sync_fetch_and_add(val, 1);
}

#define SYN_THRESHOLD 100
#define TCP_SYN 0x02
#define TCP_ACK 0x10

SEC("xdp")
int synflood(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *end  = (void *)(long)ctx->data_end;
  if (data + sizeof(struct ethhdr)
      + sizeof(struct iphdr)
      + sizeof(struct tcphdr) > end)
    return XDP_PASS;
  struct ethhdr *eth = data;
  if (eth->h_proto != htons(ETH_P_IP))
    return XDP_PASS;
  struct iphdr *ip = data + sizeof(*eth);
  if (ip->protocol != IPPROTO_TCP)
    return XDP_PASS;
  struct tcphdr *tcp = (void *)ip
                       + sizeof(*ip);
  __u8 flags = ((__u8 *)tcp)[13];
  if (!(flags & TCP_SYN)
      || (flags & TCP_ACK))
    return XDP_PASS;

  bump_stat(&syn_stats, 0);

  __u32 src = ip->saddr;
  __u64 *count = bpf_map_lookup_elem(
                   &syn_counter, &src);
  if (count) {
    if (*count > SYN_THRESHOLD) {
      bump_stat(&syn_stats, 1);
      return XDP_DROP;
    }
    __sync_fetch_and_add(count, 1);
  } else {
    bump_stat(&syn_stats, 2);
    __u64 init = 1;
    bpf_map_update_elem(&syn_counter,
      &src, &init, BPF_ANY);
  }
  return XDP_PASS;
}
```

</td></tr>
</table>

## Userspace loader

`whistler/loader` is a pure Common Lisp BPF loader — no libbpf, no CFFI.
It loads `.bpf.o` files, creates maps, attaches probes, and consumes ring
buffers from SBCL.

### Inline BPF sessions

Write BPF programs and userspace code in the same Lisp form. The BPF code
compiles at macroexpand time, and the bytecode is embedded as a literal:

```lisp
(whistler/loader:with-bpf-session ()
  ;; Kernel side, compiled to eBPF at macroexpand time
  (bpf:map counter :type :hash :key-size 4 :value-size 8 :max-entries 1024)
  (bpf:prog trace (:type :kprobe :section "kprobe/__x64_sys_execve" :license "GPL")
    (incf (getmap counter 0))
    0)

  ;; Userspace side, normal CL at runtime
  (bpf:attach trace "__x64_sys_execve")
  (loop (sleep 1)
        (format t "count: ~d~%" (bpf:map-ref counter 0))))
```

One file, one language. No intermediate artifacts or separate build steps.

## Documentation

The full language reference, compilation model, and API details are in
[doc/MANUAL.md](doc/MANUAL.md).

## Author

Whistler was created by [Anthony Green](https://github.com/atgreen).

## License

MIT

The compiler itself is MIT-licensed. BPF programs compiled by Whistler
typically use `license "GPL"` in their `defprog` because the kernel requires
GPL for BPF programs calling GPL-only helpers.
