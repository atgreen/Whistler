# Cgroup Outbound Firewall

A process-level outbound firewall using three cooperating cgroup eBPF
programs. Reimplements
[ebpf-cgroup-firewall](https://github.com/lawrencegripper/ebpf-cgroup-firewall)
(originally Go + C) in Whistler.

## What it does

Traditional firewalls are IP-based and machine-wide. This firewall
attaches to a **cgroup**, so it targets a single process or group of
processes. It:

1. **Intercepts outbound connections** (`cgroup/connect4`) -- redirects
   DNS to a local proxy (for domain-level decisions) and HTTP/HTTPS to
   a transparent MITM proxy (for URL-level decisions).
2. **Tracks socket-to-port correlation** (`sockops`) -- maps source
   ports back to client socket cookies so egress can identify which
   connection a packet belongs to.
3. **Enforces firewall rules** (`cgroup_skb/egress`) -- checks every
   outbound packet against IP allowlists, emits events with PID, IP,
   port, and decision to a ring buffer for userspace logging.

## Architecture

```
                    ┌──────────────────────────────────────┐
                    │          Userspace Loader             │
                    │  (populates maps, reads ring buffer)  │
                    └──────────┬───────────────────────────┘
                               │ ring buffer events
          ┌────────────────────┼────────────────────────┐
          │                    │                         │
   ┌──────┴───────┐    ┌──────┴───────┐    ┌────────────┴──────┐
   │  connect4     │    │  sockops     │    │  cgroup_skb/egress │
   │ (sock_addr)   │    │ (sock_ops)   │    │  (skb filter)     │
   │               │    │              │    │                    │
   │ Redirect DNS, │    │ Track src    │    │ Check allowlists,  │
   │ HTTP, HTTPS   │    │ port→cookie  │    │ emit events,       │
   │ to proxies    │    │ on connect   │    │ allow/deny packets  │
   └───────────────┘    └──────────────┘    └────────────────────┘
          │                    │                         │
          └────────────────────┼────────────────────────┘
                               │
                          Shared Maps
               (socket-pid, original-ip/port,
                src-port→cookie, allowlists)
```

## BPF source

The complete source is in `examples/cgroup-firewall.lisp`. Key patterns
demonstrated:

### Multi-program coordination via shared maps

Seven maps connect the three programs. `connect4` stores original
destinations before redirecting; `sockops` stores port-to-cookie
mappings; `egress` reads both to reconstruct the full picture:

```lisp
;; socket cookie → original destination IP (before redirect)
(defmap sock-client-to-original-ip :type :hash
  :key-size 8 :value-size 4 :max-entries 262144
  :map-flags 1)  ; BPF_F_NO_PREALLOC

;; source port → client socket cookie (for proxy correlation)
(defmap src-port-to-sock-client :type :hash
  :key-size 2 :value-size 8 :max-entries 262144
  :map-flags 1)
```

### Setf-able context access for connection redirection

`ctx` is a setf-able place for BPF context struct fields. The compiler
resolves field names from the program type automatically — `(ctx
user-ip4)` instead of `(ctx u32 4)`. This is what makes transparent
proxying work -- the application thinks
it's connecting to the original destination, but the kernel sends the
traffic to localhost:

```lisp
;; Read the original destination
(let ((user-ip4 (ctx user-ip4)))
  ;; Redirect to localhost proxy
  (setf (ctx user-ip4) +localhost-nbo+)
  (setf (ctx user-port) (htons 8080)))
```

### Typed packet headers with defunion

Instead of raw `(load u8 buf 9)` with magic offsets, the example
defines proper header structs and a union for stack-efficient reuse:

```lisp
(defstruct ip-hdr
  (ver-ihl u8) (tos u8) (tot-len u16) (id u16) (frag-off u16)
  (ttl u8) (protocol u8) (check u16) (saddr u32) (daddr u32))

(defstruct udp-hdr
  (src-port u16) (dst-port u16) (length u16) (checksum u16))

(defstruct tcp-hdr
  (src-port u16) (dst-port u16) (seq u32) (ack-seq u32)
  (doff-flags u16) (window u16) (check u16) (urg-ptr u16))

;; Single stack allocation, accessed through any header's accessors
(defunion packet-buf ip-hdr udp-hdr tcp-hdr)
```

`defunion` allocates the size of the largest member. The returned
pointer works with any member's field accessors since all members
share offset 0:

```lisp
(let* ((pkt (make-packet-buf))
       (rc (skb-load-bytes (ctx-ptr) 0 pkt (sizeof ip-hdr))))
  (let ((protocol (ip-hdr-protocol pkt))   ; access as IP header
        (daddr    (ip-hdr-daddr pkt)))
    ;; Reuse buffer for transport header
    (skb-load-bytes (ctx-ptr) (sizeof ip-hdr) pkt (sizeof udp-hdr))
    (udp-hdr-dst-port pkt)))               ; access as UDP header
```

### Events via ringbuf-output

Every firewall decision is reported to userspace. The event struct is
built on the stack and copied to the ring buffer in a single helper
call:

```lisp
(defstruct event
  (pid         u32)
  (port        u16)
  (allowed     u8)
  (pad0        u8)
  (ip          u32)
  (original-ip u32)
  (event-type  u8)
  (pad1        u8)
  (dns-txid    u16)
  (pid-resolved u8)
  (redirected  u8)
  (pad2        u16))

(let ((evt (make-event)))
  (setf (event-pid evt) pid
        (event-port evt) (ntohs port)
        (event-allowed evt) 1
        (event-ip evt) (ntohl daddr)
        (event-event-type evt) +http-redirect+)
  (ringbuf-output events evt (sizeof event) 0))
```

This is more compact than `with-ringbuf` (which uses
reserve+field-stores+submit) and matches the pattern clang generates
from C's `bpf_ringbuf_output()`.

## Compiling

```bash
./whistler compile examples/cgroup-firewall.lisp -o firewall.bpf.o
```

This produces a single ELF with three program sections
(`cgroup/connect4`, `sockops`, `cgroup_skb/egress`) and seven shared
maps.

## Key points

- **Three program types**: This example uses `cgroup-sock-addr` (to
  modify connection destinations), `cgroup-sock` (to observe socket
  events), and `cgroup-skb` (to filter packets). Each has a different
  context struct with different available fields.

- **Setf-able context**: Most cgroup programs only read context fields
  via `(ctx field-name)`. `cgroup/connect4` *writes* via
  `(setf (ctx field-name) ...)` to `user-ip4` and `user-port`,
  redirecting connections -- this is what makes it a transparent proxy
  rather than just an observer.

- **Runtime constants**: The original Go implementation uses `.rodata`
  rewriting to set proxy ports, PID, and firewall mode at load time.
  The Whistler version uses placeholder values that should be set by
  the loader before attaching.

- **IPv6**: Not supported. IPv6 packets are blocked in egress and
  reported with event type `+packet-ipv6+`.

- **Return values**: `cgroup/connect4` always returns `1` (allow the
  connection -- enforcement happens in egress). `cgroup_skb/egress`
  returns `1` to allow or `0` to drop the packet.

## Comparison with the Go/C original

| Aspect | Go + cilium/ebpf | Whistler |
|--------|-----------------|----------|
| BPF source | 450 lines of C | 400 lines of Lisp |
| Userspace | 2000+ lines of Go | Loader TBD |
| Build | clang + bpf2go codegen | `./whistler compile` |
| Maps | C struct definitions | `defmap` declarations |
| Headers | C struct casts | `defstruct` + `defunion` |
| Events | `bpf_ringbuf_output` | `ringbuf-output` |
| Multi-prog | Separate C files or sections | Single `.lisp` file |
