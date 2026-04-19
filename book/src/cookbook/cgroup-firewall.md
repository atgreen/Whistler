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

`ctx` is a setf-able place for BPF context struct fields. Reading uses
`(ctx TYPE OFFSET)`, writing uses `(setf (ctx TYPE OFFSET) VALUE)`.
This is what makes transparent proxying work -- the application thinks
it's connecting to the original destination, but the kernel sends the
traffic to localhost:

```lisp
;; Read the original destination
(let ((user-ip4 (ctx u32 +sock-addr-user-ip4+)))
  ;; Redirect to localhost proxy
  (setf (ctx u32 +sock-addr-user-ip4+) +localhost-nbo+)
  (setf (ctx u32 +sock-addr-user-port+) (htons 8080)))
```

### Structured events via ring buffer

Every firewall decision is reported to userspace with full context --
PID, original and redirected IPs, port, event type, and DNS transaction
ID:

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

(with-ringbuf (evt events (sizeof event))
  (setf (event-pid evt) pid
        (event-port evt) (ntohs port)
        (event-allowed evt) 1
        (event-ip evt) (ntohl daddr)
        (event-event-type evt) +http-redirect+))
```

### Packet parsing with skb-load-bytes

The egress program reads IP, TCP, and UDP headers from the packet
buffer to extract protocol and port information:

```lisp
(let* ((iph (make-event))  ; reuse struct as scratch buffer
       (rc (skb-load-bytes (ctx-ptr) 0 iph +iph-size+)))
  (when (s< rc 0)
    (return +egress-deny+))
  (let* ((protocol (load u8 iph +iph-protocol+))
         (daddr    (load u32 iph +iph-daddr+)))
    ...))
```

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
  via `(ctx TYPE OFFSET)`. `cgroup/connect4` *writes* via
  `(setf (ctx ...) ...)` to `user_ip4` and `user_port`, redirecting
  connections -- this is what makes it a transparent proxy rather than
  just an observer.

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
| Events | Manual struct packing | `defstruct` + `with-ringbuf` |
| Multi-prog | Separate C files or sections | Single `.lisp` file |
