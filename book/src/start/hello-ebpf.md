# Hello eBPF

This chapter walks through the simplest useful Whistler program: an XDP
packet counter.

## The program

Create a file `count-xdp.lisp`:

```lisp
(in-package #:whistler)

(defmap pkt-count :type :array
  :key-size 4 :value-size 8 :max-entries 1)

(defprog count-packets (:type :xdp :section "xdp" :license "GPL")
  (incf (getmap pkt-count 0))
  XDP_PASS)
```

This defines:

- **A BPF map** called `pkt-count`. It is an array with a single 64-bit entry,
  keyed by a 32-bit index.
- **A BPF program** called `count-packets`. It is an XDP program (attached to
  a network interface), placed in the ELF section `"xdp"`, and licensed as GPL
  (required for BPF programs that call GPL-only kernel helpers).

The program body does two things:

1. `(incf (getmap pkt-count 0))` -- look up key 0 in the map and atomically
   increment the value.
2. `XDP_PASS` -- return the XDP verdict that passes the packet through
   unchanged.

## Compiling

### From the REPL

```lisp
(require :asdf)
(push #p"/path/to/whistler/" asdf:*central-registry*)
(asdf:load-system "whistler")
(in-package #:whistler-user)

(load "count-xdp.lisp")
(compile-to-elf "count.bpf.o")
;; => Compiled 1 program (11 instructions total), 1 map -> count.bpf.o
```

### From the command line

```bash
./whistler compile count-xdp.lisp -o count.bpf.o
```

Either way, you get a standard BPF ELF object file that any BPF loader
can process.

## Loading and attaching

### With bpftool / ip

Attach the XDP program to a network interface:

```bash
sudo ip link set dev eth0 xdp obj count.bpf.o sec xdp
```

Read the counter:

```bash
sudo bpftool map dump name pkt_count
```

Detach when done:

```bash
sudo ip link set dev eth0 xdp off
```

### With the Whistler loader

You can skip the external tools entirely and do everything from the REPL
using `whistler/loader`:

```lisp
(asdf:load-system "whistler/loader")
(in-package #:whistler-loader-user)

(with-bpf-object (obj "count.bpf.o")
  (attach-obj-xdp obj "count_packets" "eth0")
  (let ((counter (bpf-object-map obj "pkt_count")))
  (loop repeat 5
        do (sleep 1)
           (format t "packets: ~d~%"
                   (or (map-lookup-int counter 0) 0)))))
```

### Inline session (no intermediate file)

The most Lisp-native approach compiles and loads in one form:

```lisp
(in-package #:whistler-loader-user)

(with-bpf-session ()
  (bpf:map pkt-count :type :array
    :key-size 4 :value-size 8 :max-entries 1)
  (bpf:prog count-packets (:type :xdp :section "xdp" :license "GPL")
    (incf (getmap pkt-count 0))
    XDP_PASS)

  (bpf:attach count-packets "eth0")
  (loop repeat 5
        do (sleep 1)
           (format t "packets: ~d~%" (bpf:map-ref pkt-count 0))))
```

The `bpf:` forms compile to eBPF at macroexpand time. The rest is ordinary
Common Lisp that runs at load time.

For interactive development, prefer this inline-session workflow. Use file
compilation when you specifically want a `.bpf.o` artifact.

## What the compiler produces

The 11-instruction output for this program:

1. Store key 0 to the stack.
2. Load the map file descriptor.
3. Call `bpf_map_lookup_elem`.
4. Check for null (verifier requires this).
5. Load the current value.
6. Add 1.
7. Store the new value (atomic).
8. Set return value to `XDP_PASS` (2).
9. Exit.

This matches the instruction count of the equivalent C program compiled with
`clang -O2`.
