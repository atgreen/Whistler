# XDP Tail Call Dispatch

Use a `prog-array` map to dispatch XDP processing to per-protocol handler
programs via tail calls.

## BPF programs

```lisp
(in-package #:whistler)

;;; Jump table: protocol number -> program FD
(defmap jt :type :prog-array
  :key-size 4 :value-size 4 :max-entries 256)

;;; Per-protocol counters
(defmap proto-stats :type :array
  :key-size 4 :value-size 8 :max-entries 3)

(defconstant +stat-dispatched+ 0)
(defconstant +stat-tcp+ 1)
(defconstant +stat-udp+ 2)

;;; Dispatcher -- entry point
(defprog xdp-dispatch (:type :xdp :section "xdp" :license "GPL")
  (let ((data     (xdp-data))
        (data-end (xdp-data-end)))
    (when (> (+ data 34) data-end)
      (return XDP_PASS))
    (when (/= (eth-type data) +ethertype-ipv4+)
      (return XDP_PASS))
    (let ((proto (ipv4-protocol (+ data +eth-hdr-len+))))
      (declare (type u32 proto))
      (incf (getmap proto-stats +stat-dispatched+))
      (tail-call jt proto)))
  XDP_PASS)

;;; TCP handler (separate program, same ELF)
(defprog tcp-handler (:type :xdp :section "xdp/tcp" :license "GPL")
  (incf (getmap proto-stats +stat-tcp+))
  XDP_PASS)

;;; UDP handler (separate program, same ELF)
(defprog udp-handler (:type :xdp :section "xdp/udp" :license "GPL")
  (incf (getmap proto-stats +stat-udp+))
  XDP_PASS)

(compile-to-elf "tail-call-dispatch.bpf.o")
```

## Loading and wiring

After compilation, load all programs and populate the jump table:

```bash
# Load all programs from the multi-program ELF
bpftool prog loadall tail-call-dispatch.bpf.o /sys/fs/bpf/tcd

# Wire protocol handlers into the jump table
bpftool map update name jt \
  key 6 0 0 0 value pinned /sys/fs/bpf/tcd/tcp_handler
bpftool map update name jt \
  key 17 0 0 0 value pinned /sys/fs/bpf/tcd/udp_handler

# Attach the dispatcher to a network interface
ip link set dev eth0 xdp pinned /sys/fs/bpf/tcd/xdp_dispatch
```

## Key points

- **Multi-program ELF**: Each `defprog` with a distinct `:section` name
  produces a separate program section in the ELF. Use `bpftool prog
  loadall` to load them all and pin each to bpffs.

- **Tail-call semantics**: `(tail-call jt proto)` compiles to the
  `BPF_TAIL_CALL` helper. If the key exists in the prog-array, execution
  transfers to that program with the same context and no return. If the
  key is missing (no handler loaded), execution falls through to the
  next instruction -- here, `XDP_PASS`.

- **Shared maps**: All programs in the same ELF share map definitions.
  The `proto-stats` array is accessible from both the dispatcher and the
  handlers.

- **bpftool population**: `prog-array` maps cannot be populated from BPF
  code. Insert program FDs from userspace using bpftool or the loader's
  `map-update`.
