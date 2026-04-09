# Tail Calls

BPF tail calls transfer execution from one BPF program to another using
a program array map. The call is a zero-cost jump -- no stack frame is
pushed, and the callee inherits the caller's context.

## Syntax

```lisp
(tail-call prog-array-map index)
```

`prog-array-map` must be a map declared with `:type :prog-array`. The
`index` is evaluated at runtime and used to look up a program file
descriptor in the map.

If no program is loaded at the given index, or the index is out of
range, execution **falls through** to the next instruction. This is not
an error -- it is the standard BPF tail call contract.

## Example: protocol dispatch

```lisp
;; Jump table: protocol number -> program FD
(defmap jt :type :prog-array
  :key-size 4 :value-size 4 :max-entries 256)

(defmap proto-stats :type :array
  :key-size 4 :value-size 8 :max-entries 3)

(defconstant +stat-dispatched+ 0)

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
      ;; Tail call into protocol-specific handler.
      ;; Falls through to XDP_PASS if no handler is loaded.
      (tail-call jt proto)))
  XDP_PASS)
```

At load time, populate the jump table with program file descriptors:

```sh
bpftool map update name jt key 6 0 0 0 value pinned /sys/fs/bpf/tcp_handler
bpftool map update name jt key 17 0 0 0 value pinned /sys/fs/bpf/udp_handler
```

## Notes

- The map must be `:type :prog-array`. Using another map type is a
  compile error.
- The BPF verifier limits tail call depth (typically 33).
- Tail calls and normal calls share the same stack, so deeply nested
  tail calls may hit the 512-byte stack limit.
