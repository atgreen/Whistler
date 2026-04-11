# defprog

`defprog` defines a BPF program. Each `defprog` form compiles into one
program section in the output ELF object.

## Syntax

```lisp
(defprog name (:type :xdp :section nil :license "GPL")
  body...)
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `name` | -- | Symbol naming the program |
| `:type` | `:xdp` | BPF program type |
| `:section` | `nil` | ELF section name (defaults to lowercase type) |
| `:license` | `"GPL"` | License string embedded in the ELF |

## Program Types

| Keyword | BPF Program Type | Context Argument |
|---------|-----------------|------------------|
| `:xdp` | `BPF_PROG_TYPE_XDP` | `xdp_md` pointer |
| `:socket-filter` | `BPF_PROG_TYPE_SOCKET_FILTER` | `__sk_buff` pointer |
| `:tracepoint` | `BPF_PROG_TYPE_TRACEPOINT` | Tracepoint args pointer |
| `:kprobe` | `BPF_PROG_TYPE_KPROBE` | `pt_regs` pointer |
| `:cgroup-skb` | `BPF_PROG_TYPE_CGROUP_SKB` | `__sk_buff` pointer |
| `:cgroup-sock` | `BPF_PROG_TYPE_CGROUP_SOCK` | `bpf_sock` pointer |
| `:cgroup-sock-addr` | `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` | `bpf_sock_addr` pointer |

## Return Value

The last expression in the body is implicitly returned as the program's
return code. There is no explicit `return` form. For XDP programs, this is
typically an XDP action constant:

```lisp
(defprog drop-all (:type :xdp)
  XDP_DROP)
```

## Section Names

The ELF section name defaults to the lowercase string form of the program
type. For example, a `:kprobe` program gets the section name `"kprobe"`. To
override this -- for instance, to attach to a specific kernel function --
pass `:section` explicitly:

```lisp
(defprog trace-exec (:type :kprobe :section "kprobe/sys_execve")
  0)
```

## License

The `:license` parameter controls the license string embedded in the ELF.
It defaults to `"GPL"`. Some BPF helper functions are restricted to
GPL-licensed programs. If you set a non-GPL license, calls to GPL-only
helpers will be rejected by the kernel verifier at load time.

## Multiple Programs

Multiple `defprog` forms in the same source file compile into a single ELF
object, each in its own section. This is useful for tail call dispatch or
for bundling related programs:

```lisp
(defmap dispatch :type :prog-array
  :key-size 4
  :value-size 4
  :max-entries 4)

(defprog handler-a (:type :xdp :section "xdp/handler_a")
  ;; Handle protocol A
  XDP_PASS)

(defprog handler-b (:type :xdp :section "xdp/handler_b")
  ;; Handle protocol B
  XDP_DROP)

(defprog main (:type :xdp)
  ;; Dispatch to sub-programs via tail call
  (tail-call dispatch 0)
  XDP_PASS)
```

## Full Example

A minimal tracepoint program that records events to a ring buffer:

```lisp
(defstruct event
  (pid u32)
  (ts u64))

(defmap events :type :ringbuf
  :max-entries (* 256 1024))

(defprog trace-sched (:type :tracepoint
                      :section "tracepoint/sched/sched_process_exec")
  (with-ringbuf (e events (sizeof event))
    (setf (event-pid e) (get-current-pid-tgid)
          (event-ts e) (ktime-get-ns)))
  0)
```
