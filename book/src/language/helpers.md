# BPF Helpers

BPF helper functions are kernel-provided routines callable from BPF
programs. In Whistler, call them by name in function position.
Arguments are passed in registers R1--R5 and the return value is in R0.

```lisp
(get-current-pid-tgid)                      ; 0 args
(probe-read-user dst size src)              ; 3 args
(get-current-comm buf-ptr buf-size)         ; 2 args
(ringbuf-reserve map-name size flags)       ; 3 args (special: map arg)
```

The compiler validates argument counts at compile time.

## Available helpers

| Helper | ID | Args | Description |
|--------|----|------|-------------|
| `map-lookup-elem` | 1 | -- | (use `map-lookup` instead) |
| `map-update-elem` | 2 | -- | (use `map-update` instead) |
| `map-delete-elem` | 3 | -- | (use `map-delete` instead) |
| `probe-read` | 4 | 3 | Read kernel memory (legacy) |
| `ktime-get-ns` | 5 | 0 | Monotonic clock, nanoseconds |
| `trace-printk` | 6 | 3 | Debug printf to trace_pipe |
| `get-prandom-u32` | 7 | 0 | Pseudo-random u32 |
| `get-smp-processor-id` | 8 | 0 | Current CPU number |
| `tail-call` | 12 | -- | (use the `tail-call` form instead) |
| `get-current-pid-tgid` | 14 | 0 | PID in low 32, TGID in high 32 |
| `get-current-uid-gid` | 15 | 0 | UID in low 32, GID in high 32 |
| `get-current-comm` | 16 | 2 | Copy task comm to buffer |
| `redirect` | 23 | 2 | Redirect packet to ifindex |
| `perf-event-output` | 25 | 3 | Send data via perf event |
| `skb-load-bytes` | 26 | 3 | Load bytes from skb |
| `get-current-task` | 35 | 0 | Pointer to current task_struct |
| `probe-read-str` | 45 | 3 | Read kernel string |
| `get-socket-cookie` | 47 | 1 | Socket cookie for tracking |
| `get-current-cgroup-id` | 80 | 0 | Current cgroup v2 ID |
| `probe-read-user` | 112 | 3 | Read user-space memory |
| `probe-read-kernel` | 113 | 3 | Read kernel memory (modern) |
| `probe-read-user-str` | 114 | 3 | Read user-space string |
| `ringbuf-output` | 130 | 4 | Copy data to ring buffer |
| `ringbuf-reserve` | 131 | 3 | Reserve ring buffer space |
| `ringbuf-submit` | 132 | 2 | Submit ring buffer entry |
| `ringbuf-discard` | 133 | 2 | Discard ring buffer entry |
| `get-current-task-btf` | 159 | 0 | Current task_struct (BTF-aware) |
| `ktime-get-coarse-ns` | 161 | 0 | Coarse monotonic clock |

Map helpers (1--3) and `tail-call` (12) are called through dedicated
Whistler forms rather than by name. The table lists them for
completeness.

## Example

```lisp
(defprog trace-fork (:type :tracepoint
                     :section "tracepoint/sched/sched_process_fork"
                     :license "GPL")
  (let ((tgid (get-current-pid-tgid))
        (pid  (cast u32 (>> tgid 32)))
        (ts   (ktime-get-ns)))
    (setf (getmap fork-times pid) ts))
  0)
```
