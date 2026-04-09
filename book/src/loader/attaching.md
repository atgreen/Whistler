# Attaching Programs

After loading, programs must be attached to a kernel hook point. All
attachment functions return an `attachment` struct that can be passed to
`(detach att)` for cleanup.

## Kprobe

```lisp
(attach-kprobe prog-fd "function_name")
(attach-kprobe prog-fd "function_name" :retprobe t)
```

Attaches to a kernel function entry (or return) point via the kprobe PMU.

## Uprobe

```lisp
(attach-uprobe prog-fd "/path/to/binary" "symbol_name")
(attach-uprobe prog-fd "/path/to/binary" "symbol_name" :retprobe t)
```

Resolves the symbol to a file offset via ELF parsing, then attaches via
the uprobe PMU.

## Tracepoint

```lisp
(attach-tracepoint prog-fd "tracepoint/sched/sched_process_fork")
(attach-tracepoint prog-fd "sched/sched_process_fork")
```

Resolves the tracepoint ID from tracefs and opens a perf event. The
`tracepoint/` prefix is optional. Hyphens are converted to underscores
for the filesystem lookup.

## XDP

```lisp
(attach-xdp prog-fd "eth0")
(attach-xdp prog-fd "eth0" :mode "xdpdrv")
```

Attaches an XDP program to a network interface. Mode options:

| Mode           | Description           |
|----------------|-----------------------|
| `"xdp"`        | Auto (kernel decides) |
| `"xdpdrv"`     | Native driver mode    |
| `"xdpgeneric"` | SKB/generic mode      |
| `"xdpoffload"` | Hardware offload      |

## TC (Traffic Control)

```lisp
(attach-tc prog-fd "eth0")
(attach-tc prog-fd "eth0" :direction "egress")
```

Attaches a TC classifier program. Sets up the `clsact` qdisc and pins
the program to bpffs. Direction is `"ingress"` (default) or `"egress"`.

## Cgroup

```lisp
(attach-cgroup prog-fd "/sys/fs/cgroup" +bpf-cgroup-inet-egress+)
(attach-cgroup prog-fd "/sys/fs/cgroup" +bpf-cgroup-inet-egress+ :flags 2)
```

Attaches a BPF program to a cgroup. The attach type must be one of the
constants below. Optional `:flags` can include `BPF_F_ALLOW_MULTI` (2)
or `BPF_F_REPLACE` (4).

### Cgroup attach type constants

| Constant                         | Value | Section name            |
|----------------------------------|-------|-------------------------|
| `+bpf-cgroup-inet-ingress+`     | 0     | `cgroup_skb/ingress`    |
| `+bpf-cgroup-inet-egress+`      | 1     | `cgroup_skb/egress`     |
| `+bpf-cgroup-inet-sock-create+` | 2     | `cgroup/sock_create`    |
| `+bpf-cgroup-inet4-connect+`    | 10    | `cgroup/connect4`       |
| `+bpf-cgroup-inet6-connect+`    | 11    | `cgroup/connect6`       |
| `+bpf-cgroup-udp4-sendmsg+`     | 14    | `cgroup/sendmsg4`       |
| `+bpf-cgroup-udp6-sendmsg+`     | 15    | `cgroup/sendmsg6`       |
| `+bpf-cgroup-inet-sock-release+`| 34    | `cgroup/sock_release`   |

## Convenience wrappers

For `with-bpf-object` users, these look up the program by name and
track the attachment on the object (auto-detached on close):

```lisp
(attach-obj-kprobe obj "prog_name" "function_name" :retprobe nil)
(attach-obj-uprobe obj "prog_name" "/path/to/bin" "symbol" :retprobe nil)
(attach-obj-cgroup obj "prog_name" "/sys/fs/cgroup" +bpf-cgroup-inet-egress+)
```

## Detaching

```lisp
(detach attachment)
```

Closes perf event FDs and runs any cleanup (e.g., removing TC filters,
detaching from cgroups, removing XDP programs).
