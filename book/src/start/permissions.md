# Permissions

Loading and attaching BPF programs requires elevated privileges. You do not
need full root access -- Linux capabilities are sufficient.

## Required capabilities

Two capabilities cover the common case:

- **CAP_BPF** -- load BPF programs and create maps.
- **CAP_PERFMON** -- attach to perf events (kprobes, uprobes, tracepoints)
  and use ring buffers.

Together these allow loading, attaching, and consuming events for most BPF
program types without running as root.

## Setting capabilities on SBCL

Grant the capabilities to the SBCL binary:

```bash
sudo setcap cap_bpf,cap_perfmon+ep /usr/bin/sbcl
```

Verify:

```bash
getcap /usr/bin/sbcl
# /usr/bin/sbcl cap_bpf,cap_perfmon=ep
```

After this, any SBCL process can load BPF programs and attach probes.

If you built a standalone `whistler` binary, set capabilities on that instead:

```bash
sudo setcap cap_bpf,cap_perfmon+ep ./whistler
```

## Tracepoint format files

`deftracepoint` reads tracepoint format definitions from tracefs at
macroexpand time. These files are often root-readable only by default:

```bash
ls -l /sys/kernel/tracing/events/sched/sched_switch/format
# -r--r----- 1 root root ...
```

Make them world-readable so the compiler can parse them without root:

```bash
# Single tracepoint
sudo chmod a+r /sys/kernel/tracing/events/sched/sched_switch/format

# All tracepoints in a category
sudo chmod -R a+r /sys/kernel/tracing/events/sched/

# All tracepoints
sudo find /sys/kernel/tracing/events -name format -exec chmod a+r {} +
```

This only affects the format metadata files. It does not grant access to
the trace ring buffer or enable tracing.

## vmlinux BTF

`import-kernel-struct` reads BTF type information from
`/sys/kernel/btf/vmlinux`. On most distributions this file is already
world-readable:

```bash
ls -l /sys/kernel/btf/vmlinux
# -r--r--r-- 1 root root ...
```

If it is not, make it readable:

```bash
sudo chmod a+r /sys/kernel/btf/vmlinux
```

## XDP and TC attachment

Attaching XDP and TC programs to network interfaces requires
**CAP_NET_ADMIN** in addition to `CAP_BPF`:

```bash
sudo setcap cap_bpf,cap_perfmon,cap_net_admin+ep /usr/bin/sbcl
```

## Cgroup attachment

Attaching cgroup BPF programs (`cgroup_skb`, `cgroup/sock`, etc.) requires
write access to the cgroup directory and `CAP_BPF`. Typically this means:

```bash
sudo setcap cap_bpf,cap_perfmon,cap_net_admin+ep /usr/bin/sbcl
```

## Running as root

If capabilities are not an option, `sudo` works:

```bash
sudo sbcl --noinform \
  --eval '(require :asdf)' \
  --eval '(push #p"./" asdf:*central-registry*)' \
  --eval '(asdf:load-system "whistler/loader")' \
  --eval '(in-package #:whistler)'
```

This grants all capabilities but is less precise than setting individual
caps.

## Summary

| Resource | Capability needed |
|---|---|
| Load BPF programs and create maps | `CAP_BPF` |
| Attach kprobes, uprobes, tracepoints | `CAP_PERFMON` |
| Attach XDP or TC programs | `CAP_NET_ADMIN` |
| Read tracepoint format files | `chmod a+r` on format files |
| Read vmlinux BTF | Usually world-readable already |
