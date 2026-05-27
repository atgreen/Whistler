# Examples

Recipes that exercise the bpftrace frontend end-to-end. Each example
runs unchanged on `whistler bpftrace`.

## opensnoop — every file opened, per command

```sh
sudo whistler bpftrace -e \
  'tracepoint:syscalls:sys_enter_openat
     { printf("%-16s %s\n", comm, str(args->filename)); }'
```

Live stream:

```
Hyprland         /proc/self/stat
ptyxis           /home/green/.local/share/recently-used.xbel
firefox          /proc/14123/cmdline
```

## syscall count by command

```sh
sudo whistler bpftrace -e \
  'tracepoint:syscalls:sys_enter_openat { @[comm] = count(); }'
```

Aggregated at ctrl-C:

```
@[firefox]:        237
@[ptyxis]:          43
@[Hyprland]:         1
```

## biolatency-style — bounded histogram

```sh
sudo whistler bpftrace -e \
  'kretprobe:vfs_read { @us = lhist(retval, 0, 4096, 256); }'
```

The `lhist` aggregation gives linear buckets with explicit lower /
upper bounds + step. After ctrl-C:

```
@us:
(..., 0)              0  ||
[0, 256)            245  |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[256, 512)           17  |@@@                                                  |
[512, 768)            3  |                                                     |
[4096, ...)           2  |                                                     |
```

## "what does this command open" — `-c`

```sh
sudo whistler bpftrace -c 'cat /etc/hostname' \
  -e 'tracepoint:syscalls:sys_enter_openat
        { printf("%s\n", str(args->filename)); }'
```

The child is ptrace-stopped at exec entry; probes attach; child runs
to completion; tracer exits cleanly with its map state:

```
;; -c spawned pid 1989572 (ptrace-stopped) — tracing until it exits.
/etc/ld.so.cache
/lib64/libc.so.6
/etc/hostname
```

## ksym / usym — symbolised addresses

```sh
sudo whistler bpftrace -e \
  'kprobe:vfs_read
     { printf("%s called by %s\n", comm, ksym(arg0)); }'
```

`ksym` resolves against `/proc/kallsyms` at print time, falling back
to `0xHEX` when there's no match (e.g. heap pointers).

`usym(addr)` is the userspace equivalent; the symbolizer captures
`pid_tgid` in the kernel so per-pid `/proc/<pid>/maps` snapshots stay
correct even after the process exits.

## Stack traces

```sh
sudo whistler bpftrace -e \
  'uprobe:/usr/lib64/libc.so.6:malloc { @[ustack] = count(); }'
```

Userspace stack traces are symbolised through the pure-CL ELF /
DWARF `.debug_line` reader. When `glibc-debuginfo` (or equivalent)
is installed each frame renders as
`name+0xOFFSET [library] file:line`:

```
@[
        __GI___libc_malloc+0x0 [libc.so.6] malloc.c:3283
        g_malloc+0x1A [libglib-2.0.so.0.8800.1]
        g_source_set_callback+0x37 [libglib-2.0.so.0.8800.1]
        ...
]: 4
```

## kfunc — modern fentry probes

`kfunc` / `kretfunc` use BTF trampolines instead of kprobe traps.
Cheaper, supports named args:

```sh
sudo whistler bpftrace -e \
  'kfunc:vfs_read
     { @[args->file] = count(); }'
```

`args->file` lowers to a direct `ctx[0]` read, using BTF
`FUNC_PROTO` to find the slot index.

## Wildcards

```sh
sudo whistler bpftrace -e \
  'kprobe:tcp_* { @ = count(); }'
```

Currently attaches sequentially (one `perf_event_open` per match);
`BPF_TRACE_KPROBE_MULTI` fast-path is tracked in
[#39](https://github.com/atgreen/Whistler/issues/39).

## User-defined fn

```sh
sudo whistler bpftrace -e \
  'fn ms_since($t) { return (nsecs - $t) / 1000000; }
   kprobe:vfs_read    { @start[tid] = nsecs; }
   kretprobe:vfs_read /@start[tid]/
     { @ms[comm] = lhist(ms_since(@start[tid]), 0, 100, 10);
       delete(@start[tid]); }'
```

`fn` bodies are inlined at every call site, so `ms_since(@start[tid])`
expands directly into the aggregator with no function-call overhead.

## Self-identifying probes

```sh
sudo whistler bpftrace -e \
  'kprobe:vfs_read,kprobe:vfs_write,kprobe:vfs_open
     { @[probe] = count(); }'
```

`probe` is replaced at AST-rewrite time with each probe's section
name, so the map separately counts each variant.

## Constants without C headers

```sh
sudo whistler bpftrace -e \
  'tracepoint:syscalls:sys_enter_openat /args->flags == O_RDONLY/
     { @[comm] = count(); }'
```

`O_RDONLY` resolves from the curated `#define` table; `AF_INET`,
`IPPROTO_TCP`, `S_IFDIR` etc. all work the same way. No `#include`
needed.
