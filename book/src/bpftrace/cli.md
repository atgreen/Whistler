# CLI Reference

`whistler bpftrace [OPTIONS] [SCRIPT-PATH]`

## Source selection

| Flag | Behaviour |
|---|---|
| `-e PROGRAM` | Inline script. Mutually exclusive with a script path. |
| `SCRIPT-PATH` | Read script from a file. |
| `--dump` | Compile only; print the generated Whistler forms (maps, progs, user-side probes) and exit. No kernel touch. |

## Filtering and spawning

| Flag | Behaviour |
|---|---|
| `-p PID` | Inject a `pid == PID` predicate AND'd into every probe. Equivalent to bpftrace's `PidFilterPass`. |
| `-c 'CMD'` | Spawn `CMD` ptrace-stopped, attach probes, resume the child. Trace ends when the child exits. The child pid is auto-injected as a filter (since the child IS the target binary). |

### `-p` mechanics

The `-p` filter is implemented at the AST level — a post-normalize pass
walks each probe and AND's its `:predicate` slot with
`(pid == PID)`. The resulting BPF program checks the pid in-kernel
before running the rest of the body. Identical to what bpftrace does
for kprobe/kretprobe/fentry/fexit/tracepoint.

### `-c` mechanics

The child is forked with `PTRACE_TRACEME`, stops at exec entry via
`raise(SIGSTOP)`, and only resumes after the parent has attached all
probes and called `PTRACE_DETACH`. This matches bpftrace's
synchronisation: every syscall the spawned binary makes happens after
probes are live.

Unlike bpftrace's `-c` (which spawns through `/bin/sh -c`), whistler
splits the command on whitespace and `execve`s the binary directly,
so:

- The child pid IS the user's target (e.g. `find`), not a wrapping
  `sh`. The auto-pid-filter actually catches the right process.
- Shell metacharacters (`|`, `>`, `2>/dev/null`, quotes) pass through
  as literal argv tokens — same behaviour as bpftrace.

If you need a real shell, write `-c 'sh -c "complex | pipeline"'`
explicitly.

## Listing probes

| Flag | Behaviour |
|---|---|
| `-l [PATTERN]` | List kernel functions matching the glob PATTERN. Reads `/sys/kernel/tracing/available_filter_functions` when readable (sudo); falls back to `/proc/kallsyms`. No script needed. |

```sh
whistler bpftrace -l 'kprobe:tcp_send*'
```

Output is one `kprobe:NAME` per line followed by a count:

```
kprobe:tcp_send_mss
kprobe:tcp_sendmsg_fastopen
kprobe:tcp_sendmsg_locked
...
;; 27 probes
```

Compiler-generated specialisations (`tcp_call_bpf.cold`,
`x.constprop.0.isra.0`) are silently dropped — they show up in
kallsyms but the kprobe machinery refuses them.

## Diagnostic flags

| Flag | Behaviour |
|---|---|
| `-V`, `--version` | Print version string. |
| `-h`, `--help` | Print usage. |
| `--dump` | Stop after codegen and print the generated `defmap` / `defprog` forms. |

## Examples

```sh
# Trace every openat call, group by command name
sudo whistler bpftrace \
  -e 'tracepoint:syscalls:sys_enter_openat { @[comm] = count(); }'

# Only the events from PID 1234
sudo whistler bpftrace -p 1234 \
  -e 'kprobe:vfs_read { @ = count(); }'

# Trace a one-shot command's syscalls
sudo whistler bpftrace -c 'cat /etc/hostname' \
  -e 'tracepoint:syscalls:sys_enter_openat
        { printf("%s\n", str(args->filename)); }'

# What can I probe in TCP?
whistler bpftrace -l 'kprobe:tcp_*' | head

# Just check the script compiles — no kernel
whistler bpftrace --dump examples/bpftrace/biolatency.bt
```
