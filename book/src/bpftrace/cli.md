# CLI Reference

```
whistler bpftrace [OPTIONS] [SCRIPT-PATH]
```

## Source selection

| Flag | Behaviour |
|---|---|
| `-e PROGRAM` | Inline script. Can't be combined with a script path. |
| `SCRIPT-PATH` | Read script from a file. |
| `--dump` | Compile only — print the generated Whistler forms and exit. The kernel isn't touched. |

## Filtering and spawning

| Flag | Behaviour |
|---|---|
| `-p PID` | AND a `pid == PID` predicate into every probe. |
| `-c 'CMD'` | Spawn `CMD` ptrace-stopped, attach probes, resume. The trace ends when the child exits, and the child's pid is auto-injected as a filter. |

### How `-p` works

A post-normalize AST pass walks each probe and AND's its `:predicate`
slot with `(pid == PID)`. The pid check runs in-kernel before the
rest of the body. This matches bpftrace's `PidFilterPass`.

### How `-c` works

The child is forked with `PTRACE_TRACEME` and stops at exec entry via
`raise(SIGSTOP)`. The parent attaches every probe, then issues
`PTRACE_DETACH`. The first instruction the spawned binary executes
happens after probes are live — same synchronisation bpftrace uses.

Whistler splits the command on whitespace and `execve`s the first
token directly, with no shell in between. That has two practical
consequences:

- The child pid is the user's target (e.g. `find`), not a wrapping
  `sh`. The auto-pid-filter catches the right process.
- Shell metacharacters like `|`, `>`, or `2>/dev/null` pass through as
  literal argv tokens — bpftrace behaves the same way.

If you need shell interpretation, write it out: `-c 'sh -c "complex |
pipeline"'`.

## Listing probes

| Flag | Behaviour |
|---|---|
| `-l [PATTERN]` | List kernel functions matching the glob `PATTERN`. Reads `/sys/kernel/tracing/available_filter_functions` when readable; falls back to `/proc/kallsyms`. No script needed. |

```sh
whistler bpftrace -l 'kprobe:tcp_send*'
```

One match per line, followed by a count:

```
kprobe:tcp_send_mss
kprobe:tcp_sendmsg_fastopen
kprobe:tcp_sendmsg_locked
...
;; 27 probes
```

Compiler-generated specialisations like `tcp_call_bpf.cold` and
`x.constprop.0.isra.0` show up in `/proc/kallsyms` but the kprobe
machinery refuses them, so the listing drops anything containing a
`.`.

## Diagnostic flags

| Flag | Behaviour |
|---|---|
| `-V`, `--version` | Print the version string. |
| `-h`, `--help` | Print usage. |
| `--dump` | Stop after codegen and print the generated `defmap` and `defprog` forms. |

## Script parameters (`getopt`)

Args after `--` (or after the script path) of the form `--NAME` or
`--NAME=VALUE` are exposed to the script through bpftrace's
`getopt(NAME, DEFAULT)` builtin. Bool defaults take `--NAME` as 1 and
`--NAME=true/1`/`--NAME=false/0` as the parsed value; int defaults
parse `--NAME=N` as an integer; missing flag yields the DEFAULT.

```sh
# tools/syscount.bt uses sysname = getopt("sysname", false) to gate
# between numeric IDs and resolved names.
sudo whistler bpftrace tools/syscount.bt -- --sysname
```

## Examples

```sh
# Count openat calls by comm
sudo whistler bpftrace \
  -e 'tracepoint:syscalls:sys_enter_openat { @[comm] = count(); }'

# Only PID 1234
sudo whistler bpftrace -p 1234 \
  -e 'kprobe:vfs_read { @ = count(); }'

# What does this command open?
sudo whistler bpftrace -c 'cat /etc/hostname' \
  -e 'tracepoint:syscalls:sys_enter_openat
        { printf("%s\n", str(args->filename)); }'

# What can I probe in TCP?
whistler bpftrace -l 'kprobe:tcp_*' | head

# Check that a script compiles, without loading it
whistler bpftrace --dump examples/bpftrace/biolatency.bt
```
