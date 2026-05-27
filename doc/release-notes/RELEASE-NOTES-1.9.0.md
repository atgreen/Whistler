# Whistler 1.9.0 Release Notes

## New Features

### bpftrace-compatible frontend

The Whistler binary now runs scripts written in
[bpftrace](https://github.com/bpftrace/bpftrace)'s surface language.
Parser, AST passes, and codegen are all in the same SBCL image,
reusing the standard Whistler SSA/regalloc pipeline. No separate
bpftrace install, no clang, no LLVM.

```sh
sudo whistler bpftrace \
  -e 'tracepoint:syscalls:sys_enter_openat
        { @[comm] = count(); }'
```

The bulk of bpftrace's day-to-day surface is supported:

- **Probes** — `kprobe`, `kretprobe`, `kfunc`, `kretfunc`, `uprobe`,
  `uretprobe`, `tracepoint`, `profile`, `interval`, `BEGIN`, `END`.
  Wildcards (`kprobe:tcp_*`) and multi-target specs
  (`kprobe:foo,kprobe:bar`).
- **Aggregations** — `count`, `sum`, `avg`, `min`, `max`, `stats`,
  `hist`, `lhist(x, lo, hi, step)`.
- **Async actions** — `printf` (with `%-16s` / `%05d` flag/width
  parsing), `print(@m)`, `clear`, `zero`, `delete`, `time`, `exit`.
- **String / address builtins** — `str(ptr [, n])`, `kstr(ptr [, n])`,
  `ksym(addr)`, `usym(addr)`, `ntop([af,] addr)`, `reg("ip"|"sp"|…)`.
- **Built-in variables** — `pid`, `tid`, `uid`, `gid`, `comm`,
  `nsecs`, `cpu`, `retval`, `curtask`, `args`, `probe`, `func`,
  `kstack`, `ustack`, `$local`, `@global`, composite `@[k1, k2]`.
- **Symbolic constants** — `AF_INET`, `O_RDONLY`, `IPPROTO_TCP`,
  etc. resolved from kernel BTF enums plus a curated `#define`
  table. No C headers needed.
- **Struct access** — `curtask->pid`,
  `((struct sock_common *)arg0)->skc_family` (BTF-resolved scalar
  field offsets).
- **Control flow** — `if`/`else`, ternary, filter `/predicate/`,
  `while` loops (bounded), user-defined `fn` (inlined at AST → IR).

CLI flags match bpftrace's workflow: `-e PROGRAM`, `-l [PATTERN]`,
`-p PID`, `-c 'CMD'`, `--dump`, `-V`, `-h`. The `-c` flag spawns the
target binary `PTRACE_TRACEME`-stopped at exec entry, attaches
probes, then resumes — matching bpftrace's synchronisation so
short-lived commands have probes live for their full lifetime.

See [the bpftrace chapter](https://atgreen.github.io/Whistler/bpftrace/index.html)
of the book for the full reference.

### Userspace stack symbolisation

A new `whistler/symbolize` package resolves userspace addresses
(typically captured by `bpf_get_stackid` with `BPF_F_USER_STACK`)
into `name+0xOFFSET [library] file:line` strings. Pure Common Lisp:
ELF64 reader for symbol tables, build-ID / `.gnu_debuglink` fallback
for separate debug files, and a DWARF 4 / DWARF 5 `.debug_line`
state-machine interpreter for source file + line. Per-pid
`/proc/<pid>/maps` snapshots survive process exit.

`@[ustack]` in a bpftrace script automatically uses the symboliser
when debuginfo is available; bare hex frames otherwise.

### kfunc / kretfunc probe support

The loader gained native fentry / fexit (BTF-trampoline) probe
attachment: `BPF_PROG_TYPE_TRACING` with
`expected_attach_type = BPF_TRACE_FENTRY / FEXIT`,
`attach_btf_id` resolved from `/sys/kernel/btf/vmlinux`, attached
via `BPF_LINK_CREATE`. Both `attach-fentry` (loader) and
`kfunc:` / `kretfunc:` (bpftrace) entry points are wired up.

### CI: ocicl dependencies + live kernel verifier

CI workflow switched from Quicklisp to [ocicl](https://github.com/ocicl/ocicl),
with `ocicl.csv` pinning iparse / fiveam plus their transitive
closure by sha256 digest. A new `kernel-verify` job runs
`make test-torture` under `sudo` on the GitHub-hosted runner — all
161 torture programs round-trip through `BPF_PROG_LOAD` on every
push, so verifier regressions surface immediately.

## Bug Fixes

- **BTF parser advance for `BTF_KIND_DECL_TAG`.** The type-table
  parser was missing the 4-byte `component_idx` extra-data step for
  `DECL_TAG` (kind 17). On any modern kernel that emits decl-tag
  records (Fedora 42+, Ubuntu 24.04+), every type record past the
  first decl-tag was indexed against the wrong offset. Symptom:
  `task_struct.pid` resolved to type-id 130091 (a
  `perf_trace_*` function) instead of `pid_t`. Caught while
  wiring up `curtask->pid` for the bpftrace frontend; affected all
  callers of `btf-find-struct` / `btf-struct-fields` on these
  kernels.

- **ctx-vreg liveness across new helper-call ops.** The
  `ctx-loads-early-p` heuristic in the regalloc decision path only
  inspected `:call` for ctx-vreg usage. With the new `:get-stackid`
  op (and the pre-existing `:tail-call`), ctx could be clobbered
  across a real call before its consumers ran, leading to
  `R1 !read_ok` verifier rejections on programs that combined
  ustack with a prior helper call. The check now considers all
  three op kinds.
