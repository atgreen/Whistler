# Surface Language

This page is a reference for the bpftrace surface as it lives inside
`whistler bpftrace`. The shape mirrors upstream bpftrace, so existing
scripts mostly run unchanged.

## Probes

```
PROBE-TYPE:TARGET [, PROBE-TYPE:TARGET ...] [/predicate/] { body }
```

| Probe | Target | Notes |
|---|---|---|
| `BEGIN` | — | Fires once at attach. |
| `END` | — | Fires once at exit. |
| `kprobe:FUNC` | kernel function | Wildcards: `kprobe:tcp_*`. |
| `kretprobe:FUNC` | kernel function | Same wildcards. |
| `kfunc:FUNC` | kernel function | BTF-trampoline fentry. Faster than kprobe. |
| `kretfunc:FUNC` | kernel function | BTF-trampoline fexit. |
| `uprobe:PATH:SYM` | user function | |
| `uretprobe:PATH:SYM` | user function | |
| `tracepoint:CAT:EVENT` | tracepoint | `args->FIELD` reads from format file. |
| `profile:hz:N` | — | Periodic, per-CPU. |
| `interval:s:N` / `:ms:N` / `:us:N` / `:hz:N` | — | Single CPU, periodic. |

Multi-target on one body:

```
kprobe:vfs_read,kprobe:vfs_write { @[probe] = count(); }
```

Wildcards (kernel ≥ 5.18 will use `BPF_TRACE_KPROBE_MULTI` once
[#39](https://github.com/atgreen/Whistler/issues/39) is closed; today
falls back to sequential perf_event_open):

```
kprobe:tcp_* { @ = count(); }
```

## Maps and aggregations

Map references use `@`. Untagged `@` is fine, named maps use
`@foo`. Keys go in brackets:

```
@        = …       # global scalar
@foo     = …       # named scalar
@[pid]   = …       # keyed
@[pid, ustack] = …  # composite key
```

Right-hand side is a value or an aggregation:

| RHS | Storage | Output |
|---|---|---|
| scalar (`5`, `nsecs`) | u64 | bare number |
| `count()` | u64 counter | bare number |
| `sum(x)` | per-CPU u64 | sum across CPUs |
| `avg(x)` | per-CPU (count, sum) | computed average |
| `min(x)` / `max(x)` | per-CPU (count, value) | min / max across CPUs |
| `stats(x)` | per-CPU (count, sum) | `count N, average A, total T` |
| `hist(x)` | per-CPU log2 buckets | bpftrace-style ASCII histogram |
| `lhist(x, lo, hi, step)` | per-CPU linear buckets | linear histogram with `[a, b)` labels |

The composite-key string slot is always 16 bytes for `comm` and the
exact byte width you requested for `str(ptr [, n])` / `kstr(ptr [, n])`.

## Built-in variables

| Builtin | Returns |
|---|---|
| `pid` | u32 |
| `tid` | u32 |
| `uid` | u32 |
| `gid` | u32 |
| `nsecs` | u64 — `CLOCK_BOOTTIME` (matches bpftrace) |
| `cpu` | u32 |
| `cgroup` | u64 |
| `comm` | 16-byte char[] |
| `retval` | u64 — kretprobe / kretfunc / uretprobe only |
| `args` | tracepoint args struct — used with `->field` |
| `arg0`..`arg9` | function arg N (kprobe / uprobe / kfunc) |
| `curtask` | `struct task_struct *` — use with `->field` |
| `probe` | string — current probe's section name |
| `func` | string — current probed function name |
| `kstack` / `ustack` | stack-id, formatted at print time |
| `$name` | local variable (assign with `$name = …`) |

## Functions and async actions

### Output

| Form | Effect |
|---|---|
| `printf(FMT, args…)` | C-style format. Supports `%d / %u / %x / %X / %p / %c / %s / %lld / %%`, flag `-` (left-align), `0` (zero-pad), decimal width. |
| `print(@m)` | Dump map `@m` from userspace. |
| `time()` | Print current time. |
| `exit()` | Set the exit flag; runtime stops at next tick. |
| `clear(@m)` | Empty map `@m`. |
| `zero(@m)` | No-op in current implementation. |
| `delete(@m[k])` | Remove key. |

### Memory / address

| Form | Returns | Helper |
|---|---|---|
| `str(ptr [, n])` | string slot (default 64 B) | `bpf_probe_read_user_str` |
| `kstr(ptr [, n])` | string slot | `bpf_probe_read_kernel_str` |
| `ksym(addr)` | resolved name | userspace `/proc/kallsyms` |
| `usym(addr)` | resolved name | userspace symbolizer (PR1+PR3) |
| `ntop([af,] addr)` | IPv4 / IPv6 string | userspace format |
| `reg("ip"\|"sp"\|"di"\|…)` | u64 register | `pt_regs` direct read |

### Aggregation-only

`count`, `sum`, `avg`, `min`, `max`, `stats`, `hist`, `lhist` — see
above. Must be on the RHS of `@m = …`.

## Operators

C-style: `+ - * / % == != < > <= >= && || ! & | ^ << >> ~`. Compound
assigns: `+= -= *= /= %= &= |= ^=`. Increment / decrement: `++ --`.

## Casts and struct access

```
((struct task_struct *)curtask)->pid
((struct sock_common *)arg0)->skc_family
```

The cast tags the inner expression with a struct type; the subsequent
`->FIELD` is resolved against the kernel's BTF for that struct.

Scalar field widths (1 / 2 / 4 / 8 bytes) are supported. Nested
struct-pointer chasing (`curtask->mm->mmap_lock`) is not yet wired up.

## Control flow

```
if (cond) { … } else { … }

while ($i < 10) { $i += 1; }

cond ? a : b

kprobe:foo /pid == 1234/ { … }     # filter predicate
```

`while` is lowered to a bounded `dotimes` (64 iterations; body short-
circuits once the condition is false) since the BPF verifier requires
known termination.

## Symbolic constants

Identifiers like `AF_INET` / `O_RDONLY` / `IPPROTO_TCP` resolve from
two sources at codegen:

1. Kernel BTF `BTF_KIND_ENUM` / `ENUM64` members (free; harvested
   once per session).
2. A curated `#define` table for constants that aren't in BTF
   (POSIX flags, socket families, mode bits).

The curated entries override BTF on conflict — values are pinned so a
kernel renaming an enum can't silently change script semantics.

No `#include`, no C parser.

## User-defined functions

```
fn dub($x) { return $x * 2; }

kprobe:vfs_read { @ = dub(arg2); }
```

Inlined at the AST → IR boundary: each call site has its body
substituted in, parameters textually replaced with the actual
arguments. Caveats:

- Single substitution per parameter; side-effecting args evaluate at
  every use. Don't pass `nsecs` if you need it stable.
- Recursion isn't blocked but loops forever in the inliner.
- No types / no return-type annotations — every value is u64.

## What's missing

The big remaining gaps versus upstream bpftrace:

| Feature | Status |
|---|---|
| `for ($k : @m) { … }` | Not wired up (needs `bpf_for_each_map_elem`). |
| `break` / `continue` | Not wired up. |
| Chained pointer struct access (`curtask->mm->mmap`) | Single-level only. |
| `raw_tracepoint`, `software`, `hardware`, `watchpoint` | Not wired up. |
| `system()` async action | Not wired up. |
| C++ symbol demangling | Skipped intentionally. |
| `#include` of C headers | Not planned — see [Symbolic constants](#symbolic-constants). |
