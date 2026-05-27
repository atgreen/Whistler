# Surface Language

Reference for the bpftrace surface as `whistler bpftrace` accepts it.
Existing bpftrace scripts mostly run unchanged.

## Probes

A probe is one or more attach specs, an optional filter predicate, and a
body block:

```
PROBE-TYPE:TARGET [, PROBE-TYPE:TARGET ...] [/predicate/] { body }
```

| Probe | Target | Notes |
|---|---|---|
| `BEGIN` | — | Fires once at attach. |
| `END` | — | Fires once at exit. |
| `kprobe:FUNC` | kernel function | Wildcards allowed: `kprobe:tcp_*`. |
| `kretprobe:FUNC` | kernel function | Same. |
| `kfunc:FUNC` | kernel function | BTF-trampoline fentry — cheaper than kprobe. |
| `kretfunc:FUNC` | kernel function | BTF-trampoline fexit. |
| `uprobe:PATH:SYM` | user function | |
| `uretprobe:PATH:SYM` | user function | |
| `tracepoint:CAT:EVENT` | tracepoint | `args->FIELD` reads from the format file. |
| `profile:hz:N` | — | Periodic, per-CPU. |
| `interval:s:N` / `:ms:N` / `:us:N` / `:hz:N` | — | Periodic, single-CPU. |

Several specs can share one body:

```
kprobe:vfs_read,kprobe:vfs_write { @[probe] = count(); }
```

Wildcard targets attach to every matching kernel function:

```
kprobe:tcp_* { @ = count(); }
```

On kernels ≥ 5.18 these will eventually use `BPF_TRACE_KPROBE_MULTI`; see
issue [#39](https://github.com/atgreen/Whistler/issues/39). Today they
fall back to one `perf_event_open` per match, which is slower but
correct.

## Maps and aggregations

Map references start with `@`. The unnamed `@` is fine; named maps use
`@foo`. Keys go in brackets:

```
@              = …    # global scalar
@foo           = …    # named scalar
@[pid]         = …    # keyed
@[pid, ustack] = …    # composite key
```

The right-hand side is either a value or an aggregation:

| RHS | Storage | Output |
|---|---|---|
| scalar (`5`, `nsecs`) | u64 | bare number |
| `count()` | u64 counter | bare number |
| `sum(x)` | per-CPU u64 | sum across CPUs |
| `avg(x)` | per-CPU (count, sum) | computed average |
| `min(x)` / `max(x)` | per-CPU (count, value) | min / max across CPUs |
| `stats(x)` | per-CPU (count, sum) | `count N, average A, total T` |
| `hist(x)` | per-CPU log2 buckets | ASCII histogram |
| `lhist(x, lo, hi, step)` | per-CPU linear buckets | linear histogram with `[a, b)` labels |

String-typed composite-key slots are 16 bytes for `comm` and whatever
size you ask for with `str(ptr [, n])` / `kstr(ptr [, n])` (default 64).

## Built-in variables

| Builtin | Returns |
|---|---|
| `pid` | u32 |
| `tid` | u32 |
| `uid` | u32 |
| `gid` | u32 |
| `nsecs` | u64; `CLOCK_BOOTTIME`, matching bpftrace |
| `cpu` | u32 |
| `cgroup` | u64 |
| `comm` | 16-byte char[] |
| `retval` | u64; kretprobe / kretfunc / uretprobe only |
| `args` | tracepoint args struct, used with `->field` |
| `arg0`..`arg9` | nth function arg (kprobe / uprobe / kfunc) |
| `curtask` | `struct task_struct *`, used with `->field` |
| `probe` | string; the current probe's section name |
| `func` | string; the current probed function name |
| `kstack` / `ustack` | stack-id, formatted at print time |
| `$name` | local variable (`$name = …` to assign) |

## Functions and async actions

### Output

| Form | Effect |
|---|---|
| `printf(FMT, args…)` | C-style format. Supports `%d / %u / %x / %X / %p / %c / %s / %lld / %%`, the `-` (left-align) and `0` (zero-pad) flags, and decimal width. |
| `print(@m)` | Dump map `@m` from userspace. |
| `time()` | Print the current time. |
| `exit()` | Raise the exit flag; the runtime stops at the next tick. |
| `clear(@m)` | Empty map `@m`. |
| `zero(@m)` | No-op for now. |
| `delete(@m[k])` | Remove a key. |

### Memory and addresses

| Form | Returns | Helper |
|---|---|---|
| `str(ptr [, n])` | string slot (default 64 B) | `bpf_probe_read_user_str` |
| `kstr(ptr [, n])` | string slot | `bpf_probe_read_kernel_str` |
| `ksym(addr)` | resolved name | userspace `/proc/kallsyms` |
| `usym(addr)` | resolved name | userspace symbolizer |
| `ntop([af,] addr)` | IPv4 / IPv6 string | userspace format |
| `reg("ip"\|"sp"\|"di"\|…)` | u64 register | direct `pt_regs` read |

### Aggregations

`count`, `sum`, `avg`, `min`, `max`, `stats`, `hist`, `lhist`. See the
[Maps and aggregations](#maps-and-aggregations) table above. All of
these must appear on the right-hand side of `@m = …`.

## Operators

C-style: `+ - * / % == != < > <= >= && || ! & | ^ << >> ~`. Compound
assigns: `+= -= *= /= %= &= |= ^=`. Pre/post increment and decrement:
`++ --`.

## Casts and struct access

```
((struct task_struct *)curtask)->pid
((struct sock_common *)arg0)->skc_family
```

A cast tags the inner expression with a struct type; the subsequent
`->FIELD` is resolved against the kernel's BTF for that struct. Scalar
fields up to 8 bytes are supported. Nested pointer chasing
(`curtask->mm->mmap_lock`) is not yet wired up — see the
[Limits](#limits) table.

## Control flow

```
if (cond) { … } else { … }

while ($i < 10) { $i += 1; }

cond ? a : b

kprobe:foo /pid == 1234/ { … }     # filter predicate
```

`while` lowers to a bounded `dotimes` (currently 64 iterations) with the
body short-circuiting once the condition goes false. The BPF verifier
requires a static upper bound on every loop, so this is unavoidable
without `bpf_loop()` helper plumbing.

## Symbolic constants

Identifiers like `AF_INET`, `O_RDONLY`, `IPPROTO_TCP` resolve at codegen
from two sources, in order:

1. Kernel BTF `BTF_KIND_ENUM` / `ENUM64` members. Free — Whistler
   harvests them once per session.
2. A small curated table of POSIX/Linux `#define` constants BTF doesn't
   carry (socket families, mode bits, open flags).

The curated entries override BTF on conflict so a kernel renaming an
enum can't silently change script semantics. No `#include`, no C
parser.

## User-defined functions

```
fn dub($x) { return $x * 2; }

kprobe:vfs_read { @ = dub(arg2); }
```

Functions are inlined at the AST-to-IR boundary: each call site
substitutes the body, with parameters textually replaced by the
argument expressions. A few caveats follow from that approach:

- Side-effecting arguments evaluate at every reference. Don't pass
  `nsecs` into a parameter you read twice if you need it stable.
- Recursion isn't blocked; the inliner will loop forever.
- No type or return-type annotations — every value is u64.

## Limits

The gaps versus upstream bpftrace, in case you hit one:

| Feature | Status |
|---|---|
| `for ($k : @m) { … }` | Not wired up; needs `bpf_for_each_map_elem`. |
| `break` / `continue` | Not wired up. |
| Chained pointer struct access (`curtask->mm->mmap_lock`) | Single level only. |
| `raw_tracepoint`, `software`, `hardware`, `watchpoint` | Not wired up. |
| `system()` async action | Not wired up. |
| C++ symbol demangling | Intentionally skipped. |
| `#include` of C headers | Not planned. Use [symbolic constants](#symbolic-constants) instead. |
