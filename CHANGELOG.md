# Changelog

All notable user-facing changes per release. Newest first.

## 1.13.0 — 2026-09-07

### Bug Fixes

- `attach-tracepoint` opened a single perf event on CPU 0 only, so
  tracepoint samples from a process running on any other CPU were never
  delivered. The loader now opens and enables one perf event per online
  CPU (issuing `PERF_EVENT_IOC_SET_BPF` once, since tracepoint program
  attachment is global).
- `hist()` bucket indexing now matches bpftrace: value 0 lands in
  bucket `[0]`, value 1 in `[1]`, and each power-of-two interval in its
  labeled slot — previously every positive bucket landed one slot low
  and values 0 and 1 were merged. log2 histogram maps and runtime
  iteration widened from 64 to 65 buckets so the full u64 range stays
  representable, and all four histogram printers now trim leading empty
  buckets the way upstream bpftrace does.
- Fixed comm-keyed histogram lowering: `@h[comm] = hist(...)` now
  copies the comm string's bytes into the map key instead of storing it
  as a scalar, so string-shaped keys survive having the bucket slot
  appended.

## 1.12.0 — 2026-08-26

### New Features

#### Compile-time return-code validation

The compiler now catches an invalid constant return value at compile
time, with a clear message, instead of letting it through to a cryptic
kernel-load rejection. A program that returns a value outside its
program type's action set — e.g. `(return 99)` from an XDP program — is
now a compile error naming the valid actions. Both explicit `(return
...)` and the implicit trailing-value return are checked. Enforced for
the program types whose return set is small and strict: XDP
(`XDP_ABORTED`..`XDP_REDIRECT`), `cgroup_skb`, and `sk_lookup`; other
types are left to the kernel verifier. This is the first slice of a
broader compile-time verifier model.

#### Annotated disassembly

`disassemble-cu` now annotates each emitted BPF instruction with the
surface Whistler form it was lowered from (falling back to the IR op for
instructions produced by optimization passes), making the shape of the
generated code legible at a glance — a `map-lookup` expanding into its
lookup/null-check/increment sequence, which branch a guard produced, and
so on.

#### `make bench` — instruction-count benchmarking against clang

A reproducible harness (`make bench`, `benchmarks/manifest.txt`,
`scripts/bench.sh`) compiles curated Whistler programs alongside
hand-written `clang -O2` equivalents (`examples/*.c`) and compares their
instruction counts, failing on a regression above a committed baseline.
On the current suite Whistler matches or beats `clang -O2`.

#### Codegen improvements

Several optimizations reduce instruction counts: `log2` and unary
negation of compile-time constants now fold to a literal; constants
whose 64-bit value is a sign-extended 32-bit immediate (notably any
negative constant) materialize with a single `mov64` instead of a
two-slot `ld_imm64`; and the peephole pass now threads conditional
branches through the goto-to-epilogue trampolines that tail-merging
introduces, deleting the now-unreachable trampolines.

A new `examples/percpu-counter.lisp` demonstrates a genuine per-CPU
packet counter over a `:percpu-array` map.

### Bug Fixes

- The loader no longer mislabels every failed `BPF_PROG_LOAD` as a
  verifier rejection. Only `EACCES` (the verifier-rejection errno, whose
  log holds the verifier trace) is reported as such; `EPERM` (e.g. a
  missing `CAP_NET_ADMIN` when loading XDP/TC programs) and `EINVAL`
  now surface the real errno instead of a misleading empty verifier log.
- A bare `map-lookup` result — a maybe-null pointer — passed directly as
  a kfunc argument is now rejected at compile time, matching the
  existing checks on `load`, `store`, and `atomic-add`.
- Fixed a latent truncation in the emitter that could load a genuine
  64-bit constant with a sign-extended 32-bit `mov64` instead of
  `ld_imm64` on the constant-register path.

## 1.11.0 — 2026-08-14

### New Features

#### kfunc support — calling BPF kernel functions (issue #44)

BPF programs can now call kfuncs — the extensible kernel functions that
have replaced the frozen helper set. Resolution is by BTF at load time,
on Whistler's pure-CL toolchain (no libbpf): a call compiles to a
`BPF_PSEUDO_KFUNC_CALL`, the ELF carries an `R_BPF_64_32` relocation
against an extern BTF `FUNC`, and the loader patches in the kfunc's
vmlinux BTF id. Both load paths handle it — the `.bpf.o` loader and the
in-memory session/bpftrace-runtime path.

Call a kfunc by name like a helper; six ship predeclared
(`bpf-rcu-read-lock`/`unlock`, `bpf-task-from-pid`/`bpf-task-release`,
`bpf-cgroup-from-id`/`bpf-cgroup-release`). Declare your own with
`defkfunc`. Acquire/release and maybe-null pointers are modeled and
checked at compile time (a leaked acquired reference or an unguarded
`:ret-null` result is a compile error); the verifier remains
authoritative for per-path completeness and the per-program-type kfunc
allowlist. Available from both the Whistler surface language and the
bpftrace frontend (call by kernel symbol name). See
`examples/kfunc-task.lisp` and `examples/bpftrace/kfunc-rcu.bt`.

#### sk_lookup program support — compile, load, and attach

Whistler can now express `BPF_PROG_TYPE_SK_LOOKUP`, the programmable
listener-lookup hook (Linux 5.9+) that lets a single socket answer for
any port within a network namespace. The compiler gained the sk_lookup
program type and its `bpf_sk_lookup` context struct, the
`bpf_sk_assign` / `bpf_sk_lookup_tcp` / `bpf_sk_lookup_udp` /
`bpf_sk_release` helpers, and the sockmap and sockhash map types a
catch-all redirector needs. The loader routes the section name to the
program type and its required `expected_attach_type`, and
`attach-sk-lookup` creates a BPF link against a network-namespace fd —
the loader's first netns-targeted `BPF_LINK_CREATE`. See
`examples/sk-lookup-catchall.lisp` for the canonical look-up / assign /
release pattern. Verified end to end on Linux 7.0 through the pure-Lisp
loader.

#### bpftrace frontend: broad surface expansion

The bpftrace frontend gained a large batch of language and stdlib
coverage, closing much of the gap with upstream bpftrace:

- **Tuples**: tuple-typed map values and variables, `$t.N` component
  access, nested tuples, tuple slots as map keys/values, and
  bool/`ntop`/`strftime`-typed elements that render correctly.
- **Arrays**: multi-dimensional subscripts (`$a.x[i][j]`,
  `args.FIELD[i]`), whole-array round-trips through `$vars`, array
  compare (`==` / `!=`), and rendering `int[N]` arrays as map keys,
  values, and tuple slots — with runtime out-of-bounds warnings.
- **Map iteration**: `for $kv : @m { … }` iterates map keys via sidecar
  arrays; `len(@m)` via a sidecar counter.
- **Stdlib builtins**: `str`/`buf`/`strncmp`/`strcontains`/`strstr`/
  `find`, `pton`/`ntop`/`macaddr`/`path`, `kptr`/`uptr`/`percpu_kaddr`,
  `signal`/`override`/`cgroupid`/`socket_cookie`, `jiffies`/`nsecs`/
  `strftime`, `is_str`/`is_ptr`/`is_integer`/`is_array`/`is_literal`,
  `assert`/`static_assert`, `syscall_name`/`signal_name`, and more.
- **Probes**: `self:signal:NAME` userspace-handler probes, kprobe
  `MODULE:` prefix and `+OFFSET` suffix, and stricter rejection of
  probe shapes that aren't actually supported.
- **Output**: `-f json` output mode, `-q`, per-key `@m[k] = hist(x)` /
  `lhist(x, …)`, `print(@m, top, div)`, config blocks
  (`print_maps_on_exit`), and CLI/`-l` listing fixes.
- **Control flow**: `while` loops with `break`/`continue`, `unroll(N)`,
  compound-assignment operators beyond `+=`/`-=`, and pre/post
  increment/decrement as expressions.

### Bug Fixes

- **percpu_kaddr** now emits an `ld_imm64` with `PSEUDO_BTF_ID`, so the
  resulting `percpu_ptr` is accepted by the verifier.
- **phi-branch-threading** repairs downstream PHI nodes on redirected
  edges, fixing miscompiles from an SSA optimization pass.
- **map-update** copies key and value into `r2`/`r3` in parallel,
  avoiding a clobber when the two sources alias.
- Immediate-to-stack stores now use `ST_MEM` directly instead of
  borrowing `R1` as scratch.
- for-loops extend back-edge liveness and correctly restore the
  environment for shadowed variables.

## 1.10.0 — 2026-05-28


### New Features

#### bpftrace: range-based `for` loops with `break` / `continue`

bpftrace's range form is now supported:

```
for $j : ((uint64)0)..((uint64)max_path_depth) {
  @paths[tid, $j] = str($dentry.d_name.name);
  if ($dentry == $mnt_root) { break; }
  $dentry = $dentry.d_parent;
  continue;
}
```

Lowered to a bounded `dotimes` with two flags: a continue-flag scoped
to the current iteration, and a break-flag scoped to the whole loop.
Statements after a `break` or `continue` in the same lexical scope —
including statements nested inside `if` branches — are skipped via
dynamic-binding-driven wrapping. `while (cond) { … }` gained the same
treatment, so `break`/`continue` work in both shapes.

#### Per-CPU scratch maps lift the 512-byte stack ceiling

Any `struct-alloc` larger than 32 bytes now spills off the BPF stack
into an auto-defined per-CPU array map (`__bt-scratch__`,
`BPF_MAP_TYPE_PERCPU_ARRAY`, `max_entries=1`). The scratch buffer is
looked up once at probe entry and every spilled allocation site
becomes a constant-offset pointer arithmetic into the per-CPU slot —
the same technique bpftrace + libbpf use.

This unlocks scripts whose total state would otherwise exceed BPF's
hard 512-byte stack limit. Opensnoop's `sys_exit` body (multiple
str-var buffers, a for-loop's iteration scratch, chained-field
intermediates) needed ~520 bytes on the stack before; it now compiles
and runs.

#### bpftrace: more positions for `str()` / `kstr()`

`str()` and `kstr()` are now usable as:

- map value: `@filename[tid] = str(args.filename)`
- `$var` value: `$path = str(@filename[tid])`
- printf arg with explicit size: `printf("%.32s", str(p, 32))`

`$var`s backed by a string buffer can be indexed with `$v[i]` (returns
the byte at offset `i`). Combined with literal-string indexing
(`"/"[0]` folds at compile time), conditions like `$path[0] != "/"[0]`
work as written.

#### bpftrace: per-tracepoint `args.FIELD` resolution

`args.FIELD` is now resolved against *the format file of the current
probe's tracepoint*, not via a script-wide `tp-FIELD` macro. This was
silently mis-loading in scripts that attach the same field name to
multiple tracepoints with different layouts. The most common case:
opensnoop attaches `args.filename` to `sys_enter_open` (filename at
offset 16) **and** `sys_enter_openat` (filename at offset 24 — `dfd`
occupies offset 16). The shared macro was using `sys_enter_open`'s
offset for every probe, so on `openat` we were storing the file
descriptor `int` instead of the user pointer, and `probe_read_user_str`
later returned zero bytes — empty filenames in the output.

#### bpftrace: field-chain types flow through `$var = chain` assignments

```
$dentry = curtask.fs.pwd.dentry;   // $dentry now typed as `dentry'
$vfsmnt = curtask.fs.pwd.mnt;       // $vfsmnt typed as `vfsmount'
$mnt_root = $vfsmnt.mnt_root;       // walk through vfsmount struct
```

The `$v = chain; $v.field` stash pattern that bpftrace tools lean on
heavily now works. `field-chain-leaf-struct` walks the chain through
vmlinux BTF and records the leaf pointer's target struct as the
left-hand `$var`'s type. The walker correctly unwraps typedef /
`const` / `volatile` so `const struct qstr *` resolves to `qstr` (and
not to a const-wrapper whose `vlen` is 0).

#### bpftrace: more tool surface

Several bpftrace tools that previously didn't compile now do, thanks
to a long tail of surface-language additions in this window:

- `tuple` keys for composite map keys (`@m[(args.dev, args.sector)]`)
  and `has_key(@m, k)` for explicit presence checks.
- `let @m = lruhash(N);` / `hashmap(N)` top-level map declarations
  (parsed; type inferred from usage).
- `offsetof(struct NAME, FIELD)` resolved at compile time via BTF.
- `cgroup_path()`, `cat()`, `join(argv)`, `buf(ptr, len)` with the
  matching `%r` printf conversion for byte-array output.
- `getopt()` stub returning the literal default value (so scripts
  that use macros built on `getopt("flag", DEFAULT, "help")` parse
  and run as if the flag is unset).
- `time("FMT")` strftime format strings; `%f` microseconds resolved
  from the kernel timestamp.
- `kaddr()` falls back to `/boot/System.map` when `kallsyms` is
  zeroed (the `kptr_restrict` case on hardened distros).
- `elapsed` builtin (script-start nsecs offset, populated via a
  hidden map at runtime).
- `ntop(addr)` as a map value (17-byte family+address layout in the
  map slot).
- `strerror(errno)` rendered as `%s` via userspace `strerror(3)` at
  print time.
- `let` declarations, `comm == "literal"` predicates, `*expr`
  user-pointer deref, 2-arg `delete(@m, k)`, no-paren `if`, `ppid`
  builtin, `func` / `probe` as map keys/values, `$var-typed`
  comparison for `tcplife`-style scripts.

#### bpftrace: minimal C preprocessor + `config = { … }`

`#include <…>` is silently dropped; `#define NAME INT` populates a
per-parse table; `#ifndef BPFTRACE_HAVE_BTF` always takes the
BTF branch. The grammar accepts and ignores top-level
`config = { … }` blocks so existing tools parse without surfacing
their runtime knobs.

#### bpftrace: tool runner robustness

Multi-target probe attachment no longer aborts on the first failure:
individual attach errors are reported and the rest of the probes keep
running. Bare uprobe library names (`uprobe:libssl:SSL_read`) resolve
through `ldconfig -p`.

### Bug Fixes

#### SSA optimizer: `simplify-cfg` linear-chain merger

The CFG-merge sub-pass was using a stale `compute-cfg-edges`
snapshot, doing multiple merges in one sweep, and dropping
non-trivial PHIs whose dst was still in use elsewhere. The downstream
symptom was malformed IR that passed `ir-well-formed-p` (which only
checked vreg defs) and crashed the emitter's jump-fixup pass with
`NIL is not of type NUMBER` — surfacing in `compile-bpf-forms` as the
unhelpful `NIL is not of type COMPILATION-UNIT`.

The pass is now correctness-first:

- Refuses to merge when the successor has any non-trivial PHIs.
- One merge per sweep — the outer `while changed` loop restarts and
  re-runs `compute-cfg-edges` with fresh data.
- Rewrites label references in surviving blocks at the time of the
  merge.

A new `prune-stale-phi-args` pass runs before and after `simplify-cfg`
so PHI arg labels always match the actual predecessor set; single-arg
result collapses to `:mov`, empty result to `(:mov 0)`.

`ir-well-formed-p` now also rejects branch / PHI label args that
reference removed blocks, catching a future regression at the gate
instead of crashing the emitter. `fix-dangling-branches` remains as
defence-in-depth.

#### AST: integer comparisons and constant-test `IF`/`WHEN`/`UNLESS` fold early

`constant-fold-sexpr` now folds integer comparisons (`=`, `/=`, `<`,
`<=`, `>`, `>=`) to `1`/`0` and `(IF int then else)` /
`(WHEN int body)` / `(UNLESS int body)` to the live branch. This
eliminates patterns like `(if 0 …)` — generated by bpftrace's
`getopt(name, false, …)` macros — before they reach the SSA
optimizer's CFG-merge passes.

#### bpftrace: macro `$name` vs bare `name` params no longer conflated

`macro sys_exit(ret, @filename, @paths) { $ret = ret; … }` now
correctly distinguishes the bare `ret` macro param from the local
`$ret` variable. Previously both were substituted with the call-site
value, so `$ret = ret` became `args.ret = args.ret` and downstream
references to `$ret` saw the wrong shape.

#### bpftrace: small surface fixes

- `printf("%.32s", …)` precision spec now parsed and applied to `%s`
  truncation in the userspace formatter (was silently ignored).
- `ntop`'s 17-byte slot layout: address at offset 0, family byte at
  offset 16 (was swapped — broke `printf("%s", $v)` for ntop-typed
  `$var`s read from a map).
- Cast binds to a full postfix expression, not just to a primary, so
  `(struct sock *)retval.field` parses as `cast(retval.field)`
  (matches bpftrace), not `cast(retval).field`.
- `:str` map keys (produced when `func` / `probe` are used as keys)
  now round-trip through pointer-mode map ops without truncation.
- Cross-program shared string buffer: one probe-scope scratch slot
  serves every `gen-string-set` instead of allocating one per
  literal — `writeback.bt`'s 8 × 64-byte reason strings no longer
  blow the 512-byte stack.
- `time()` with no argument emits a real newline, not a literal
  `~%`.

## 1.9.0 — 2026-05-27


### New Features

#### bpftrace-compatible frontend

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

#### Userspace stack symbolisation

A new `whistler/symbolize` package resolves userspace addresses
(typically captured by `bpf_get_stackid` with `BPF_F_USER_STACK`)
into `name+0xOFFSET [library] file:line` strings. Pure Common Lisp:
ELF64 reader for symbol tables, build-ID / `.gnu_debuglink` fallback
for separate debug files, and a DWARF 4 / DWARF 5 `.debug_line`
state-machine interpreter for source file + line. Per-pid
`/proc/<pid>/maps` snapshots survive process exit.

`@[ustack]` in a bpftrace script automatically uses the symboliser
when debuginfo is available; bare hex frames otherwise.

#### kfunc / kretfunc probe support

The loader gained native fentry / fexit (BTF-trampoline) probe
attachment: `BPF_PROG_TYPE_TRACING` with
`expected_attach_type = BPF_TRACE_FENTRY / FEXIT`,
`attach_btf_id` resolved from `/sys/kernel/btf/vmlinux`, attached
via `BPF_LINK_CREATE`. Both `attach-fentry` (loader) and
`kfunc:` / `kretfunc:` (bpftrace) entry points are wired up.

#### CI: ocicl dependencies + live kernel verifier

CI workflow switched from Quicklisp to [ocicl](https://github.com/ocicl/ocicl),
with `ocicl.csv` pinning iparse / fiveam plus their transitive
closure by sha256 digest. A new `kernel-verify` job runs
`make test-torture` under `sudo` on the GitHub-hosted runner — all
161 torture programs round-trip through `BPF_PROG_LOAD` on every
push, so verifier regressions surface immediately.

### Bug Fixes

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

## 1.8.0 — 2026-05-01


### New Features

- **LSM program support.** The loader now supports Linux Security
  Module (LSM) BPF programs. Programs with `lsm/` section names are
  detected automatically, BTF func IDs are resolved from
  `/sys/kernel/btf/vmlinux`, and attachment uses `BPF_LINK_CREATE`.
  `with-bpf-session` handles LSM programs with `(bpf:attach prog)` --
  no target argument needed.

### Bug Fixes

- **Return instruction across branches.** The emitter now always emits
  `mov r0, src` on return, even when the source is already in r0.
  Previously, multi-branch programs where different branches left the
  return value in different registers could produce incorrect code.

- **Parallel move resolution.** Fixed the safety check in the parallel
  move scheduler. The check now correctly tests whether the
  destination register is read as a source by another pending move,
  rather than checking the wrong direction.

## 1.7.0 — 2026-04-20


### New Features

- **Field-name context access.** `(ctx field-name)` reads a context
  struct field by name instead of raw offset. `(setf (ctx field-name) val)`
  writes. The compiler resolves fields from the program type's context
  struct (`xdp_md`, `__sk_buff`, `bpf_sock_addr`, `bpf_sock_ops`).
  Array fields use `(ctx user-ip6 0)`. Legacy `(ctx u32 4)` still works.

- **BTF-driven field resolution.** Context field offsets are resolved
  from `/sys/kernel/btf/vmlinux` at compile time when available,
  matching the build host's actual kernel layout. Falls back to a
  static table when BTF is unavailable. Set `*vmlinux-btf-path*` for
  cross-compilation.

- **CO-RE relocations for context access.** Field-name `ctx` access
  emits BPF CO-RE (Compile Once, Run Everywhere) relocations
  automatically. The loader patches offsets at load time based on the
  target kernel's BTF. Both reads and writes are covered.

- **`defunion`**: Stack-allocate the size of the largest member and
  access through any member's field accessors. Useful for reusing a
  single buffer across protocol header types.

- **`ringbuf-output`**: Direct ring buffer output via
  `bpf_ringbuf_output` -- build a struct on the stack, then copy it
  in one helper call. Complements the existing `with-ringbuf`
  (reserve/submit) pattern.

- **Setf-able `ctx` form.** `(setf (ctx ...) val)` replaces the
  deprecated `ctx-store`. Supports multi-pair setf.

- **Mov-chain forwarding peephole pass.** Eliminates redundant
  register-to-register move chains in the post-regalloc BPF output.

### Bug Fixes

- **Store register clobbering.** Fixed cases where the emitter reused
  a source register as a scratch register during store operations,
  corrupting the value before it was written.

- **Ringbuf pointer spilling.** The register allocator now correctly
  handles ringbuf reserve pointers that are live across helper calls.

- **Mov-chain forwarding safety.** The peephole pass no longer forwards
  through moves whose source is overwritten before the consumer.

### New Example

- **Cgroup outbound firewall** (`examples/cgroup-firewall.lisp`): A
  process-level outbound firewall using three cooperating cgroup
  programs (`connect4`, `sockops`, `cgroup_skb/egress`) with shared
  maps, transparent proxy redirection, and ring buffer event logging.

## 1.6.2 — 2026-04-18


### Bug Fixes

- **TC detach scoped to our filter**: Previously, detaching a TC program
  removed all filters in the direction. Now only the specific pinned
  filter is cleaned up.

- **cgroup bind/post_bind support**: `cgroup/bind4`, `cgroup/bind6`,
  `cgroup/post_bind4`, and `cgroup/post_bind6` sections now correctly
  map to their expected attach types, fixing kernel load failures.

- **Tracepoint per-CPU attachment**: Tracepoint perf events are now
  opened on all online CPUs instead of only CPU 0. CPU enumeration
  uses actual IDs from sysfs, fixing attachment on sparse CPU
  topologies.

- **Removed dead `map-lookup-delete` code** that referenced a constant
  no longer present.

## 1.6.1 — 2026-04-11


### Migration Guide

#### defstruct CL-side type is now CLOS

The CL-side record type generated by `defstruct` is now a CLOS `defclass`
instead of a CL `defstruct`. The `-RECORD` suffix is retained. The public
API is unchanged:

```lisp
(make-my-event-record :pid 0 :ts 0)    ; constructor
(my-event-record-pid ev)               ; accessor
(decode-my-event bytes)                 ; decoder
(encode-my-event record)               ; encoder
```

If your code relied on CL struct internals (`copy-structure`, `#S(...)`
reader syntax, `my-event-record-p`), switch to standard CLOS patterns.

#### New convenience packages

Two packages are provided for REPL use, with CL symbol conflicts
pre-resolved:

```lisp
(in-package #:whistler-user)           ; compiler only
(in-package #:whistler-loader-user)    ; compiler + loader
```

`make repl` and `make repl-loader` use these by default.

#### Typed map operations

New loader functions eliminate manual key/value encoding:

```lisp
;; Before
(map-lookup info (encode-int-key 42 4))

;; After
(map-lookup-int info 42)
```

Full list: `map-lookup-int`, `map-update-int`, `map-delete-int`,
`map-lookup-struct-int`, `map-update-struct-int`,
`map-get-next-key-int`, and byte-vector variants without the `-int`
suffix.

#### Decoding ring buffer consumers

`open-decoding-ring-consumer` and `with-decoding-ring-consumer` auto-decode
events using a struct's `decode-NAME` function:

```lisp
;; Before
(open-ring-consumer map-info
  (lambda (sap len)
    (let ((buf (make-array len :element-type '(unsigned-byte 8))))
      (dotimes (i len) (setf (aref buf i) (sb-sys:sap-ref-8 sap i)))
      (let ((ev (decode-my-event buf)))
        (process ev)))))

;; After
(with-decoding-ring-consumer (consumer map-info 'my-event)
  (ring-poll consumer :timeout-ms 1000))
```

### New Features

- `attach-obj-xdp` and `attach-obj-tc` in the loader.
- `bpf-session-map` and `bpf-session-prog` convenience accessors.
- `make repl` starts in `whistler-user`; `make repl-loader` starts in
  `whistler-loader-user`.

### Documentation

- Updated inline-session, ring buffer, and map documentation with new APIs.
- Updated defstruct docs to reflect CLOS record type.

## 1.6.0 — 2026-04-11


### New Features

- Torture test suite (`tests/test-torture.lisp`): 161 programs stress-testing
  ALU, comparisons, control flow, register pressure, maps, helpers, loops,
  packet parsing, and complex combinations. When run with `CAP_BPF`
  (`make test-torture`), output is validated against the real kernel BPF
  verifier. Codegen validation tests check constant folding, helper IDs,
  branch structure, callee-saved register usage, and stack allocation.

- Compile-time context access validation: `ctx-load` now checks access
  widths against the known context struct layout for XDP (`xdp_md`) and TC
  (`__sk_buff`) programs. Invalid widths produce a clear error with a fix
  suggestion.

### Bug Fixes

- **Wrong helper in map-lookup-delete fusion.** The SSA optimizer fused
  `map-lookup` + `map-delete` into BPF helper 46, which is
  `bpf_get_socket_cookie` -- not `bpf_map_lookup_and_delete_elem` (a
  userspace syscall, not an in-kernel helper). The fusion is disabled and
  the bogus constant removed.

- **Missing SSA phis for `setf` in loops.** `setf` inside `dotimes`
  updated the environment but did not create phi nodes at the loop header.
  `lower-dotimes` now pre-inserts phis for all in-scope variables; DCE
  removes unused ones.

- **Missing SSA phis for `setf` in branches.** `setf` in one arm of
  `if`/`when`/`unless` created a new vreg without merging at the join
  point. `lower-if` now inserts phis for variables whose vregs differ
  between branches.

- **Missing phi moves on `br-cond` edges.** `emit-br-cond-insn` emitted
  plain conditional + unconditional jumps without phi resolution copies.
  Phi-move emission is factored into a shared helper called by both `:br`
  and `:br-cond`, with trampoline blocks when needed.

- **Nested loop phi predecessor.** Inner `dotimes` referenced the program
  entry block instead of the block where the counter init was emitted.

- **R0 in caller-free pool.** The register allocator documented R0 as
  reserved but still included it in the allocatable pool.

### Documentation

- Fixed stale `ctx`-passing API across 7 book pages (`xdp-data ctx` etc.).
- Updated `defprog` syntax from `(&key ...)` to `(:type ... :section ...)`.
- Updated examples to use zero-argument accessor macros and `with-ringbuf`.
- `book/book/` added to `.gitignore`.

## 1.5.0 — 2026-04-02


### New Features

- Tracepoint attachment support in the loader. New `attach-tracepoint`
  function resolves tracepoint IDs from tracefs and attaches BPF programs
  via perf events. `bpf:attach` in `with-bpf-session` now automatically
  dispatches tracepoint programs. (issue #32)

- New `fork-tracker` example demonstrating inline BPF session with
  tracepoint attachment (`sched/sched_process_fork`).

### Bug Fixes

- Fix off-by-one in `section-to-prog-type` that caused tracepoint
  programs to be loaded as `BPF_PROG_TYPE_SOCKET_FILTER`. (issue #32)

- Fix `+perf-type-tracepoint+` constant: was 1 (`PERF_TYPE_SOFTWARE`),
  now correctly 2 (`PERF_TYPE_TRACEPOINT`). (issue #32)

## 1.4.0 — 2026-04-02


### New Features

- Add LRU hash map type support (`:lru-hash` in `defmap`). LRU hash maps
  automatically evict least-recently-used entries when full.

### Bug Fixes

- Fix helper call argument clobbering with parallel-move resolution (issue #31).

## 1.3.0 — 2026-03-30


### New Features

- `import-kernel-struct` now supports embedded (non-scalar) struct fields (#30)
  - Embedded struct accessors return the field address (`ptr + offset`) instead of attempting a load
  - Enables natural chaining: `(msghdr-msg-iter msg)` -> `(iov-iter-__iov iter)` -> `(iovec-iov-base iov)`
  - No more hardcoded offsets for navigating nested kernel structs
- Compile-time type checking for kernel struct pointers
  - `(as-msghdr ptr)` tags a pointer with its struct type
  - Accessors verify the tag at compile time -- passing the wrong struct type is an error
  - Embedded struct accessors propagate types automatically
  - Bare untyped pointers still work (fully backward compatible)

### Bug Fixes

- `import-kernel-struct` no longer silently drops non-scalar fields

## 1.2.0 — 2026-03-30


### Bug Fixes

- Fix kprobe/uprobe attachment opening one perf event per CPU, causing duplicate events on every probe hit (#29)
- Fix ringbuf mmap EPERM on kernels with strict memory protection checks (#27)
- Fix attach-tc BPF_OBJ_PIN field ordering and error handling

### New Features

- TC (sched_cls) packet parsing macros: `with-tc-packet`, `with-tc-tcp`, `with-tc-udp` with `TC_ACT_OK`/`TC_ACT_SHOT` return codes (#28)
- TC/clsact BPF program attachment via `attach-tc`
- Compile-time validation for 8 common BPF verifier failure patterns (atomic-add arity, alignment, unchecked map pointers, and more)
- Kprobe retprobe support in `attach-kprobe`

## 1.1.0 — 2026-03-28


### New features

- **`kernel-load` form** — Safely read from kernel pointers via
  `probe-read-kernel`. `(kernel-load u32 task 2772)` expands to a
  stack-alloc + probe-read-kernel + load sequence.

- **`import-kernel-struct` uses `kernel-load`** — Generated accessors
  now use `kernel-load` instead of direct `load`, making them safe for
  kernel pointers (e.g., from `get-current-task`) by default.

- **Anonymous struct/union flattening in `import-kernel-struct`** — The
  BTF parser now recursively descends into anonymous struct/union members,
  surfacing their fields as direct members. Fields like `skc_daddr` and
  `skc_dport` inside `sock_common`'s anonymous unions are now accessible.

- **`get-current-task` and `probe-read-kernel` helpers** — BPF helpers
  #35 and #113 for kernel struct traversal.

- **`reset-compilation-state`** — Exported function to clear accumulated
  maps/programs/structs between `compile-to-elf` calls in the REPL.

- **Stack usage breakdown in error messages** — When the 512-byte BPF
  stack limit is exceeded, the error now includes a per-category breakdown
  (struct-alloc, register spills, map key temporaries, etc.).

- **`:value-type` for `defmap`** — Explicit struct-valued map declarations.

- **aarch64 support for `pt-regs-parm1..6`** — Architecture-specific
  pt_regs offsets with compile-time error on unsupported platforms.

### Bug fixes

- **Fix phi-threading dropping vreg definitions (issue #12)** —
  `phi-branch-threading` redirected predecessor branches but left stale
  inputs in phi instructions. After `simplify-cfg` merged blocks, the phi
  destination vreg lost its definition, causing the emitter to assign it
  to a callee-saved register that collided with prior helper call results
  (e.g., `ktime-get-ns` in R7). Fixed by removing the threaded input from
  the phi when redirecting the predecessor.

- **Fix nil call-dst crash in `hoist-loads-before-calls`** — Void helper
  calls (unused result after dead-destination-elimination) caused a type
  error in the `/=` comparison.

## 1.0.1 — 2026-03-23


### Bug fixes

- **`with-bpf-session` from CL-USER** — Fixed a crash when using
  `with-bpf-session` from packages other than `whistler`. Symbols like
  `incf` and `getmap` in the `bpf:prog` body resolved to `CL:INCF` and
  `CL-USER::GETMAP` instead of their Whistler equivalents, causing the
  compiler to produce invalid IR. The session macro now re-interns body
  symbols into the `whistler` package before compilation.

- **Unbound variable error reporting** — Fixed a TYPE-ERROR in the
  lowerer's error handler that crashed instead of printing the diagnostic.
  The handler called `search` on a symbol instead of its name.

## 1.0.0 — 2026-03-22


Whistler 1.0 is a complete Lisp-to-eBPF platform: compiler, loader, and
inline session runtime — all in pure Common Lisp with zero external
dependencies.

### Compiler

An SSA-based optimizing compiler that produces eBPF ELF objects matching
or beating `clang -O2` on instruction count. Includes copy propagation,
constant propagation, SCCP, dead code elimination, LICM, CSE,
store-to-load forwarding, PHI-branch threading, bitmask fusion, ALU
narrowing, live-range splitting, and peephole optimization.

### Loader (`whistler/loader`)

A pure Common Lisp BPF userspace loader — no libbpf, no CFFI. Loads
`.bpf.o` files, creates maps, patches relocations, loads programs, and
attaches kprobes/uprobes/XDP. Includes ring buffer consumer and map
iteration. All syscalls via SBCL's `sb-alien`.

### Inline sessions (`with-bpf-session`)

Write BPF programs and userspace code in one Lisp form. The compiler runs
at macroexpand time; bytecode is embedded as a literal in the expansion:

```lisp
(with-bpf-session ()
  (bpf:map counter :type :hash :key-size 4 :value-size 8 :max-entries 1024)
  (bpf:prog trace (:type :kprobe :section "kprobe/..." :license "GPL")
    (incf (getmap counter 0)) 0)
  (bpf:attach trace "__x64_sys_execve")
  (loop (sleep 1) (format t "~d~%" (bpf:map-ref counter 0))))
```

### Kernel integration

- **`deftracepoint`** — auto-resolve tracepoint field offsets from
  `/sys/kernel/tracing/events/` at compile time.
- **`import-kernel-struct`** — import kernel struct definitions from
  `/sys/kernel/btf/vmlinux` at compile time. No kernel headers needed.

### Struct codec

`whistler:defstruct` generates both BPF macros and CL-side struct with
byte-level decode/encode — one definition serves kernel and userspace.

### Protocol library

Ethernet, IPv4, IPv6, TCP, UDP, ICMP headers with compile-time accessors
and statement-oriented parsing macros (`with-packet`, `with-tcp`, etc.).

### Polyglot header generation

`--gen c`, `--gen go`, `--gen rust`, `--gen python`, `--gen lisp` produce
matching struct definitions from `defstruct` — one source of truth.

### Since 0.7.0

- **SCCP pass** — sparse conditional constant propagation through PHIs
- **`deftracepoint`** — kernel tracepoint field auto-resolution
- **`import-kernel-struct`** — vmlinux BTF struct import
- **IPv6 and ICMP** protocol headers
- **`ir-dump`** for SSA inspection during development
- **Uprobe symbol fix** — correct PT_LOAD segment-based vaddr→file offset
- **Array codec fix** — non-u8 array fields decode/encode correctly
- **XDP attachment** — accepts mode (xdp/xdpdrv/xdpgeneric)
- **CPU topology** — handles comma-separated multi-range formats
- **Zero dependencies** — no external CL libraries required

## 0.7.0 — 2026-03-21


### New: `whistler/loader` — pure Common Lisp BPF loader

A complete userspace BPF loader with zero C dependencies. Load `.bpf.o`
files, create maps, attach probes, read maps, and consume ring buffers
from SBCL:

```lisp
(whistler/loader:with-bpf-object (obj "my-probes.bpf.o")
  (whistler/loader:attach-obj-kprobe obj "trace_execve" "__x64_sys_execve")
  ...)
```

Components: ELF parser, BPF map operations, map FD relocation patching,
program loading with verifier error capture, kprobe/uprobe/XDP attachment,
ring buffer consumer via mmap + epoll.

### New: `with-bpf-session` — inline BPF in one Lisp form

Compile BPF code at macroexpand time and load it at runtime. No `.bpf.o`
files, no build step — one file, one language:

```lisp
(with-bpf-session ()
  (bpf:map stats :type :hash :key-size 4 :value-size 8 :max-entries 1024)
  (bpf:prog counter (:type :kprobe :section "kprobe/..." :license "GPL")
    (incf (getmap stats 0)) 0)
  (bpf:attach counter "__x64_sys_execve")
  (loop (sleep 1) (format t "~d~%" (bpf:map-ref stats 0))))
```

The `bpf:` prefix separates kernel-side declarations from userspace CL code.
Uprobe vs kprobe is auto-detected from the section name.

### New: struct decode/encode for userspace

`whistler:defstruct` now generates a CL struct and byte codec alongside the
BPF macros — one definition serves both kernel and userspace:

- `NAME-RECORD` — CL `defstruct` with matching slots
- `decode-NAME` — bytes → CL struct
- `encode-NAME` — CL struct → bytes (round-trips perfectly)

### New features

- **MIT LICENSE file** added.
- **`--gen lisp`** documented in README alongside C/Go/Rust/Python.

### Improvements

- **Zero external CL dependencies.** Removed `cl-version-string`; version
  now comes from ASDF system definition. Only SBCL required.
- **Struct field stores auto-truncate.** No `cast` needed when writing a
  wider value to a narrow field — `(setf (my-u8-field ptr) u16-val)` works.
- **Self-contained ffi-call-tracker example.** Complete standalone inline
  BPF program with uprobe attachment and stats display in one Lisp file.

## 0.6.0 — 2026-03-21


### New features

- **`with-ringbuf`** — Reserve/null-check/submit pattern in one form:
  ```lisp
  (with-ringbuf (event events (sizeof my-event))
    (setf (my-event-type event) 1)
    ...)
  ```

- **`fill-process-info`** — Fill pid, uid, timestamp, and comm fields from
  BPF helpers using struct accessor names, replacing ~8 lines of boilerplate.

- **Multi-pair `setf`** — Standard CL `setf` with multiple place/value pairs:
  ```lisp
  (setf (my-struct-a ptr) 1
        (my-struct-b ptr) 2
        (my-struct-c ptr) 3)
  ```

- **`defmap` defaults** — `:key-size` and `:value-size` default to 0, so
  ringbuf maps only need `(defmap events :type :ringbuf :max-entries 262144)`.

- **Structured compiler errors** — All error messages now have `what`, `where`,
  `expected`, and `hint` fields with context-specific suggestions.

### Compile-time diagnostics

- **Narrow type as pointer** — Error when a `u8` or `u16` value is passed as
  a pointer argument to `probe-read`, `probe-read-user`, etc. (Fixes #8)

- **Helper argument count** — Error when a BPF helper is called with the wrong
  number of arguments (e.g., `(ktime-get-ns 42)` instead of `(ktime-get-ns)`).

- **Malformed let bindings** — Detects `(let (x 1) ...)` and suggests the
  correct `(let ((x 1)) ...)` with double parentheses.

- **Unbound variables** — Shows variables currently in scope.

- **Unknown forms** — Detects CL functions used in BPF context
  (e.g., `format`, `loop`) with an explanation that they're not available.

- **Stack overflow** — Reports exact bytes needed when the 512-byte BPF stack
  limit is exceeded.

## 0.5.4 — 2026-03-20


### Bug fixes

- **Fix ctx-load reading from uninitialized stack spill.** When the register
  allocator spilled the ctx vreg to the stack, `emit-ctx-load-insn` loaded
  from the uninitialized spill slot instead of using R6 (where ctx was
  saved). Now uses R6 directly for all ctx-loads. (Fixes #10)

- **Prevent register allocator from evicting ctx out of R6.** The spill
  candidate selection could evict the ctx interval and reassign R6 to another
  variable. The ctx interval now has infinite lifetime and is excluded from
  spill candidates. (Fixes #10)

- **Fix jump offset corruption in peephole self-move elimination.** The
  `eliminate-redundant-movs` pass used `remove-if` to delete `mov rX, rX`
  instructions without adjusting jump offsets, causing "jump out of range"
  verifier failures in large programs. Now uses `reindex-after-deletion`.
  (Fixes #11)

- **Fix peephole coalesce-copy setting register fields on JA instructions.**
  The register rename phase replaced dst/src fields on unconditional jump
  instructions which don't use them. The BPF verifier rejects non-zero
  reserved fields with "BPF_JA uses reserved fields". (Fixes #11)

## 0.5.3 — 2026-03-20


### Bug fixes

- **Fix R0 not set before exit after helper call in kprobe/tracepoint
  programs.** The `elide-tracepoint-return` optimization cleared return value
  operands for kprobe and tracepoint programs, causing bare `exit` instructions
  with undefined R0 after helper calls. The BPF verifier requires R0 to be
  set before every exit, regardless of program type. (Fixes #9)

- **Give `let` proper CL semantics (parallel bindings).** `let` previously
  evaluated bindings sequentially (like `let*`). Now all init forms are
  evaluated before any variables are bound, matching standard Common Lisp.

### New features

- **`let*` support.** Sequential binding form where each init can reference
  prior bindings in the same form.

- **`ash` support.** CL's arithmetic shift function now works in BPF programs
  with constant shift counts. Positive counts compile to left shifts, negative
  to right shifts. (Fixes #6)

## 0.5.2 — 2026-03-19


### Bug fixes

- **Fix BTF encoding for structs with array fields.** Array field types
  (`BTF_KIND_ARRAY`) were interleaved with struct member entries, producing
  malformed BTF that libbpf and bpftool rejected. (Fixes #1)

- **Fix ELF map symbols: emit `STT_OBJECT` with size.** Map symbols were
  emitted as `NOTYPE` with size 0, causing libbpf's `bpf_object__open()` to
  fail matching BTF `VAR` entries to ELF symbols. (Fixes #2)

- **Stop emitting CO-RE relocations for user-defined structs.** All struct
  field accesses generated CO-RE relocations, causing libbpf to search kernel
  BTF, fail, and replace every access with an invalid instruction. User-defined
  structs now emit direct loads/stores with compile-time offsets. (Fixes #3)

- **Convert BTF struct field names from hyphens to underscores.** Field names
  retained Lisp-style hyphens which the kernel BTF validator rejected as
  invalid C identifiers. (Fixes #4)

- **Use defprog name for FUNC symbols instead of section name.** FUNC symbols
  used the ELF section path (e.g. `kprobe/__x64_sys_execve`) which contains
  slashes that the kernel rejects. Now uses the defprog name. (Fixes #5)

## 0.5.1 — 2026-03-19


### Bug fixes

- **Fix phi resolution at loop back-edges.** Programs with helper calls
  (e.g. `probe-read-user`) inside `dotimes` loops could fail BPF verification
  with "R2 !read_ok" because the loop counter's caller-saved register was
  stale after helper calls clobbered it. The emitter now inserts phi
  resolution moves at all predecessor branches instead of only at the phi
  instruction site.

### New features

- **Struct-key map macros.** `getmap`, `setmap`, `incf`, `remmap`, and
  `delmap` now automatically dispatch to `-ptr` variants at compile time
  when the map's `:key-size` exceeds 8 bytes. No source changes needed —
  just use the high-level macros with struct pointer keys.

- **`do-user-ptrs`** — Iterate over a user-space array of pointers with
  automatic bounded iteration, pointer read, and null guard:
  ```lisp
  (do-user-ptrs (ptr base-ptr count +max+ :index i)
    body...)
  ```

- **`do-user-array`** — Iterate over a user-space array of scalars or
  structs:
  ```lisp
  (do-user-array (val u32 array-ptr count +max+)
    body...)
  (do-user-array (entry my-struct entries-ptr count +max+ :index i)
    body...)
  ```

## 0.5.0 — 2026-03-19


### Bug Fixes

- **Value-size-aware map macros.** `getmap`, `setmap`, `incf-map`, and
  `atomic-add` now derive the correct BPF operation width (u8/u16/u32/u64)
  from the map's declared `:value-size`. Previously these were hard-wired
  to 64-bit, emitting invalid `ldxdw`/64-bit atomics for maps with smaller
  value sizes.

- **Reject conflicting licenses in multi-program builds.** `compile-to-elf`
  now signals an error when programs declare different licenses instead of
  silently using the first program's license for all.

### New Optimization Passes

- **CFG simplification.** Folds constant branches, merges jump-only blocks
  and linear chains, removes unreachable blocks. Runs in a fixed-point
  loop to catch cascading opportunities.

- **Common subexpression elimination.** Intra-block CSE for pure ALU ops,
  byte-swaps, casts, and memory loads (invalidated on stores/calls).

- **Store-to-load forwarding.** Replaces loads from just-stored locations
  with the stored value, eliminating memory round-trips.

- **Loop-invariant code motion.** Detects natural loops, hoists invariant
  instructions (constants, ctx-loads, pure ALU) to the loop preheader.

- **Trivial phi elimination.** Collapses PHI nodes where all inputs
  converge to the same value.

- **Fixpoint canonicalization.** Copy-prop, const-prop, phi elimination,
  CFG simplification, and DCE now iterate to a fixed point, catching
  multi-step optimization chains that single-pass missed.

### Code Size Improvements

| Example          | 0.4.1 | 0.5.0 | Saved |
|------------------|-------|-------|-------|
| synflood-xdp     |    71 |    68 |    -3 |
| ratelimit-xdp    |    62 |    55 |    -7 |
| runqlat           |    57 |    37 |   -20 |
| multi-prog        |    45 |    44 |    -1 |

### Test Suite

- New FiveAM-based test suite with 138 checks across 11 test files,
  covering opcode-level instruction verification, all optimization
  passes, protocol parsing, map operations, tail calls, ring buffers,
  multi-program builds, and ELF output validation. Run with `make test`.

### New Example

- `percpu-counter.lisp` — demonstrates LICM hoisting ctx-loads out of
  a loop.

## 0.4.1 — 2026-03-18


### Improvements

- **Restore map FD caching with control-flow safety.** Map file
  descriptor caching in callee-saved registers is re-enabled, replacing
  2-instruction `ld_pseudo` sequences with 1-instruction `mov` for
  repeated map references. The cache now uses dominator analysis to
  ensure a cached register is only reused when the caching block
  dominates the current block, preventing use of uninitialized
  registers on paths that bypass the first map reference.

## 0.4.0 — 2026-03-18


### Bug Fixes

#### BTF / ELF Compatibility (cilium/ebpf, libbpf)

- **Emit proper BTF line_info section.** The kernel requires at least
  one `bpf_line_info` entry per function when `func_info` is present.
  Previously the section was empty, causing cilium/ebpf to fail with
  "can't read record size: EOF".

- **Sanitize BTF FUNC names.** Section names containing slashes (e.g.
  `tracepoint/sock/inet_sock_set_state`) are now stripped to the last
  path component for the BTF FUNC type name, since slashes are invalid
  in BTF identifiers.

- **Consistent naming between ELF symbols and BTF VARs.** Map names
  now use `lisp-to-c-name` (lowercase, hyphens→underscores)
  consistently in both ELF symbol table entries and BTF VAR/DATASEC
  types. Previously a mix of uppercase/hyphens vs lowercase/underscores
  caused cilium/ebpf to report symbol/VAR count mismatches.

- **Case-insensitive kernel struct field lookup.** CO-RE field index
  resolution for kernel structs (e.g. `xdp_md`) now uses
  case-insensitive comparison, fixing incorrect relocations for fields
  like `data_end`.

#### Register Allocation

- **Spill across ring buffer helper calls.** `ringbuf-reserve`,
  `ringbuf-submit`, and `ringbuf-discard` are now recognized as
  call-like operations, so the register allocator correctly spills
  caller-saved registers (R1-R5) across these BPF helper calls.

#### Code Generation

- **Forward-only jumps for return statements.** When a program has
  multiple `return` statements, their exit blocks are now placed at the
  end of the instruction stream. This prevents backward jumps that
  trigger the BPF verifier's infinite loop detection.

- **Disable cross-block map FD caching.** Map file descriptor caching
  in callee-saved registers did not account for control flow, causing
  "R9 !read_ok" verifier errors when a cached register was
  uninitialized on some paths. Caching is disabled until a
  control-flow-aware implementation is added.

#### Peephole Optimizer

- **Fix tail-merge direction.** Duplicate `mov r0, IMM; exit`
  epilogues are now replaced with forward jumps to the *last*
  occurrence (previously the first), ensuring all exit jumps go
  forward as required by the BPF verifier.

- **Preserve jump-target `goto` instructions.** `goto pc+0`
  elimination now checks whether the instruction is itself a jump
  target before deleting it, preventing conditional branches from
  targeting past-the-end positions.

- **Fix redundant mask elimination.** `AND rX, MASK` was incorrectly
  deleted when the register's known bit-width equaled the mask's
  container size (e.g. a byte-loaded value ANDed with `0x0f` was
  treated as a no-op because both were classified as "8-bit"). Mask
  width is now computed using `integer-length`, so `0x0f` is correctly
  identified as 4 bits.

## 0.3.0 — 2026-03-18


### New features

- **Array fields in defstruct** — `(field-name (array type count))` declares
  fixed-size array fields with C-compatible layout. Generates indexed
  accessors `(name-field ptr idx)` with `setf` support, and pointer
  accessors `(name-field-ptr ptr)` for passing array addresses to BPF
  helpers. Constant indices fold to fixed offsets at compile time; runtime
  indices skip the multiply for byte-sized elements.

- **sizeof** — `(sizeof struct-name)` expands to the struct's byte size at
  compile time. Replaces magic numbers in `probe-read-user`,
  `ringbuf-reserve`, etc.

- **memset** — `(memset ptr offset value nbytes)` fills memory with widened
  stores. 16 bytes of `#xFF` compiles to 2 u64 immediate stores instead of
  16 u8 stores. Values representable as signed 32-bit (like -1 for 0xFF
  fill) use `mov` instead of `ld_imm64`, saving 2 instructions per store.

- **memcpy** — `(memcpy dst dst-off src src-off nbytes)` copies memory using
  the widest possible load/store pairs.

- **pt-regs-parm1 through parm6, pt-regs-ret** — x86-64 `struct pt_regs`
  access macros matching C's `PT_REGS_PARM1()` etc. from `bpf_tracing.h`.
  Eliminates raw register offset constants in uprobe/kprobe programs.

- **BTF array support** — Array fields emit proper `BTF_KIND_ARRAY` entries
  in the `.BTF` section.

- **Codegen for array fields** — Shared header generation (C, Go, Rust,
  Python, Common Lisp) emits correct array syntax for each language:
  `uint8_t field[16]`, `[16]uint8`, `[u8; 16]`, `ctypes.c_uint8 * 16`.

### Bug fixes

- **Fixed ELF output tests** — Updated `write-minimal-elf` and
  `write-elf-with-maps` tests to use the multi-program `write-bpf-elf` API
  introduced in 0.2.0. All 14 tests now pass.

## 0.2.0 — 2026-03-17


### Bug fixes

- **Fixed peephole store-load forwarding bug** that caused incorrect code
  generation when a spilled register was overwritten between the store and
  reload. The BPF verifier would reject programs with "R1 type=scalar
  expected=fp". This affected programs using `probe-read-user` with
  struct-alloc destinations.

### New features

- **BTF-defined maps** — Maps now use the modern `.maps` section with full
  BTF type information (BTF_KIND_VAR, BTF_KIND_DATASEC, struct with
  type/key_size/value_size/max_entries fields). Compatible with current libbpf.

## 0.1.0 — 2026-03-17


Initial release. A Lisp that compiles to eBPF.

### Features

#### Compiler
- SSA-based optimizing compiler producing code that matches or beats `clang -O2`
- 14 optimization passes: copy/constant propagation, bswap folding, dead code/store elimination, lookup-delete fusion, load hoisting, PHI-branch threading, bitmask fusion, ALU narrowing, live-range splitting
- Linear-scan register allocator with value classification, rematerialization, and backend portfolio search
- Peephole optimizer with tail merging, branch inversion, dead jump elimination
- Map-fd caching, struct key pointer caching, immediate store optimization

#### Surface Language
- Standard CL `let` bindings with optional types (inferred from initializers)
- `(declare (type ...))` for sub-64-bit narrowing
- CL-style `defstruct` with accessor functions and `setf` expanders
- CL-style map interface: `getmap`, `(setf (getmap ...))`, `remmap`, `incf`
- `when-let`, `if-let`, `case`, `with-tcp`, `with-ipv4`, protocol accessors
- Full CL macros at compile time

#### BPF Features
- XDP, TC, tracepoint, kprobe program types
- Multi-program ELF (multiple `defprog` in one file)
- Tail calls via `:prog-array` maps
- Ring buffer support (`ringbuf-reserve`, `ringbuf-submit`)
- CO-RE relocations via `.BTF.ext` for cross-kernel portability
- BTF type information for all structs and programs

#### Tooling
- CLI with `compile`, `disasm`, `--version`, `--help`
- `--gen` flag for shared type headers: C, Go, Rust, Python, Common Lisp
- Version strings via `cl-version-string` with git hash

### Examples

9 examples included:
- Packet counter, port blocker, SYN flood filter, rate limiter
- Run queue latency histogram (tracepoint)
- Tail call dispatcher, multi-program ELF
- TC classifier, ring buffer events

### Benchmarks

| Program | Whistler | clang -O2 |
|---------|----------|-----------|
| count-xdp | 11 | 11 |
| drop-port | 25 | 26 |
| synflood | 65 | 68 |

