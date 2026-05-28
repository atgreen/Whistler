# Whistler 1.10.0 Release Notes

## New Features

### bpftrace: range-based `for` loops with `break` / `continue`

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

### Per-CPU scratch maps lift the 512-byte stack ceiling

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

### bpftrace: more positions for `str()` / `kstr()`

`str()` and `kstr()` are now usable as:

- map value: `@filename[tid] = str(args.filename)`
- `$var` value: `$path = str(@filename[tid])`
- printf arg with explicit size: `printf("%.32s", str(p, 32))`

`$var`s backed by a string buffer can be indexed with `$v[i]` (returns
the byte at offset `i`). Combined with literal-string indexing
(`"/"[0]` folds at compile time), conditions like `$path[0] != "/"[0]`
work as written.

### bpftrace: per-tracepoint `args.FIELD` resolution

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

### bpftrace: field-chain types flow through `$var = chain` assignments

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

### bpftrace: more tool surface

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

### bpftrace: minimal C preprocessor + `config = { … }`

`#include <…>` is silently dropped; `#define NAME INT` populates a
per-parse table; `#ifndef BPFTRACE_HAVE_BTF` always takes the
BTF branch. The grammar accepts and ignores top-level
`config = { … }` blocks so existing tools parse without surfacing
their runtime knobs.

### bpftrace: tool runner robustness

Multi-target probe attachment no longer aborts on the first failure:
individual attach errors are reported and the rest of the probes keep
running. Bare uprobe library names (`uprobe:libssl:SSL_read`) resolve
through `ldconfig -p`.

## Bug Fixes

### SSA optimizer: `simplify-cfg` linear-chain merger

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

### AST: integer comparisons and constant-test `IF`/`WHEN`/`UNLESS` fold early

`constant-fold-sexpr` now folds integer comparisons (`=`, `/=`, `<`,
`<=`, `>`, `>=`) to `1`/`0` and `(IF int then else)` /
`(WHEN int body)` / `(UNLESS int body)` to the live branch. This
eliminates patterns like `(if 0 …)` — generated by bpftrace's
`getopt(name, false, …)` macros — before they reach the SSA
optimizer's CFG-merge passes.

### bpftrace: macro `$name` vs bare `name` params no longer conflated

`macro sys_exit(ret, @filename, @paths) { $ret = ret; … }` now
correctly distinguishes the bare `ret` macro param from the local
`$ret` variable. Previously both were substituted with the call-site
value, so `$ret = ret` became `args.ret = args.ret` and downstream
references to `$ret` saw the wrong shape.

### bpftrace: small surface fixes

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
