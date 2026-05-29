# Whistler bpftrace gaps

Tracks what's still missing between the whistler bpftrace frontend and
full bpftrace coverage, as measured by the runtime test suite. Final
tally of the last full run: **133 of 933 executed tests pass**. Real
bpftrace tools (`tools/*.bt`) still parse-and-compile at 38/38.

## Conventions

- "≈N" is the approximate number of distinct tests blocked by the gap
  (from `make bpftrace-runtime-test` output classification).
- "Effort" is the author's guess at unblocking scope: **S** = under a
  day, **M** = days, **L** = a real project.
- "Strategy" sketches where the work would land — file names, the
  relevant existing machinery — for whoever picks it up next.

## Major feature gaps

### `len(@map)` returns count of entries — **≈7 tests, M**

bpftrace's `len(@m)` returns the live entry count. The kernel BPF API
gives no count helper. Two viable approaches:

1. **Sidecar counter map.** Inject a 1-entry array map per `len()`-
   used `@m`; instrument every `@m[k] = …` site and `delete(@m, k)`
   to inc/dec it; rewrite `len(@m)` to read the sidecar. Touches
   `infer-maps`, `lower-map-assign`, `lower-call(delete)`, and a new
   inference pass that figures out which maps need a sidecar.
2. **`bpf_for_each_map_elem` (kernel ≥ 5.13).** Call the helper with
   a counter-bump callback. Cleaner kernel-side, but needs the
   callback-program codegen we don't have yet.

Today: `lower-len` errors with `arg must be 'comm', 'pcomm', or a
string-typed $var`.

### Pointer arithmetic on map values — **≈18 tests, M-L**

`@ = (int32 *) 0x32; @ -= 1;` should leave `@` at `0x32 - sizeof(int32)
= 0x2e`. bpftrace scales `+=`/`-=`/`++`/`--` by the pointed-to size.

Today: we lower `@-=1` as a plain integer decrement (`@` minus 1, not
minus 4). Requires `minfo-value-ptr-elt-size` (already in place from
the round-trip work) to flow into `lower-map-assign`'s `:+= / :-=`
arms, and into `lower-incdec` for the map branch.

### Bare `args` in fentry/kfunc — **≈3 tests, M**

`fentry:vfs_open { @ = args; }` — `args` as a whole struct, not
`args.field`. bpftrace serialises the struct (per the function's BTF
parameter types) into a byte buffer and stores it.

Strategy: in `lower-args` (codegen.lisp), when the access has no
`->field`, emit a struct-alloc sized to sum-of-BTF-param-widths, fill
each slot from the matching `ctx` offset, return the buffer pointer.
Update `infer-maps` so `@m = args` triggers a wide value-size.

### JSON output mode (`-q -f json`) — **≈16 tests, M**

bpftrace's `-f json` switches all printf/map-dump output to JSON.
Each printf becomes a `{"type":"printf","data":…}` line; map dumps
become `{"type":"map","data":{…}}`. The whistler runtime emits
human-formatted text only.

Strategy: a `*json-output-p*` dynvar wired from a new `-f json` CLI
flag; conditional in `lower-printf-string-literal` and in the map
print path. The printf format string still applies; JSON layer just
wraps each output unit.

### Tuple-as-map-value / tuple-as-var — **≈12 tests, M**

`@m = (1, "x")` and `$t = ($a, $b)` need to back the map value /
local var with a multi-slot struct, not a u64. We already track tuple
shape per-var in `*tuple-vars*` for key expansion; the missing piece
is treating a tuple as a *value*: store into a stack buffer with a
known per-slot layout, return the buffer pointer, and let downstream
prints / map-value paths read from it.

Strategy: add `*tuple-vars*`-style tracking to map minfo, then a
`gen-tuple-value-set` that uses the same per-slot layout as
`composite-key-layout`. Print path needs to format the recovered
tuple bytes per slot.

### `macro` hygiene + recursion — **≈19 tests, M**

Several macro tests hit substitution edge cases:
- Recursive / mutually recursive macros.
- Macros calling macros that take `@m` or `$x` params.
- Macros whose params shadow outer-scope vars.

Strategy: in `substitute-vars` and `inline-user-call`, generate fresh
gensyms per macro invocation so param vars don't collide. For
recursion, track an invocation stack and refuse to inline past depth.

### `buf(ptr, n)` byte-dump — **≈8 tests, M**

bpftrace's `buf()` captures N bytes from `ptr` into a hex-printable
buffer; `printf("%r", buf(…))` shows the hex dump. The codegen needs
to allocate, probe-read, and the runtime printer needs a `:buf` slot
type alongside `:string` / `:int`.

Strategy: extend `printf-arg-type` with `:buf SIZE`; add the
allocation+probe-read sequence in `lower-printf-arg`; add a runtime
formatter that renders hex (`%r` / `%llr`).

### `strftime(fmt, ts)` time formatting — **≈3 tests, S-M**

We have `time(fmt)` for the current time. `strftime(fmt, ts)` does
the same for an arbitrary timestamp. The userspace formatter already
exists; just need a separate async-time variant that takes a
timestamp expression.

Strategy: in `lower-async-time`, accept an optional second arg
(timestamp expr); if present, emit it in the ringbuf record instead
of `ktime_get_ns`. Runtime decoder uses the supplied ts.

## Probe-type gaps

### `usdt:…` USDT probes — **≈10 tests, L**

USDT probes need:
- Grammar entry for `usdt:PATH:PROVIDER:PROBE` and wildcards.
- Loader support: read the binary's `.note.stapsdt` notes, locate
  semaphore + base, attach uprobes per location.
- Codegen for `arg0..argN` reading from registers per the SDT
  argument spec.

### `iter:…` BPF iterators — **≈3 tests, M-L**

`iter:task { … }` runs a program for each task. Different prog type
(`BPF_PROG_TYPE_TRACING` with `BPF_TRACE_ITER`). Loader needs
`BPF_LINK_CREATE` with the iterator attach info; user invokes via
`bpf_iter_create` + `read()`.

### `watchpoint:0xADDR:LEN:rw` — **≈3 tests, M**

Memory watchpoints via hardware breakpoints (`perf_event_open` with
`PERF_TYPE_BREAKPOINT`). The grammar entry plus the loader attach
path.

### `bench:NAME` benchmark probes — **≈3 tests, S**

bpftrace 0.22+ pseudo-probe firing in a tight loop for
microbenchmarks. Cheap: grammar entry, treat as a user-side probe.

### `rawtracepoint:…` — **≈4 tests, M**

Different prog type (`BPF_PROG_TYPE_RAW_TRACEPOINT`) — args are the
raw kernel function args without tracepoint format-file mediation.

## Parser-only gaps

### `import "stdlib/…";` — **≈4 tests, M**

bpftrace 0.22+ module imports. Probably the cleanest path is to
inline a curated stdlib of macros at parse time.

### `enum` value resolution — **≈6 tests, M**

We parse `enum Foo { A, B }` at top level (accept-and-discard) but
don't resolve `A` / `B` as integer constants. Need an `*enum-values*`
table consulted by `resolve-constant`.

### `(enum Foo)$x` cast — **≈2 tests, S-M**

Cast result is treated as the matching enum-name string at print
time. After enum support lands, the cast becomes a printf %s with
runtime lookup.

### `unroll(N) { body }` — **≈2 tests, S**

bpftrace 0.22+ `unroll` directive. Easiest: parse and just emit the
body N times at AST normalize time when N is a literal.

### `tseries(value, interval, depth)` — **≈9 tests, L**

Time series collection — bpftrace 0.22+. Per-key rolling window of
samples with timestamps. Substantial userspace+kernel state machine.

### Comments — **≈23 col-2 parse errors, S**

Several test scripts start with a comment that we mis-handle. Our
`strip-comments` is solid, but the grammar reject point is at
column 2 which suggests something at script start. Need to
investigate the specific scripts.

### Pre/post `++`/`--` as **expression** — **≈4 tests, M**

`printf("%d", @x++)` uses postfix as expr. Our statement-level
support landed; expression-level needs side-effecting expression
lowering. Either:
- AST rewrite (split `printf("%d", @x++)` into `let $t = @x; @x++;
  printf("%d", $t);`).
- IR-level `(prog1 read incr)`-style emit.

## Codegen gaps (typesystem residual)

### Whole-array roundtrip via $var — **≈3 tests, M**

`@a[0] = ((struct A *) X).x; $x = @a[0]; $x[0]` needs `$x` to be
backed by a 16-byte stack buffer copied from the map's value, with
subscript reads going through that buffer.

Strategy: a `*array-vars*` table parallel to `*str-vars*`; in
`lower-assign` for `$x = @a[0]` where `@a` is value-array-p, allocate
a buffer, memcpy / probe-read-kernel from map-lookup-ptr into it,
record `(VAR-NAME elt-size arr-len)`. `lower-index` consults the
table.

### Multi-dim array index `$b.y[i][j]` — **≈5 tests, M**

`int y[2][2]` parses and we compute size correctly (`y` = 16 bytes),
but `.y[i][j]` only handles one subscript. Need to:
- Record per-field array shape (list of dims, not just a flat count).
- Compute element offset as i*outer-stride + j*inner-stride.
- Emit a single sized probe-read at that offset.

### Array compare `$a.x == $b.x` — **≈2 tests, M**

Equality on two struct array fields. Read both into buffers, memcmp
byte-by-byte (XOR-accumulator style like our strncmp), return 0/1.

### `args.argv[i]` tracepoint array access — **≈4 tests, M**

`args.argv` on `sys_enter_execve` is `char **` — an array of string
pointers. We need to:
- Recognise array-typed tracepoint fields (the format file marks
  them with `[N]`).
- For `args.argv[i]`, emit a single 8-byte load at ctx+argv_off+i*8
  to get the pointer, then it's usable as a `str()` arg.

### Pointer-array struct fields — **≈5 tests, M**

`struct C { int *z[4]; }` parses as 4×8-byte slots. `*((struct C
*)X).z[i]` needs:
- The subscript to read the i'th 8-byte pointer.
- The `*` deref to probe-read 4 bytes at that pointer.

We have `.z[i]` (returns the pointer u64) but no generic `*expr`
deref operator. Adding it would unblock several pointer-style tests.

### Array-literal cast `(int8[N])X`, `(int8[])X` — **≈3 tests, M**

`(int8[8])12345` reinterprets the int as an 8-byte array; `[0]` then
reads the low byte. Real semantic work — value-as-buffer reinterpret.

## Loader + runtime gaps

### `-f json` output — see "JSON output mode" above

### `--info` flag — **≈1 test, S**

Print a stub matching bpftrace's `--info` format (build flags,
kernel features). Pure text; doesn't have to be accurate.

### `bpftrace -` (script from stdin) — **≈1 test, S**

`bpftrace - < script.bt` reads script from stdin. Trivial fix in
`read-bpftrace-source`.

### Tracefs format file unavailability — quality of life

Already surfaces a clear error mentioning the unreadable paths. Could
extend by bundling a snapshot of common format files (sched, syscalls)
so tests run without root.

### `percpu_kaddr()` BPF verifier rejections — **≈4 tests, M**

Our `lower-percpu-kaddr-call` produces a sequence the verifier
rejects in some configurations. Need to look at the specific
verifier output and adjust the emitted shape.

### Static type-check errors — **≈8 tests**

Several tests expect bpftrace's semantic-check pass to emit a
specific error string (e.g., "Argument mismatch for @g: trying to
access with arguments…"). We let the kernel verifier reject these
instead, which produces a different error string. Adding a
type-check pass that produces matching error strings is a real
project; lower-priority since whatever wrote the wrong types still
fails — just with a less helpful message.

## Test-infrastructure observations

### Notify-handshake interaction with `has_exact_expect`

The runner clears `output` when it sees the notify line *if* the
test uses `EXPECT_EXACT`. Most tests use `EXPECT` (regex) and
the notify line shows up in `output`. The regex matcher uses
`re.MULTILINE` so this rarely hurts, but a handful of edge cases
fail because the regex unintentionally matches the notify line.

### Testprogs we skip in `build-bpftrace-testprogs.sh`

Special-recipe binaries we don't build:
- `false.bin` — llvm-objcopy flat-binary
- `archive.zip` — testprog packed in zip
- `uprobe_test-stripped`, `uprobe_separate_debug-stripped`
- `*-split` (split DWARF)
- `hello_go`, `hello_rust` (Go/Rust toolchains)

Any test that depends on these will SKIP cleanly (via the engine
patch) rather than crash the suite.

## Where to start

Highest impact for least scope, in rough order:

1. **Pointer arithmetic on maps** (≈18 tests, M) — `value-ptr-elt-
   size` already tracked; just need scaled `+=`/`-=`/`++`/`--`.
2. **Tuple-as-value** (≈12 tests, M) — parallels existing tuple-as-key
   work; lots of reuse from `composite-key-layout`.
3. **Bare `args`** (≈3 tests, M) — high information density: also
   exercises the BTF param walk that other features can reuse.
4. **`enum` resolution** (≈6 tests, M) — small, contained.
5. **`unroll(N)`** (≈2 tests, S) — easy.
6. **`--info` / `bpftrace -`** (≈2 tests, S) — trivial CLI fixes.
7. **JSON output** (≈16 tests, M) — single switch flips lots of
   tests; useful for downstream tooling regardless.
8. **`len(@map)`** (≈7 tests, M) — sidecar counter is straightforward;
   the AST instrumentation is the tricky bit.

Real architectural projects (after the above):

- **USDT** (≈10 tests, L) — full new probe type
- **JSON output** (if not done as part of #7)
- **`tseries()`** (≈9 tests, L) — userspace state machine
- **Multi-dim arrays** (≈5 tests, M)
- **Pointer-array fields + generic `*expr` deref** (≈5 tests, M)
