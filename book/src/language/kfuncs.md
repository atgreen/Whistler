# kfuncs

kfuncs (BPF kernel functions) are the modern, extensible way the kernel
exposes capabilities to BPF programs — the replacement for the frozen
[helper](./helpers.md) set. Unlike helpers, kfuncs have no stable integer
IDs; they are resolved by BTF at load time. Whistler does this on its own
pure-CL toolchain, with no libbpf:

- a kfunc call compiles to a `BPF_PSEUDO_KFUNC_CALL` instruction,
- the ELF object carries an `R_BPF_64_32` relocation against an extern
  BTF `FUNC` symbol,
- the loader resolves the kfunc's type id in `/sys/kernel/btf/vmlinux`
  and patches it into the call's immediate.

Call a kfunc by name in function position, exactly like a helper:

```lisp
(bpf-rcu-read-lock)
(let ((task (bpf-task-from-pid pid)))
  ...)
```

The Lisp name maps to the kernel symbol by turning hyphens into
underscores: `bpf-task-from-pid` → `bpf_task_from_pid`.

## Predeclared kfuncs

Six kfuncs ship ready to call:

| Whistler name | Signature | Flags |
|---------------|-----------|-------|
| `bpf-rcu-read-lock` | `() → void` | |
| `bpf-rcu-read-unlock` | `() → void` | |
| `bpf-task-from-pid` | `(s32) → task_struct*` | `:acquire :ret-null` |
| `bpf-task-release` | `(task_struct*) → void` | `:release` |
| `bpf-cgroup-from-id` | `(u64) → cgroup*` | `:acquire :ret-null` |
| `bpf-cgroup-release` | `(cgroup*) → void` | `:release` |

## Acquire / release and maybe-null pointers

Many useful kfuncs hand back a *refcounted* pointer that may be NULL.
Whistler models both obligations and checks them at compile time so you
get a clear error instead of a raw verifier log:

- **`:ret-null`** — the result may be NULL and must be null-checked
  before use. Passing a bare maybe-null result straight into another
  kfunc is a compile error; bind it and guard it with `when`/`if`.
- **`:acquire`** — the returned reference must be released on the way out
  via its paired `:release` kfunc. Leaking it is a compile error:
  *"acquired reference from BPF-TASK-FROM-PID is never released."*

```lisp
(defprog task-demo (:type :kprobe :section "test_run/task_demo")
  (let ((task (bpf-task-from-pid 1)))   ; :ret-null → must null-check
    (when task                          ; guard the maybe-null pointer
      (bpf-task-release task)))         ; :acquire → must release
  0)
```

The compile-time checks are a fast, friendly first line of defense. The
BPF verifier remains authoritative: it enforces per-path release
completeness (released on one branch but not another) and the
per-program-type kfunc allowlist.

## Program-type gating

The kernel registers each kfunc for specific program types. For example
`bpf_task_from_pid` is allowed for tracing / syscall / raw_tracepoint
programs but **not** plain kprobe or XDP — loading it there fails the
verifier with *"calling kernel function ... is not allowed."* This is
kernel policy, not a Whistler limitation. `bpf_rcu_read_lock` /
`bpf_rcu_read_unlock` are allowed under most types, including kprobe.

## Declaring your own kfunc

Use `defkfunc` to declare any kfunc the running kernel exports:

```lisp
(defkfunc bpf-task-from-pid ((pid s32)) (ptr task_struct) :acquire :ret-null)
(defkfunc bpf-task-release  ((task (ptr task_struct))) void :release)
```

- **Parameters** are `(var type)` pairs; the variable names are for
  readability only.
- **Types** are `u8`..`u64`, `s32`/`s64`, `void`, or `(ptr STRUCT)` for a
  pointer to a kernel struct.
- **Flags** are `:acquire`, `:release`, `:ret-null` (drive the compile-time
  checks above), plus `:trusted` and `:sleepable` (recorded, but enforced
  by the verifier).

`defkfunc` extends the shared registry that both the Whistler and
bpftrace frontends and the loader consume, so a declared kfunc is
immediately callable from either language.

## Example

See [`examples/kfunc-task.lisp`](https://github.com/atgreen/whistler/blob/main/examples/kfunc-task.lisp)
for a complete program that acquires a task, releases it, and runs in the
kernel via `BPF_PROG_TEST_RUN`. The same kfuncs are callable from the
[bpftrace frontend](../bpftrace/surface.md) by their kernel symbol name —
see [`examples/bpftrace/kfunc-rcu.bt`](https://github.com/atgreen/whistler/blob/main/examples/bpftrace/kfunc-rcu.bt).
