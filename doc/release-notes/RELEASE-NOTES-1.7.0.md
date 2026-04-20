# Whistler 1.7.0 Release Notes

## New Features

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

## Bug Fixes

- **Store register clobbering.** Fixed cases where the emitter reused
  a source register as a scratch register during store operations,
  corrupting the value before it was written.

- **Ringbuf pointer spilling.** The register allocator now correctly
  handles ringbuf reserve pointers that are live across helper calls.

- **Mov-chain forwarding safety.** The peephole pass no longer forwards
  through moves whose source is overwritten before the consumer.

## New Example

- **Cgroup outbound firewall** (`examples/cgroup-firewall.lisp`): A
  process-level outbound firewall using three cooperating cgroup
  programs (`connect4`, `sockops`, `cgroup_skb/egress`) with shared
  maps, transparent proxy redirection, and ring buffer event logging.
