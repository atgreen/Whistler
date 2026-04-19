# Summary

[Introduction](./index.md)

# Getting Started

- [Installation](./start/installation.md)
- [Hello eBPF](./start/hello-ebpf.md)
- [Permissions](./start/permissions.md)

# The Language

- [Top-Level Declarations](./language/declarations.md)
  - [defmap](./language/defmap.md)
  - [defprog](./language/defprog.md)
  - [defstruct](./language/defstruct.md)
- [Forms](./language/forms.md)
  - [Variables and Types](./language/variables.md)
  - [Control Flow](./language/control-flow.md)
  - [Arithmetic and Bitwise](./language/arithmetic.md)
  - [Memory Access](./language/memory.md)
  - [Map Operations](./language/maps.md)
  - [Ring Buffers](./language/ringbuf.md)
  - [BPF Helpers](./language/helpers.md)
  - [Loops](./language/loops.md)
  - [Tail Calls](./language/tail-calls.md)
  - [Inline Assembly](./language/asm.md)
- [Macros](./language/macros.md)

# Program Types

- [XDP](./programs/xdp.md)
- [Kprobe / Uprobe](./programs/kprobe.md)
- [Tracepoints](./programs/tracepoint.md)
- [Traffic Control (TC)](./programs/tc.md)
- [Cgroup](./programs/cgroup.md)

# Kernel Integration

- [deftracepoint](./kernel/deftracepoint.md)
- [import-kernel-struct](./kernel/import-kernel-struct.md)
- [Protocol Library](./kernel/protocols.md)

# Userspace Loader

- [Loading Programs](./loader/loading.md)
- [Attaching Programs](./loader/attaching.md)
- [Map Operations](./loader/maps.md)
- [Ring Buffer Consumer](./loader/ringbuf.md)
- [Inline BPF Sessions](./loader/sessions.md)

# Compiler Internals

- [Compilation Model](./internals/compilation.md)
- [ELF Output](./internals/elf.md)
- [Shared Header Generation](./internals/codegen.md)
- [CLI Reference](./internals/cli.md)

# Cookbook

- [Tracepoint with Ring Buffer](./cookbook/tracepoint-ringbuf.md)
- [Kernel Struct Traversal](./cookbook/kernel-struct.md)
- [XDP Tail Call Dispatch](./cookbook/tail-call-dispatch.md)
- [Inline Session](./cookbook/inline-session.md)
- [Cgroup Packet Counter](./cookbook/cgroup-counter.md)
- [Cgroup Outbound Firewall](./cookbook/cgroup-firewall.md)
