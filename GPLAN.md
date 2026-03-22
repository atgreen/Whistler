# Whistler Improvement Plan

This document outlines implemented and proposed improvements for the Whistler project to enhance the user experience, observability, and protocol support.

## Implemented Improvements

### 1. Expanded Protocol Support
- Added IPv6 and ICMP header definitions and constants to `src/protocols.lisp`.
- Exported these symbols from the `whistler` package in `src/packages.lisp`.
- This enables users to write BPF programs for modern network stacks more easily.

### 2. Compiler Observability
- Added `ir-dump` and `print-object` methods for `ir-insn` in `src/ir.lisp`.
- Exported `ir-dump` from the `whistler/ir` package.
- This allows developers to inspect the SSA intermediate representation at any stage of the optimization pipeline, which is invaluable for debugging and understanding the compiler's behavior.

## Future Recommendations

### 1. Tracepoint Macro (`deftracepoint`)
Automate the calculation of tracepoint field offsets. Instead of manual `ctx-load` with magic numbers, users should be able to define tracepoints declaratively:
```lisp
(deftracepoint sched-switch
  (prev-pid u32)
  (prev-state u64)
  (next-pid u32))
```
The macro could resolve offsets by parsing `/sys/kernel/debug/tracing/events/` or by using BTF information.

### 2. Kernel Struct Import (BTF-based)
Enable Whistler to import kernel struct definitions directly from the system's BTF (usually in `/sys/kernel/btf/vmlinux`). This would eliminate the need for manual `defstruct` definitions for kernel types, providing a Lisp-native equivalent to C's `vmlinux.h`.

### 3. BPF Dry-Run / Interpreter
Implement a Lisp-native BPF interpreter or a "dry-run" validator to provide more detailed and human-readable feedback than the kernel's verifier. This would drastically improve the development loop by catching common errors before the program is even loaded.

### 4. Expanded Protocol Library
Continue expanding `protocols.lisp` with headers for:
- ICMPv6
- VLAN (802.1Q)
- ARP
- DNS
- Common application protocols (HTTP, TLS, etc.)

### 5. Optimization Logging
Add a mechanism to log or trace which optimization passes were applied and what they changed (e.g., "Fused map lookup and delete in block @bb_10" or "Hoisted load of %5 before call to helper:6"). This would help users understand how their code is being transformed and optimized.

### 6. Enhanced REPL Integration
Leverage Common Lisp's interactive nature by adding REPL-specific commands to:
- Inspect the state of loaded BPF maps in real-time.
- Monitor ring buffer events directly in the REPL.
- Hot-reload BPF programs with one command.

### 7. CO-RE for Kernel Structs
While Whistler has CO-RE support for user-defined structs, extending this to automatically handle kernel structs (by discovering their layout via BTF) would make programs even more portable across different kernel versions without requiring a full kernel source tree.
