# Whistler 1.0.0 Release Notes

Whistler 1.0 is a complete Lisp-to-eBPF platform: compiler, loader, and
inline session runtime — all in pure Common Lisp with zero external
dependencies.

## Compiler

An SSA-based optimizing compiler that produces eBPF ELF objects matching
or beating `clang -O2` on instruction count. Includes copy propagation,
constant propagation, SCCP, dead code elimination, LICM, CSE,
store-to-load forwarding, PHI-branch threading, bitmask fusion, ALU
narrowing, live-range splitting, and peephole optimization.

## Loader (`whistler/loader`)

A pure Common Lisp BPF userspace loader — no libbpf, no CFFI. Loads
`.bpf.o` files, creates maps, patches relocations, loads programs, and
attaches kprobes/uprobes/XDP. Includes ring buffer consumer and map
iteration. All syscalls via SBCL's `sb-alien`.

## Inline sessions (`with-bpf-session`)

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

## Kernel integration

- **`deftracepoint`** — auto-resolve tracepoint field offsets from
  `/sys/kernel/tracing/events/` at compile time.
- **`import-kernel-struct`** — import kernel struct definitions from
  `/sys/kernel/btf/vmlinux` at compile time. No kernel headers needed.

## Struct codec

`whistler:defstruct` generates both BPF macros and CL-side struct with
byte-level decode/encode — one definition serves kernel and userspace.

## Protocol library

Ethernet, IPv4, IPv6, TCP, UDP, ICMP headers with compile-time accessors
and statement-oriented parsing macros (`with-packet`, `with-tcp`, etc.).

## Polyglot header generation

`--gen c`, `--gen go`, `--gen rust`, `--gen python`, `--gen lisp` produce
matching struct definitions from `defstruct` — one source of truth.

## Since 0.7.0

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
