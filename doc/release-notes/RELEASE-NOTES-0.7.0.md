# Whistler 0.7.0 Release Notes

## New: `whistler/loader` — pure Common Lisp BPF loader

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

## New: `with-bpf-session` — inline BPF in one Lisp form

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

## New: struct decode/encode for userspace

`whistler:defstruct` now generates a CL struct and byte codec alongside the
BPF macros — one definition serves both kernel and userspace:

- `NAME-RECORD` — CL `defstruct` with matching slots
- `decode-NAME` — bytes → CL struct
- `encode-NAME` — CL struct → bytes (round-trips perfectly)

## New features

- **MIT LICENSE file** added.
- **`--gen lisp`** documented in README alongside C/Go/Rust/Python.

## Improvements

- **Zero external CL dependencies.** Removed `cl-version-string`; version
  now comes from ASDF system definition. Only SBCL required.
- **Struct field stores auto-truncate.** No `cast` needed when writing a
  wider value to a narrow field — `(setf (my-u8-field ptr) u16-val)` works.
- **Self-contained ffi-call-tracker example.** Complete standalone inline
  BPF program with uprobe attachment and stats display in one Lisp file.
