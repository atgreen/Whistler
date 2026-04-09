# Loading Programs

The Whistler userspace loader is a pure Common Lisp BPF loader -- no
libbpf dependency. It handles ELF parsing, map creation, relocation
patching, and program loading via the bpf(2) syscall.

## Setup

```lisp
(asdf:load-system "whistler/loader")
```

## with-bpf-object (recommended)

The simplest way to load a compiled BPF object:

```lisp
(whistler/loader:with-bpf-object (obj "my-prog.bpf.o")
  ;; obj is a loaded bpf-object with maps created and programs loaded
  ;; Attach, read maps, etc.
  ...)
;; All resources (maps, programs, attachments) auto-closed here
```

`with-bpf-object` opens the ELF, creates all maps, patches map FD
relocations, loads all programs into the kernel, and closes everything
on exit (normal or error) via `unwind-protect`.

## Manual lifecycle

For finer control:

```lisp
(let ((obj (whistler/loader:open-bpf-object "my-prog.bpf.o")))
  ;; Parses ELF, extracts map definitions. Nothing loaded yet.

  (whistler/loader:load-bpf-object obj)
  ;; Creates maps, patches relocations, loads programs.

  ;; ... use obj ...

  (whistler/loader:close-bpf-object obj))
  ;; Detaches programs, closes all FDs.
```

## Object accessors

After loading, look up maps and programs by name:

```lisp
(whistler/loader:bpf-object-map obj "my_map")   ;; -> map-info or nil
(whistler/loader:bpf-object-prog obj "my_prog")  ;; -> prog-info or nil
```

Names use underscores (matching the ELF symbol table).

## What happens during load

1. **ELF parsing** -- reads section headers, symbol table, map definitions
   from `.maps`, program bytecode from named sections, relocation entries.
2. **Map creation** -- calls `BPF_MAP_CREATE` for each map defined in the
   `.maps` section.
3. **Relocation patching** -- for each `R_BPF_64_64` relocation, replaces
   the placeholder in the instruction stream with the real map FD.
4. **Program loading** -- calls `BPF_PROG_LOAD` for each program section.
   The program type is inferred from the section name (e.g., `xdp`,
   `kprobe/...`, `tracepoint/...`, `cgroup_skb/...`).
