# Whistler 1.2.0

## Bug Fixes

- Fix kprobe/uprobe attachment opening one perf event per CPU, causing duplicate events on every probe hit (#29)
- Fix ringbuf mmap EPERM on kernels with strict memory protection checks (#27)
- Fix attach-tc BPF_OBJ_PIN field ordering and error handling

## New Features

- TC (sched_cls) packet parsing macros: `with-tc-packet`, `with-tc-tcp`, `with-tc-udp` with `TC_ACT_OK`/`TC_ACT_SHOT` return codes (#28)
- TC/clsact BPF program attachment via `attach-tc`
- Compile-time validation for 8 common BPF verifier failure patterns (atomic-add arity, alignment, unchecked map pointers, and more)
- Kprobe retprobe support in `attach-kprobe`
