# Whistler 1.5.0 Release Notes

## New Features

- Tracepoint attachment support in the loader. New `attach-tracepoint`
  function resolves tracepoint IDs from tracefs and attaches BPF programs
  via perf events. `bpf:attach` in `with-bpf-session` now automatically
  dispatches tracepoint programs. (issue #32)

- New `fork-tracker` example demonstrating inline BPF session with
  tracepoint attachment (`sched/sched_process_fork`).

## Bug Fixes

- Fix off-by-one in `section-to-prog-type` that caused tracepoint
  programs to be loaded as `BPF_PROG_TYPE_SOCKET_FILTER`. (issue #32)

- Fix `+perf-type-tracepoint+` constant: was 1 (`PERF_TYPE_SOFTWARE`),
  now correctly 2 (`PERF_TYPE_TRACEPOINT`). (issue #32)
