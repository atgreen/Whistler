# Whistler 0.5.3 Release Notes

## Bug fixes

- **Fix R0 not set before exit after helper call in kprobe/tracepoint
  programs.** The `elide-tracepoint-return` optimization cleared return value
  operands for kprobe and tracepoint programs, causing bare `exit` instructions
  with undefined R0 after helper calls. The BPF verifier requires R0 to be
  set before every exit, regardless of program type. (Fixes #9)

- **Give `let` proper CL semantics (parallel bindings).** `let` previously
  evaluated bindings sequentially (like `let*`). Now all init forms are
  evaluated before any variables are bound, matching standard Common Lisp.

## New features

- **`let*` support.** Sequential binding form where each init can reference
  prior bindings in the same form.

- **`ash` support.** CL's arithmetic shift function now works in BPF programs
  with constant shift counts. Positive counts compile to left shifts, negative
  to right shifts. (Fixes #6)
