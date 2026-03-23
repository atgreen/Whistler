# Whistler 1.0.1 Release Notes

## Bug fixes

- **`with-bpf-session` from CL-USER** — Fixed a crash when using
  `with-bpf-session` from packages other than `whistler`. Symbols like
  `incf` and `getmap` in the `bpf:prog` body resolved to `CL:INCF` and
  `CL-USER::GETMAP` instead of their Whistler equivalents, causing the
  compiler to produce invalid IR. The session macro now re-interns body
  symbols into the `whistler` package before compilation.

- **Unbound variable error reporting** — Fixed a TYPE-ERROR in the
  lowerer's error handler that crashed instead of printing the diagnostic.
  The handler called `search` on a symbol instead of its name.
