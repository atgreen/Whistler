# Whistler 0.6.0 Release Notes

## New features

- **`with-ringbuf`** — Reserve/null-check/submit pattern in one form:
  ```lisp
  (with-ringbuf (event events (sizeof my-event))
    (setf (my-event-type event) 1)
    ...)
  ```

- **`fill-process-info`** — Fill pid, uid, timestamp, and comm fields from
  BPF helpers using struct accessor names, replacing ~8 lines of boilerplate.

- **Multi-pair `setf`** — Standard CL `setf` with multiple place/value pairs:
  ```lisp
  (setf (my-struct-a ptr) 1
        (my-struct-b ptr) 2
        (my-struct-c ptr) 3)
  ```

- **`defmap` defaults** — `:key-size` and `:value-size` default to 0, so
  ringbuf maps only need `(defmap events :type :ringbuf :max-entries 262144)`.

- **Structured compiler errors** — All error messages now have `what`, `where`,
  `expected`, and `hint` fields with context-specific suggestions.

## Compile-time diagnostics

- **Narrow type as pointer** — Error when a `u8` or `u16` value is passed as
  a pointer argument to `probe-read`, `probe-read-user`, etc. (Fixes #8)

- **Helper argument count** — Error when a BPF helper is called with the wrong
  number of arguments (e.g., `(ktime-get-ns 42)` instead of `(ktime-get-ns)`).

- **Malformed let bindings** — Detects `(let (x 1) ...)` and suggests the
  correct `(let ((x 1)) ...)` with double parentheses.

- **Unbound variables** — Shows variables currently in scope.

- **Unknown forms** — Detects CL functions used in BPF context
  (e.g., `format`, `loop`) with an explanation that they're not available.

- **Stack overflow** — Reports exact bytes needed when the 512-byte BPF stack
  limit is exceeded.
