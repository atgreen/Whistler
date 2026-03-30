# Whistler 1.3.0

## New Features

- `import-kernel-struct` now supports embedded (non-scalar) struct fields (#30)
  - Embedded struct accessors return the field address (`ptr + offset`) instead of attempting a load
  - Enables natural chaining: `(msghdr-msg-iter msg)` -> `(iov-iter-__iov iter)` -> `(iovec-iov-base iov)`
  - No more hardcoded offsets for navigating nested kernel structs
- Compile-time type checking for kernel struct pointers
  - `(as-msghdr ptr)` tags a pointer with its struct type
  - Accessors verify the tag at compile time -- passing the wrong struct type is an error
  - Embedded struct accessors propagate types automatically
  - Bare untyped pointers still work (fully backward compatible)

## Bug Fixes

- `import-kernel-struct` no longer silently drops non-scalar fields
