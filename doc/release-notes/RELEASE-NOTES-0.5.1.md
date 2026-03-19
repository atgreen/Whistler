# Whistler 0.5.1 Release Notes

## Bug fixes

- **Fix phi resolution at loop back-edges.** Programs with helper calls
  (e.g. `probe-read-user`) inside `dotimes` loops could fail BPF verification
  with "R2 !read_ok" because the loop counter's caller-saved register was
  stale after helper calls clobbered it. The emitter now inserts phi
  resolution moves at all predecessor branches instead of only at the phi
  instruction site.

## New features

- **Struct-key map macros.** `getmap`, `setmap`, `incf`, `remmap`, and
  `delmap` now automatically dispatch to `-ptr` variants at compile time
  when the map's `:key-size` exceeds 8 bytes. No source changes needed —
  just use the high-level macros with struct pointer keys.

- **`do-user-ptrs`** — Iterate over a user-space array of pointers with
  automatic bounded iteration, pointer read, and null guard:
  ```lisp
  (do-user-ptrs (ptr base-ptr count +max+ :index i)
    body...)
  ```

- **`do-user-array`** — Iterate over a user-space array of scalars or
  structs:
  ```lisp
  (do-user-array (val u32 array-ptr count +max+)
    body...)
  (do-user-array (entry my-struct entries-ptr count +max+ :index i)
    body...)
  ```
