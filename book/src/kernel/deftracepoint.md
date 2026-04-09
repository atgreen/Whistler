# deftracepoint

`deftracepoint` reads a kernel tracepoint format file at macroexpand time
and generates zero-cost accessor macros for each field.

## Syntax

```lisp
(deftracepoint category/event-name [field1 field2 ...])
```

**category/event-name** is a symbol like `sched/sched-switch`. Hyphens are
converted to underscores for the filesystem lookup.

**field1, field2, ...** optionally restrict which fields to import. If
omitted, all non-`common_` fields are imported.

## How it works

At macroexpand time, Whistler reads the tracefs format file at:

```
/sys/kernel/tracing/events/{category}/{event}/format
```

It parses each field declaration to extract the name, byte offset, size,
signedness, and array dimensions. For each selected field, it generates a
macro:

```lisp
(tp-FIELD)  ;; expands to (ctx-load TYPE OFFSET)
```

The `tp-` prefix is fixed. Types are inferred from the field size:

| Size | Unsigned | Signed |
|------|----------|--------|
| 1    | u8       | i8     |
| 2    | u16      | i16    |
| 4    | u32      | i32    |
| 8    | u64      | i64    |

Array fields additionally generate a `-ptr` accessor:

```lisp
(tp-FIELD-ptr)  ;; expands to (+ (ctx-load u64 0) OFFSET)
```

This gives you a pointer into the tracepoint context buffer, suitable for
`probe-read-kernel` or `probe-read-str`.

## Examples

Import specific fields from `sched_process_fork`:

```lisp
(deftracepoint sched/sched-process-fork parent-pid child-pid)

;; Now available:
;; (tp-parent-pid) -> (ctx-load u32 24)   ; exact offset from format file
;; (tp-child-pid)  -> (ctx-load u32 28)
```

Import all fields from `sched_switch`:

```lisp
(deftracepoint sched/sched-switch)

;; Generates tp-prev-comm, tp-prev-comm-ptr, tp-prev-pid,
;; tp-prev-prio, tp-prev-state, tp-next-comm, tp-next-comm-ptr,
;; tp-next-pid, tp-next-prio
```

Use in a tracepoint program:

```lisp
(defprog trace-fork (:type :tracepoint
                     :section "tracepoint/sched/sched_process_fork"
                     :license "GPL")
  (setf (getmap ppid-map (tp-child-pid)) (tp-parent-pid))
  0)
```

## Permissions

The format file must be readable by the compiling user. If running without
root:

```bash
sudo chmod a+r /sys/kernel/tracing/events/sched/sched_process_fork/format
```

If the file is not found, Whistler also checks the debugfs fallback path
at `/sys/kernel/debug/tracing/events/`.
