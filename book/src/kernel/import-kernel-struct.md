# import-kernel-struct

`import-kernel-struct` reads the vmlinux BTF blob at macroexpand time and
generates typed accessor macros for kernel struct fields.

## Syntax

```lisp
(import-kernel-struct struct-name [field1 field2 ...])
```

**struct-name** is a symbol like `task-struct`. Hyphens are converted to
underscores for the BTF lookup.

**field1, field2, ...** optionally restrict which fields to import. If
omitted, all fields are imported (including those from anonymous nested
structs/unions, which are flattened).

## How it works

At macroexpand time, Whistler:

1. Reads and parses `/sys/kernel/btf/vmlinux` (cached across expansions).
2. Finds the struct by name in the BTF type table.
3. Resolves each field's type through typedefs, const, volatile, etc.
4. Generates accessor macros using `kernel-load` (which compiles to
   `probe-read-kernel` + stack buffer + load).

For a struct like `task_struct`, this generates:

```lisp
;; Scalar/pointer fields:
(task-struct-pid ptr)   ;; -> (kernel-load u32 ptr OFFSET)
(task-struct-tgid ptr)  ;; -> (kernel-load u32 ptr OFFSET)
(task-struct-flags ptr) ;; -> (kernel-load u32 ptr OFFSET)

;; Embedded struct fields:
(task-struct-mm ptr)    ;; -> (+ ptr OFFSET)  (returns typed pointer)

;; Size constant:
+task-struct-size+      ;; total size in bytes
```

Pointer fields resolve to `u64`. Embedded structs return a pointer offset
(no probe-read -- you access their sub-fields with further kernel-loads).
A `(as-STRUCT ptr)` cast macro is also generated for type-safe pointer
tagging.

## Pointer chasing

Kernel-load accessors compose naturally for pointer chasing:

```lisp
(import-kernel-struct task-struct pid tgid mm)
(import-kernel-struct mm-struct exe-file)
(import-kernel-struct file f-path)

;; Chase: current task -> mm -> exe_file
(let* ((task (get-current-task))
       (mm   (task-struct-mm task))
       (exe  (mm-struct-exe-file mm)))
  ;; exe is now a kernel pointer to struct file
  ...)
```

Each accessor checks the typed-ptr tag at macroexpand time. If you pass a
`mm-struct` pointer to a `task-struct` accessor, you get a compile-time
error. Use `(as-task-struct ptr)` to cast if intentional.

## CO-RE compatibility

The offsets come from the build host's BTF. For CO-RE relocatable programs,
use `core-load` / `core-ctx-load` instead. `import-kernel-struct` is best
suited for programs that will run on the same kernel they were compiled on.

## Example

```lisp
(import-kernel-struct task-struct pid tgid comm)

(defstruct exec-event
  (pid  u32)
  (tgid u32)
  (comm (array u8 16)))

(defmap events :type :ringbuf :max-entries 4096)

(defprog trace-exec (:type :kprobe
                     :section "kprobe/__x64_sys_execve"
                     :license "GPL")
  (let ((task (get-current-task)))
    (with-ringbuf (ev events (sizeof exec-event))
      (setf (exec-event-pid ev)  (task-struct-pid task)
            (exec-event-tgid ev) (task-struct-tgid task))
      (probe-read-kernel (exec-event-comm-ptr ev) 16
                         (+ task (task-struct-comm task)))))
  0)
```

Key points:

- `kernel-load` handles the probe-read-kernel dance automatically.
- Pointer fields return `u64` values you can pass to further accessors.
- `+STRUCT-SIZE+` is useful for `probe-read-kernel` buffer sizing.
