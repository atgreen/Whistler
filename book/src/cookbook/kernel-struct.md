# Kernel Struct Traversal

Read kernel data structures using `import-kernel-struct` and send
execution events to userspace.

## BPF program

```lisp
(in-package #:whistler)

;;; Import kernel struct fields from vmlinux BTF
(import-kernel-struct task-struct pid tgid comm)

;;; Userspace event struct
(defstruct exec-event
  (pid  u32)
  (tgid u32)
  (comm (array u8 16)))

;;; Maps
(defmap events :type :ringbuf :max-entries 4096)

;;; Kprobe program
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

(compile-to-elf "exec-events.bpf.o")
```

## Key points

- **CO-RE caveat**: `import-kernel-struct` reads BTF from the build host
  at compile time. The generated offsets are correct for that specific
  kernel version. For portable programs that must run across kernels, use
  `core-load` / `core-ctx-load` with BTF relocations instead.

- **kernel-load**: Each accessor like `(task-struct-pid task)` expands to
  `(kernel-load u32 task OFFSET)`, which compiles to:

  ```lisp
  (let ((buf (struct-alloc 4)))
    (probe-read-kernel buf 4 (+ task OFFSET))
    (load u32 buf 0))
  ```

  The BPF verifier requires `probe_read_kernel` for kernel pointers --
  direct dereference is not allowed.

- **Pointer chasing**: For pointer fields (e.g., `task_struct->mm`), the
  accessor returns a `u64` kernel pointer. Chain accessors naturally:

  ```lisp
  (import-kernel-struct task-struct mm)
  (import-kernel-struct mm-struct exe-file)

  (let* ((task (get-current-task))
         (mm   (task-struct-mm task))
         (exe  (mm-struct-exe-file mm)))
    ...)
  ```

- **comm field**: `comm` is a `char[16]` array in `task_struct`. The
  `(task-struct-comm task)` accessor returns an address offset (embedded
  struct/array path), so use `probe-read-kernel` to copy it into
  your event struct.
