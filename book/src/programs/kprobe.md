# Kprobe / Uprobe

Kprobes attach to kernel function entry (or return) points. Uprobes do the
same for userspace functions. Both use the `:kprobe` program type.

## Kprobes

Set the section name to `"kprobe/function_name"` to target a kernel
function:

```lisp
(defprog trace-exec (:type :kprobe
                     :section "kprobe/__x64_sys_execve")
  ;; runs each time execve is called
  0)
```

## Uprobes

For userspace functions, use `"uprobe/path"`:

```lisp
(defprog trace-malloc (:type :kprobe
                       :section "uprobe//lib64/libc.so.6")
  0)
```

## Return Probes

To trace when a function returns rather than when it is entered, use
a `kretprobe` section:

```lisp
(defprog trace-exec-ret (:type :kprobe
                         :section "kretprobe/__x64_sys_execve")
  0)
```

## Context: pt_regs

The context is accessed implicitly. Use the zero-argument macros
`pt-regs-parm1` through `pt-regs-parm6` for function arguments,
and `pt-regs-ret` for the return value on return probes:

```lisp
(defprog trace-exec (:type :kprobe
                     :section "kprobe/__x64_sys_execve")
  (let ((filename-ptr (pt-regs-parm1)))
    ;; filename-ptr holds the first argument to execve
    0))
```

| Accessor | Description |
|----------|-------------|
| `pt-regs-parm1` ... `pt-regs-parm6` | Function arguments 1-6 |
| `pt-regs-ret` | Return value (kretprobe/uretprobe only) |

## Example: Trace execve Calls

Record the PID of every process that calls execve:

```lisp
(defstruct exec-event
  (pid u32)
  (ts u64))

(defmap events :type :ringbuf
  :max-entries (* 256 1024))

(defprog trace-exec (:type :kprobe
                     :section "kprobe/__x64_sys_execve")
  (with-ringbuf (e events (sizeof exec-event))
    (setf (exec-event-pid e) (cast u32 (get-current-pid-tgid))
          (exec-event-ts e) (ktime-get-ns)))
  0)
```
