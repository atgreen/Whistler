# Inline Session

No intermediate `.bpf.o` file. The BPF program compiles at macroexpand
time and loads at runtime, all from one Lisp form.

```lisp
(asdf:load-system "whistler/loader")

(defpackage #:my-tracer
  (:use #:cl #:whistler #:whistler/loader)
  (:shadowing-import-from #:whistler #:incf #:decf)
  (:shadowing-import-from #:cl #:case #:defstruct))

(in-package #:my-tracer)

(whistler:defstruct call-event
  (pid u32) (comm (array u8 16)))

(defun run ()
  (with-bpf-session ()
    ;; BPF side -- compiled at macroexpand time
    (bpf:map events :type :ringbuf :max-entries 16384)
    (bpf:prog trace (:type :kprobe
                      :section "kprobe/__x64_sys_execve"
                      :license "GPL")
      (with-ringbuf (evt events (sizeof call-event))
        (fill-process-info evt
          :pid-field call-event-pid
          :comm-field call-event-comm-ptr))
      0)

    ;; CL side -- runs at runtime
    (bpf:attach trace "__x64_sys_execve")
    (format t "Tracing execve. Ctrl-C to stop.~%")
    (let ((ring (bpf:map-ref events)))
      (handler-case
          (loop (ring-poll ring :timeout-ms 1000))
        (sb-sys:interactive-interrupt ()
          (format t "~&Done.~%"))))))

(run)
```

## Key points

- `with-bpf-session` scopes the entire lifecycle: compile, load,
  attach, and auto-cleanup on exit.
- The `bpf:` prefix marks kernel-side declarations. Everything else
  is normal CL that runs at runtime.
- `(:shadowing-import-from #:whistler #:incf #:decf)` resolves the
  CL/Whistler symbol conflict when embedding in your own package.
- `fill-process-info` fills pid/uid/timestamp/comm from BPF helpers
  in one form, using your struct's accessor names.
