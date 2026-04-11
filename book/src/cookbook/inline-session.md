# Inline Session

A complete inline BPF session -- compilation, loading, attachment, and
event consumption in a single Lisp file, with no separate compilation step.

## Full example

```lisp
(asdf:load-system "whistler/loader")

(defpackage #:my-tracer
  (:use #:cl #:whistler #:whistler/loader)
  (:shadowing-import-from #:whistler #:incf #:decf)
  (:shadowing-import-from #:cl #:case #:defstruct))

(in-package #:my-tracer)

;;; Struct definition -- generates both BPF and CL sides
(whistler:defstruct call-event
  (pid u32)
  (ts  u64))

;;; Inline BPF session
(defun run ()
  (with-bpf-session ()
    ;; BPF side (compiled at macroexpand time)
    (bpf:map events :type :ringbuf :max-entries 4096)

    (bpf:prog trace-exec (:type :kprobe
                           :section "kprobe/__x64_sys_execve"
                           :license "GPL")
      (with-ringbuf (ev events (sizeof call-event))
        (setf (call-event-pid ev) (cast u32 (ash (get-current-pid-tgid) -32))
              (call-event-ts ev)  (ktime-get-ns)))
      0)

    ;; Userspace side (runs at runtime)
    (bpf:attach trace-exec "__x64_sys_execve")

    (let ((consumer (open-ring-consumer
                     (cdr (assoc "events" (bpf-session-maps *bpf-session*)
                                 :test #'string=))
                     (lambda (sap len)
                       (let ((buf (make-array len :element-type '(unsigned-byte 8))))
                         (dotimes (i len)
                           (setf (aref buf i) (sb-sys:sap-ref-8 sap i)))
                         (let ((ev (decode-call-event buf)))
                           (format t "exec pid=~d ts=~d~%"
                                   (call-event-pid ev)
                                   (call-event-ts ev))))))))
      (unwind-protect
           (handler-case
               (loop (ring-poll consumer :timeout-ms 1000))
             (sb-sys:interactive-interrupt ()
               (format t "~&Detaching.~%")))
        (close-ring-consumer consumer)))))

(run)
```

Run:

```bash
sudo sbcl --load my-tracer.lisp
```

## Key points

- **Lifecycle**: `with-bpf-session` manages the full BPF lifecycle. Maps,
  programs, and attachments are created on entry and cleaned up on exit.
  The `unwind-protect` around the ring consumer ensures it is closed even
  on Ctrl-C.

- **bpf: prefix**: `bpf:map` and `bpf:prog` are compiled at macroexpand
  time. `bpf:attach` and `bpf:map-ref` expand to runtime loader calls.
  Everything else is plain CL code that runs at load time.

- **Shadowing**: The package definition uses `shadowing-import-from` to
  resolve symbol conflicts between CL and Whistler. Whistler redefines
  `incf` (to support map atomic increment) and `decf`. The
  `(:shadowing-import-from #:cl #:case #:defstruct)` keeps the CL
  versions for userspace code, while the Whistler versions are used
  inside `bpf:prog` bodies via automatic re-interning.

- **Map access**: `*bpf-session*` is a special variable bound during the
  session. Look up maps by name (underscored) with:
  ```lisp
  (cdr (assoc "events" (bpf-session-maps *bpf-session*) :test #'string=))
  ```
  For simple integer reads, `(bpf:map-ref map-name key)` is more
  convenient.
