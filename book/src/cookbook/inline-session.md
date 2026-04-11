# Inline Session

A complete inline BPF session -- compilation, loading, attachment, and
event consumption in a single Lisp file, with no separate compilation step.

## Full example

```lisp
(asdf:load-system "whistler/loader")
(in-package #:whistler-loader-user)

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

    (with-decoding-ring-consumer (consumer
                                  (bpf-session-map 'events)
                                  #'decode-call-event
                                  (lambda (ev)
                                    (format t "exec pid=~d ts=~d~%"
                                            (call-event-record-pid ev)
                                            (call-event-record-ts ev))))
      (handler-case
          (loop (ring-poll consumer :timeout-ms 1000))
        (sb-sys:interactive-interrupt ()
          (format t "~&Detaching.~%"))))))

(run)
```

Run:

```bash
sudo sbcl --load my-tracer.lisp
```

## Key points

- **Lifecycle**: `with-bpf-session` manages the full BPF lifecycle. Maps,
  programs, and attachments are created on entry and cleaned up on exit.
  `with-decoding-ring-consumer` handles ring consumer cleanup even on Ctrl-C.

- **bpf: prefix**: `bpf:map` and `bpf:prog` are compiled at macroexpand
  time. `bpf:attach` and `bpf:map-ref` expand to runtime loader calls.
  Everything else is plain CL code that runs at load time.

- **Package setup**: `whistler-loader-user` is the intended default
  package for interactive work. It already imports the compiler and
  loader symbols with the right shadowing in place.

- **Map access**: `*bpf-session*` is a special variable bound during the
  session. Use `bpf-session-map` for named lookup:
  ```lisp
  (bpf-session-map 'events)
  ```
  For simple integer reads, `(bpf:map-ref map-name key)` is more
  convenient. For struct-valued maps, use `map-lookup-struct-int` and
  `map-update-struct-int` with the generated record codecs.
