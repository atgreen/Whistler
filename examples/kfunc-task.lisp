;;; kfunc-task.lisp — Calling BPF kfuncs with acquire/release semantics
;;;
;;; Usage (requires CAP_BPF + CAP_PERFMON, e.g. via
;;;   sudo setcap cap_bpf,cap_perfmon+ep $(command -v sbcl)):
;;;
;;;   sbcl --load examples/kfunc-task.lisp
;;;
;;; Expected output:
;;;   Created map result: fd=... type=2
;;;   Loaded task_demo: 18 insns, fd=..., section=test_run/task_demo
;;;   result[0] = 1  (1 = bpf_task_from_pid ran in-kernel)
;;;
;;; kfuncs are kernel functions a BPF program *calls* — the modern,
;;; extensible alternative to the frozen helper set. Whistler resolves
;;; them by BTF at load time (no libbpf): the call compiles to a
;;; BPF_PSEUDO_KFUNC_CALL, the ELF carries an R_BPF_64_32 relocation
;;; against an extern BTF FUNC, and the loader patches in the kfunc's
;;; vmlinux BTF id.
;;;
;;; This program calls bpf_task_from_pid(), which ACQUIRES a refcounted
;;; task pointer that may be NULL. Whistler enforces both obligations at
;;; compile time:
;;;   * :ret-null — the result must be null-checked before use (the (when
;;;     task ...) below); using it unguarded is a compile error.
;;;   * :acquire  — the reference must be released on the way out via its
;;;     paired release kfunc (bpf-task-release); leaking it is a compile
;;;     error ("acquired reference ... is never released").
;;; The six phase-1 kfuncs (bpf_rcu_read_lock/unlock, bpf_task_from_pid/
;;; bpf_task_release, bpf_cgroup_from_id/bpf_cgroup_release) ship
;;; predeclared; declare your own with (defkfunc ...) — see the bottom.
;;;
;;; NOTE ON PROGRAM TYPE: the kernel gates each kfunc to specific program
;;; types. bpf_task_from_pid is allowed for tracing/syscall/raw_tracepoint
;;; programs but NOT plain kprobe/xdp — loading it there fails the verifier
;;; with "calling kernel function ... is not allowed". This example uses a
;;; test_run/ section (a raw_tracepoint invoked once via BPF_PROG_TEST_RUN)
;;; so it runs standalone without attaching to anything.

(require :asdf)
(asdf:load-system "whistler/loader")

(in-package #:whistler)

(defmap result :type :array :key-size 4 :value-size 8 :max-entries 1)

(defprog task-demo (:type :kprobe :section "test_run/task_demo" :license "GPL")
  (let ((task (bpf-task-from-pid 1)))   ; pid 1 (init) always exists
    (when task                          ; :ret-null → must null-check
      (setf (getmap result 0) 1)        ; mark: the kfunc ran in-kernel
      (bpf-task-release task)))         ; :acquire → must :release
  0)

(compile-to-elf "/tmp/kfunc-task.bpf.o")
(format t "Compiled test_run/task_demo to /tmp/kfunc-task.bpf.o~%")

(whistler/loader:with-bpf-object (obj "/tmp/kfunc-task.bpf.o")
  (let ((prog (whistler/loader:bpf-object-prog obj "task_demo"))
        (map  (whistler/loader:bpf-object-map  obj "result")))
    ;; Invoke the program once in the kernel.
    (whistler/loader:prog-test-run (whistler/loader:prog-info-fd prog))
    (let ((val (whistler/loader:map-lookup
                map (whistler/loader:encode-int-key 0 4))))
      (format t "result[0] = ~d  (1 = bpf_task_from_pid ran in-kernel)~%"
              (if val (whistler/loader:decode-int-value val) 0)))))

;;; Declaring your own kfunc:
;;;
;;;   (defkfunc bpf-cgroup-from-id ((cgid u64)) (ptr cgroup) :acquire :ret-null)
;;;   (defkfunc bpf-cgroup-release ((cgrp (ptr cgroup))) void :release)
;;;
;;; The Lisp name maps to the kernel symbol by turning hyphens into
;;; underscores (bpf-cgroup-from-id → bpf_cgroup_from_id). Types are
;;; u8..u64, s32/s64, void, or (ptr STRUCT); flags are :acquire :release
;;; :ret-null :trusted :sleepable.
