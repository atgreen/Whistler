(in-package #:whistler/tests)

(def-suite bpftrace-suite
  :description "bpftrace frontend: parse, normalise, codegen"
  :in whistler-suite)

(in-suite bpftrace-suite)

;;; ========== Parser smoke tests ==========

(test parse-empty-probe
  "An empty kprobe body parses."
  (let ((ast (whistler/bpftrace::normalize
              (whistler/bpftrace::parse-script "kprobe:foo {}"))))
    (is (eq :script (first ast)))
    (is (equal '(:kprobe "foo")
               (first (getf (cdr (second ast)) :specs))))))

(test parse-builtin-pid
  "`pid` lowers to a :BUILTIN node."
  (let* ((ast (whistler/bpftrace::normalize
               (whistler/bpftrace::parse-script
                "kprobe:foo { @[pid]++; }")))
         (stmt (first (getf (cdr (second ast)) :body))))
    (is (eq :incdec (first stmt)))
    (is (equal '(:builtin :pid)
               (first (getf (cdr (getf (cdr stmt) :lhs)) :keys))))))

(test parse-predicate
  "A /predicate/ shows up on the probe's :predicate slot."
  (let ((ast (whistler/bpftrace::normalize
              (whistler/bpftrace::parse-script
               "kprobe:foo /@x[1]/ { @y++; }"))))
    (is (not (null (getf (cdr (second ast)) :predicate))))))

(test parse-args-arrow
  "args->field becomes a :FIELD with base = :ARGS."
  (let* ((ast (whistler/bpftrace::normalize
               (whistler/bpftrace::parse-script
                "tracepoint:a:b { @x = args->pid; }")))
         (stmt (first (getf (cdr (second ast)) :body)))
         (rhs  (getf (cdr stmt) :rhs)))
    (is (eq :field (first rhs)))
    (is (string= "pid" (getf (cdr rhs) :name)))
    (is (equal '(:args) (getf (cdr rhs) :base)))))

;;; ========== Codegen smoke tests ==========

(test codegen-biolatency-compiles
  "biolatency.bt translates to at least two BPF programs without errors."
  (let* ((src "BEGIN { printf(\"x\"); }
               kprobe:blk_account_io_start { @start[arg0] = nsecs; }
               kprobe:blk_account_io_done /@start[arg0]/ {
                 $delta = nsecs - @start[arg0];
                 @usecs = hist($delta / 1000);
                 delete(@start[arg0]);
               }
               END { clear(@start); }")
         (gen (whistler/bpftrace:compile-script src))
         (maps (getf gen :maps))
         (progs (getf gen :progs)))
    ;; @start + @usecs + a hidden bt-print ringbuf (BEGIN's printf
    ;; now compiles to a ringbuf-submit). No bt-exit map because no
    ;; exit() call here.
    (is (= 3 (length maps)) "two @maps + bt-print ringbuf")
    ;; Two real kprobes plus BEGIN + END (both now compile to BPF
    ;; programs run via BPF_PROG_TEST_RUN).
    (is (= 4 (length progs)) "two kprobes + BEGIN + END as BPF programs")
    ;; The histogram map is a percpu-array.
    (is (find-if (lambda (m)
                   (and (eq (third m) :type)
                        (eq (fourth m) :percpu-array)))
                 maps))))

(test codegen-counter-incdec
  "@m[k]++ generates a counter map and (incf (getmap m k))."
  (let* ((src "kprobe:foo { @counts[pid]++; }")
         (gen (whistler/bpftrace:compile-script src)))
    (is (= 1 (length (getf gen :maps))))
    (is (= 1 (length (getf gen :progs))))
    (let* ((info (first (getf gen :info)))
           (kind (getf (cdr info) :kind)))
      (is (eq :counter kind)))))

(test codegen-unsupported-feature-signaled
  "lhist() raises BPFTRACE-UNSUPPORTED (Phase 1 ships hist only)."
  (signals whistler/bpftrace:bpftrace-unsupported
    (whistler/bpftrace:compile-script
     "kprobe:foo { @h = lhist(arg0, 0, 1000, 10); }")))
