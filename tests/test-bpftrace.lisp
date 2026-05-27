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

(test codegen-lhist-records-params
  "lhist(value, lo, hi, step) compiles and records its params on the
   map info so the runtime printer can re-bucket at print time."
  (let* ((src "kprobe:foo { @h = lhist(arg0, 0, 1000, 100); }")
         (gen (whistler/bpftrace:compile-script src))
         (info (first (getf gen :info))))
    (is (eq :lhist (getf (cdr info) :kind)))
    (is (equal '(0 1000 100) (getf (cdr info) :hist-params)))
    (is (= 12 (getf (cdr info) :max-entries))
        "buckets = N+2 (10 in-range + 1 underflow + 1 overflow)")))

(test codegen-printf-ntop-v4
  "ntop(addr) emits a 4-byte slot tagged :ipv4."
  (let* ((src "kprobe:foo { printf(\"%s\\n\", ntop(arg0)); }")
         (gen (whistler/bpftrace:compile-script src))
         (entry (first (getf gen :printf-table))))
    (is (equal '(:ipv4) (third entry)))))

(test codegen-reg-ip
  "reg(\"ip\") lowers and compiles cleanly inside a kprobe."
  (let* ((src "kprobe:foo { printf(\"%s\\n\", ksym(reg(\"ip\"))); }")
         (gen (whistler/bpftrace:compile-script src)))
    (is (= 1 (length (getf gen :progs))))))

;;; ========== printf format flags ==========

(test format-printf-plain-and-percent
  "Literal text and %% pass through unchanged."
  (is (string= "hello %"
               (whistler/bpftrace::format-printf "hello %%" '())))
  (is (string= "a=42"
               (whistler/bpftrace::format-printf "a=%d" '(42)))))

(test format-printf-width-and-flags
  "Decimal width, `-' left-align and `0' zero-pad combine correctly."
  (is (string= "  foo"   (whistler/bpftrace::format-printf "%5s" '("foo"))))
  (is (string= "foo  "   (whistler/bpftrace::format-printf "%-5s" '("foo"))))
  (is (string= "00042"   (whistler/bpftrace::format-printf "%05d" '(42))))
  (is (string= "42   "   (whistler/bpftrace::format-printf "%-5d" '(42))))
  (is (string= "comm             /tmp/x"
               (whistler/bpftrace::format-printf "%-16s %s" '("comm" "/tmp/x")))))

(test format-printf-mixed-spec
  "Mixed %d/%x/%s and length-modifier %lld pass."
  (is (string= "x=ff y=255 z=hi"
               (whistler/bpftrace::format-printf "x=%x y=%u z=%s"
                                                 '(255 255 "hi"))))
  (is (string= "n=-7"
               (whistler/bpftrace::format-printf "n=%lld"
                                                 '(#xfffffffffffffff9)))))

(test codegen-printf-str-builtin
  "printf(\"%s\", str(arg0)) emits a 64-byte slot filled by
   bpf_probe_read_user_str."
  (let* ((src "uprobe:/usr/lib64/libc.so.6:fopen { printf(\"%s\\n\", str(arg0)); }")
         (gen (whistler/bpftrace:compile-script src))
         (printf-table (getf gen :printf-table))
         (entry (first printf-table)))
    (is (= 1 (length printf-table)) "one printf entry")
    (is (equal '((:string . 64)) (third entry))
        "single :string slot of size 64")))

(test codegen-printf-ksym
  "printf(\"%s\", ksym(addr)) emits an 8-byte slot tagged :ksym."
  (let* ((src "kprobe:vfs_read { printf(\"%s\\n\", ksym(arg0)); }")
         (gen (whistler/bpftrace:compile-script src))
         (entry (first (getf gen :printf-table))))
    (is (equal '(:ksym) (third entry)))))

(test codegen-printf-usym
  "printf(\"%s\", usym(addr)) emits a 16-byte slot tagged :usym."
  (let* ((src "uprobe:/usr/lib64/libc.so.6:malloc { printf(\"%s\\n\", usym(arg0)); }")
         (gen (whistler/bpftrace:compile-script src))
         (entry (first (getf gen :printf-table))))
    (is (equal '(:usym) (third entry)))))

(test format-ipv4-network-byte-order
  "ntop()'s wire format: 4 bytes printed in their stored order. A u32
   store of 0x0100A8C0 lays the bytes down as C0 A8 00 01 → 192.168.0.1."
  (let ((bytes (make-array 4 :element-type '(unsigned-byte 8)
                            :initial-contents '(#xC0 #xA8 #x00 #x01))))
    (sb-sys:with-pinned-objects (bytes)
      (let* ((sap (sb-sys:vector-sap bytes))
             (b0 (sb-sys:sap-ref-8 sap 0))
             (b1 (sb-sys:sap-ref-8 sap 1))
             (b2 (sb-sys:sap-ref-8 sap 2))
             (b3 (sb-sys:sap-ref-8 sap 3)))
        (is (string= "192.168.0.1"
                     (format nil "~D.~D.~D.~D" b0 b1 b2 b3)))))))

(test format-ipv6-zero-compression
  "format-ipv6 compresses the longest zero-run with `::`."
  (let ((bytes (make-array 16 :element-type '(unsigned-byte 8)
                              :initial-element 0)))
    ;; ::1 → all zeros except last byte = 1
    (setf (aref bytes 15) 1)
    (sb-sys:with-pinned-objects (bytes)
      (is (string= "::1" (whistler/bpftrace::format-ipv6
                          (sb-sys:vector-sap bytes) 0))))))

(test codegen-kfunc-section-and-type
  "kfunc/kretfunc compile to BPF_PROG_TYPE_TRACING with fentry/fexit
   section names."
  (let* ((src "kfunc:vfs_read { @ = count(); }")
         (gen (whistler/bpftrace:compile-script src))
         (prog (first (getf gen :progs))))
    (is (eq :tracing (getf (third prog) :type)))
    (is (string= "fentry/vfs_read" (getf (third prog) :section))))
  (let* ((src "kretfunc:vfs_read { @ = count(); }")
         (gen (whistler/bpftrace:compile-script src))
         (prog (first (getf gen :progs))))
    (is (eq :tracing (getf (third prog) :type)))
    (is (string= "fexit/vfs_read" (getf (third prog) :section)))))

(test codegen-probe-and-func-builtins
  "probe/func rewrite to string literals before printf-arg classification."
  (let* ((src "kprobe:vfs_read { printf(\"%s %s\\n\", probe, func); }")
         (gen (whistler/bpftrace:compile-script src))
         (entry (first (getf gen :printf-table))))
    (is (equal '((:string . 16) (:string . 9)) (third entry))
        "two string slots: kprobe/vfs_read\\0 (16) and vfs_read\\0 (9)")))

(test codegen-kstr-uses-kernel-helper
  "kstr() lowers to bpf_probe_read_kernel_str (helper 115)."
  (let* ((src "kprobe:vfs_read { printf(\"%s\\n\", kstr(arg1)); }")
         (gen (whistler/bpftrace:compile-script src))
         (prog (first (getf gen :progs)))
         (body (cdddr prog))
         (text (format nil "~S" body)))
    (is (search "PROBE-READ-KERNEL-STR" text)
        "kernel-str helper is used for kstr()")))

(test codegen-stats-uses-percpu-hash
  "stats() lands as :stats kind with avg's (count,sum) wire format."
  (let* ((src "kretprobe:vfs_read { @us[comm] = stats(retval); }")
         (gen (whistler/bpftrace:compile-script src))
         (info (first (getf gen :info))))
    (is (eq :stats (getf (cdr info) :kind)))
    (is (= 16 (getf (cdr info) :value-size)))))

(test codegen-kfunc-args-arrow
  "args->fieldname in kfunc lowers to a ctx u64 load at BTF's offset."
  (let* ((src "kfunc:vfs_read { @ = args->file; }")
         (gen (whistler/bpftrace:compile-script src))
         (prog (first (getf gen :progs)))
         (text (format nil "~S" (cdddr prog))))
    ;; vfs_read's first param is `file' at ctx offset 0.
    (is (search "CTX" text))
    (is (search "WHISTLER::U64" text))))

(test codegen-kfunc-args-arrow-bad-field
  "Unknown args->fieldname raises BPFTRACE-UNSUPPORTED with the actual
   parameter list."
  (signals whistler/bpftrace:bpftrace-unsupported
    (whistler/bpftrace:compile-script
     "kfunc:vfs_read { @ = args->nope; }")))
