;;; test-torture.lisp — Torture tests: compile + kernel-verify many small programs
;;;
;;; Like gcc's c-torture tests, this suite systematically generates programs
;;; that stress the compiler and validates the output against the real Linux
;;; kernel BPF verifier via BPF_PROG_LOAD.
;;;
;;; Without CAP_BPF, tests still verify successful compilation.
;;; With CAP_BPF, tests additionally load programs into the kernel verifier.

(in-package #:whistler/tests)

(def-suite torture-suite
  :description "Torture tests: compile + kernel-verify many small programs"
  :in whistler-suite)

(in-suite torture-suite)

;;; ========== CAP_BPF detection ==========

(defvar *has-cap-bpf* :unknown
  "Cached result of CAP_BPF probe. :unknown, T, or NIL.")

(defun probe-cap-bpf ()
  "Try loading a trivial XDP program (mov r0,0; exit). Returns T if it works."
  (let ((trivial-insns (make-array 16 :element-type '(unsigned-byte 8)
                                      :initial-element 0)))
    ;; mov r0, 0  → opcode #xb7, dst=0, imm=0
    (setf (aref trivial-insns 0) #xb7)
    ;; exit       → opcode #x95
    (setf (aref trivial-insns 8) #x95)
    (handler-case
        (let ((fd (whistler/loader::load-program
                   trivial-insns
                   whistler/loader::+bpf-prog-type-xdp+
                   "GPL")))
          (sb-posix:close fd)
          t)
      (error () nil))))

(defun has-cap-bpf-p ()
  "Return T if kernel verification is available."
  (when (eq *has-cap-bpf* :unknown)
    (setf *has-cap-bpf* (probe-cap-bpf)))
  *has-cap-bpf*)

;;; ========== Secure temp directory ==========
;;; Use a private temp directory to avoid symlink attacks in /tmp.

(defvar *torture-tmpdir* nil
  "Private temp directory for this test run.")

(defun torture-tmpdir ()
  "Return (creating if needed) a private temp directory for torture tests."
  (or *torture-tmpdir*
      (let ((dir (format nil "/tmp/whistler-torture-~d-~36r/"
                         (sb-posix:getpid)
                         (random (expt 36 12)))))
        (sb-posix:mkdir dir #o700)
        (setf *torture-tmpdir* dir))))

(defun torture-tmpfile (suffix)
  "Return a unique temp file path inside the private temp directory."
  (format nil "~a~d~a" (torture-tmpdir) (random 1000000) suffix))

;;; ========== Verification counters ==========

(defvar *torture-compiled* 0
  "Number of programs successfully compiled in this run.")
(defvar *torture-verified* 0
  "Number of programs verified by the kernel verifier in this run.")

(test torture-mode-report
  "Report whether kernel verification is active"
  (setf *torture-compiled* 0 *torture-verified* 0)
  (if (has-cap-bpf-p)
      (format t "~&;; Torture mode: COMPILE + KERNEL VERIFY (CAP_BPF available)~%")
      (format t "~&;; Torture mode: COMPILE ONLY (no CAP_BPF — run with sudo for full verification)~%"))
  (pass))

;;; ========== Verification helpers ==========

(defun verify-bytecode (insn-bytes &key (prog-type whistler/loader::+bpf-prog-type-xdp+)
                                        (license "GPL"))
  "Load INSN-BYTES into the kernel verifier.
   Returns (values T nil) on success, (values NIL verifier-log) on failure.
   Closes the program FD on success."
  (handler-case
      (let ((fd (whistler/loader::load-program insn-bytes prog-type license)))
        (sb-posix:close fd)
        (values t nil))
    (whistler/loader:bpf-verifier-error (e)
      (values nil (whistler/loader::bpf-verifier-error-log e)))
    (whistler/loader:bpf-error (e)
      (values nil (format nil "BPF error: errno ~d" (whistler/loader::bpf-error-errno e))))))

(defun verify-elf-source (source-string)
  "Compile a complete Whistler source (with defmap/defprog) to a temp ELF,
   then load it via the loader (creates maps, patches relocations, verifies).
   Returns (values T nil) on success, (values NIL log) on failure."
  (let ((lisp-path (torture-tmpfile ".lisp"))
        (elf-path (torture-tmpfile ".bpf.o")))
    (unwind-protect
         (progn
           (with-open-file (f lisp-path :direction :output :if-exists :supersede)
             (write-string source-string f))
           (whistler::compile-file* lisp-path elf-path)
           (handler-case
               (progn
                 (whistler/loader:with-bpf-object (obj elf-path)
                   obj)  ; use obj to suppress warning
                 (values t nil))
             (whistler/loader:bpf-verifier-error (e)
               (values nil (whistler/loader::bpf-verifier-error-log e)))
             (whistler/loader:bpf-error (e)
               (values nil (format nil "BPF error: errno ~d"
                                   (whistler/loader::bpf-error-errno e))))))
      (when (probe-file lisp-path) (delete-file lisp-path))
      (when (probe-file elf-path) (delete-file elf-path)))))

(defmacro torture-verify (source &key maps)
  "Compile SOURCE (a string of Whistler body forms) and verify.
   Asserts compilation succeeds. When CAP_BPF is available, asserts
   the kernel verifier accepts the program."
  (if maps
      ;; Map-using program: must go through ELF round-trip
      `(let* ((full-source
                (format nil "(in-package #:whistler)~%~{~a~%~}~a"
                        (loop for (name . rest) in ',maps
                              collect (format nil "(defmap ~a ~{~s ~s~^ ~})"
                                              name rest))
                        ,(format nil "(defprog torture-test (:type :xdp :section \"xdp\" :license \"GPL\") ~a)" source)))
              (lisp-path (torture-tmpfile ".lisp"))
              (elf-path (torture-tmpfile ".bpf.o")))
         (unwind-protect
              (progn
                (with-open-file (f lisp-path :direction :output :if-exists :supersede)
                  (write-string full-source f))
                (finishes (whistler::compile-file* lisp-path elf-path))
                (cl:incf *torture-compiled*)
                (when (has-cap-bpf-p)
                  (multiple-value-bind (ok log) (verify-elf-source full-source)
                    (is-true ok (format nil "Verifier rejected program:~%~a" log))
                    (when ok (cl:incf *torture-verified*)))))
           (when (probe-file lisp-path) (delete-file lisp-path))
           (when (probe-file elf-path) (delete-file elf-path))))
      ;; Mapless program: direct bytecode verification
      `(let ((bytes (compile-insn-bytes (read-whistler-forms ,source))))
         (is (not (null bytes)) "Compilation failed")
         (is (plusp (length bytes)) "Compilation produced no instructions")
         (cl:incf *torture-compiled*)
         (when (has-cap-bpf-p)
           (multiple-value-bind (ok log) (verify-bytecode bytes)
             (is-true ok (format nil "Verifier rejected program:~%~a" log))
             (when ok (cl:incf *torture-verified*)))))))

;;; ========== Category 1: Constant folding edge cases ==========

(test torture-const-zero
  "Simplest possible program"
  (torture-verify "(return 0)"))

(test torture-const-one
  "Return nonzero constant"
  (torture-verify "(return 1)"))

(test torture-const-max-u32
  "Return max u32"
  (torture-verify "(return #xffffffff)"))

(test torture-const-neg-arith
  "Subtraction producing negative"
  (torture-verify "(return (- 0 1))"))

(test torture-const-nested-fold
  "Nested constant folding"
  (torture-verify "(return (+ (* 100 200) (/ 1000 5)))"))

(test torture-const-shift-fold
  "Shift constant folding"
  (torture-verify "(return (<< 1 16))"))

(test torture-const-mod-fold
  "Modulo constant folding"
  (torture-verify "(return (mod 100 7))"))

;;; ========== Category 2: Register pressure ==========

(test torture-regpressure-5vars
  "5 live variables — light spilling"
  (torture-verify
   "(let* ((a (get-prandom-u32))
           (b (get-prandom-u32))
           (c (+ a b))
           (d (- a b))
           (e (logxor c d)))
      (declare (type u32 a b) (type u64 c d e))
      (return e))"))

(test torture-regpressure-8vars
  "8 live variables — heavy spilling"
  (torture-verify
   "(let* ((a (get-prandom-u32))
           (b (get-prandom-u32))
           (c (+ a b))
           (d (- a b))
           (e (logxor c d))
           (f (logior a e))
           (g (logand b d))
           (h (+ e f g)))
      (declare (type u32 a b) (type u64 c d e f g h))
      (return h))"))

(test torture-regpressure-10vars
  "10 live variables — extreme spilling"
  (torture-verify
   "(let* ((v0 (get-prandom-u32))
           (v1 (get-prandom-u32))
           (v2 (+ v0 v1))
           (v3 (- v0 v1))
           (v4 (logxor v2 v3))
           (v5 (logior v0 v4))
           (v6 (logand v1 v3))
           (v7 (+ v4 v5))
           (v8 (- v6 v2))
           (v9 (+ v7 v8 v0 v1 v2 v3 v4 v5 v6)))
      (declare (type u32 v0 v1) (type u64 v2 v3 v4 v5 v6 v7 v8 v9))
      (return v9))"))

(test torture-regpressure-helper-interleave
  "Variables live across helper calls (R1-R5 clobbered)"
  (torture-verify
   "(let* ((a (get-prandom-u32))
           (t1 (ktime-get-ns))
           (b (get-prandom-u32))
           (t2 (ktime-get-ns))
           (result (+ a b t1 t2)))
      (declare (type u32 a b) (type u64 t1 t2 result))
      (return result))"))

(test torture-regpressure-5vars-all-used-at-end
  "5 variables all used together in final expression"
  (torture-verify
   "(let* ((a (get-prandom-u32))
           (b (get-prandom-u32))
           (c (ktime-get-ns))
           (d (get-prandom-u32))
           (e (get-current-pid-tgid)))
      (declare (type u32 a b d) (type u64 c e))
      (return (+ a b c d e)))"))

;;; ========== Category 3: Control flow stress ==========

(test torture-deep-if-5
  "5-deep nested if/else"
  (torture-verify
   "(let ((x (get-prandom-u32)))
      (declare (type u32 x))
      (if (> x 100)
          (if (> x 200)
              (if (> x 300)
                  (if (> x 400)
                      (if (> x 500)
                          (return 5)
                          (return 4))
                      (return 3))
                  (return 2))
              (return 1))
          (return 0)))"))

(test torture-deep-if-10
  "10-deep nested if/else"
  (torture-verify
   "(let ((x (get-prandom-u32)))
      (declare (type u32 x))
      (if (> x 10)
        (if (> x 20)
          (if (> x 30)
            (if (> x 40)
              (if (> x 50)
                (if (> x 60)
                  (if (> x 70)
                    (if (> x 80)
                      (if (> x 90)
                        (if (> x 100)
                          (return 10)
                          (return 9))
                        (return 8))
                      (return 7))
                    (return 6))
                  (return 5))
                (return 4))
              (return 3))
            (return 2))
          (return 1))
        (return 0)))"))

(test torture-cond-10-clauses
  "cond with 10 clauses"
  (torture-verify
   "(let ((x (get-prandom-u32)))
      (declare (type u32 x))
      (cond
        ((= x 0) (return 10))
        ((= x 1) (return 20))
        ((= x 2) (return 30))
        ((= x 3) (return 40))
        ((= x 4) (return 50))
        ((= x 5) (return 60))
        ((= x 6) (return 70))
        ((= x 7) (return 80))
        ((= x 8) (return 90))
        (t (return 100))))"))

(test torture-diamond-cfg
  "Diamond CFG: branch, merge, branch again"
  (torture-verify
   "(let* ((x (get-prandom-u32))
           (y (if (> x 10) (+ x 1) (- x 1))))
      (declare (type u32 x) (type u64 y))
      (if (> y 20)
          (return (+ y 100))
          (return (+ y 200))))"))

(test torture-and-or-chain
  "Complex and/or chain"
  (torture-verify
   "(let ((a (get-prandom-u32))
          (b (get-prandom-u32)))
      (declare (type u32 a b))
      (if (and (or (> a 10) (< b 5))
               (or (= a 42) (> b 100)))
          (return 1)
          (return 0)))"))

(test torture-loop-basic
  "Simple dotimes loop"
  (torture-verify
   "(let ((sum 0))
      (declare (type u64 sum))
      (dotimes (i 10)
        (setf sum (+ sum i)))
      (return sum))"))

(test torture-loop-with-branch
  "Loop containing a conditional"
  (torture-verify
   "(let ((x (get-prandom-u32))
          (count 0))
      (declare (type u32 x) (type u64 count))
      (dotimes (i 8)
        (when (> x i)
          (setf count (+ count 1))))
      (return count))"))

(test torture-early-return-in-branch
  "Return from inside nested when"
  (torture-verify
   "(let ((x (get-prandom-u32))
          (y (get-prandom-u32)))
      (declare (type u32 x y))
      (when (> x 100)
        (when (> y 200)
          (return 42)))
      (return 0))"))

(test torture-when-unless-mix
  "Mixed when/unless"
  (torture-verify
   "(let ((x (get-prandom-u32)))
      (declare (type u32 x))
      (when (> x 10)
        (return 1))
      (unless (> x 5)
        (return 2))
      (return 3))"))

(test torture-nested-let-star
  "Deeply nested let* with dependencies"
  (torture-verify
   "(let* ((a (get-prandom-u32))
           (b (+ a 1))
           (c (+ b 2))
           (d (+ c 3))
           (e (+ d 4))
           (f (+ e 5)))
      (declare (type u32 a) (type u64 b c d e f))
      (return f))"))

;;; ========== Category 4: Stack pressure ==========

(test torture-stack-small-alloc
  "Small struct-alloc"
  (torture-verify
   "(let ((buf (struct-alloc 8)))
      (store u64 buf 0 42)
      (return (load u64 buf 0)))"))

(test torture-stack-multi-alloc
  "Multiple struct-allocs"
  (torture-verify
   "(let ((a (struct-alloc 16))
          (b (struct-alloc 16))
          (c (struct-alloc 16)))
      (store u64 a 0 1)
      (store u64 b 0 2)
      (store u64 c 0 3)
      (return (+ (load u64 a 0) (load u64 b 0) (load u64 c 0))))"))

(test torture-stack-with-stores
  "struct-alloc with multiple field stores"
  (torture-verify
   "(let ((buf (struct-alloc 32)))
      (store u64 buf 0  100)
      (store u64 buf 8  200)
      (store u64 buf 16 300)
      (store u64 buf 24 400)
      (return (+ (load u64 buf 0) (load u64 buf 24))))"))

(test torture-stack-memset
  "struct-alloc + memset"
  (torture-verify
   "(let ((buf (struct-alloc 64)))
      (memset buf 0 0 64)
      (return (load u64 buf 0)))"))

(test torture-stack-memcpy
  "Two allocs + memcpy between them"
  (torture-verify
   "(let ((src (struct-alloc 32))
          (dst (struct-alloc 32)))
      (store u64 src 0 42)
      (store u64 src 8 99)
      (memcpy dst 0 src 0 32)
      (return (load u64 dst 0)))"))

(test torture-stack-near-limit
  "Large allocation near 512-byte stack limit"
  (torture-verify
   "(let ((buf (struct-alloc 256)))
      (memset buf 0 0 256)
      (store u64 buf 0 1)
      (return (load u64 buf 0)))"))

;;; ========== Category 5: Map operations ==========

(test torture-map-array-lookup
  "Array map lookup + null check"
  (torture-verify
   "(let ((val (getmap m 0)))
      (if val (return val) (return 0)))"
   :maps ((m :type :array :key-size 4 :value-size 8 :max-entries 1))))

(test torture-map-array-incf
  "Array map atomic increment"
  (torture-verify
   "(incf (getmap m 0))
    (return 0)"
   :maps ((m :type :array :key-size 4 :value-size 8 :max-entries 1))))

(test torture-map-hash-lookup-update
  "Hash map lookup then update"
  (torture-verify
   "(let ((key 42))
      (declare (type u32 key))
      (let ((val (map-lookup m key)))
        (declare (type u64 val))
        (if val
            (progn (store u64 val 0 (+ (load u64 val 0) 1))
                   (return 1))
            (let ((new-val (struct-alloc 8)))
              (store u64 new-val 0 1)
              (map-update m key new-val 0)
              (return 0)))))"
   :maps ((m :type :hash :key-size 4 :value-size 8 :max-entries 256))))

(test torture-map-hash-delete
  "Hash map lookup then delete"
  (torture-verify
   "(let ((key 1))
      (declare (type u32 key))
      (let ((val (map-lookup m key)))
        (declare (type u64 val))
        (when val
          (map-delete m key)))
      (return 0))"
   :maps ((m :type :hash :key-size 4 :value-size 8 :max-entries 256))))

(test torture-map-two-maps
  "Operations on two different maps"
  (torture-verify
   "(incf (getmap counts 0))
    (incf (getmap stats 0))
    (return 0)"
   :maps ((counts :type :array :key-size 4 :value-size 8 :max-entries 1)
          (stats :type :array :key-size 4 :value-size 8 :max-entries 1))))

(test torture-map-lru-hash
  "LRU hash map basic operation"
  (torture-verify
   "(let ((key (get-prandom-u32)))
      (declare (type u32 key))
      (let ((val (map-lookup m key)))
        (declare (type u64 val))
        (if val (return 1) (return 0))))"
   :maps ((m :type :lru-hash :key-size 4 :value-size 8 :max-entries 256))))

(test torture-map-helper-as-key
  "Helper result as map key"
  (torture-verify
   "(let* ((pid-tgid (get-current-pid-tgid))
           (pid (logand (ash pid-tgid -32) #xffffffff)))
      (declare (type u64 pid-tgid) (type u32 pid))
      (let ((val (map-lookup m pid)))
        (declare (type u64 val))
        (if val (return 1) (return 0))))"
   :maps ((m :type :hash :key-size 4 :value-size 8 :max-entries 1024))))

(test torture-map-nested-lookups
  "Nested map lookups"
  (torture-verify
   "(let ((val1 (getmap a 0)))
      (if val1
          (let ((val2 (getmap b 0)))
            (if val2
                (return (+ val1 val2))
                (return val1)))
          (return 0)))"
   :maps ((a :type :array :key-size 4 :value-size 8 :max-entries 1)
          (b :type :array :key-size 4 :value-size 8 :max-entries 1))))

;;; ========== Category 6: Helper call interaction ==========

(test torture-helper-ktime
  "ktime-get-ns basic use"
  (torture-verify
   "(let ((t1 (ktime-get-ns)))
      (declare (type u64 t1))
      (return t1))"))

(test torture-helper-pid-mask
  "get-current-pid-tgid with shift and mask"
  (torture-verify
   "(let* ((pt (get-current-pid-tgid))
           (pid (logand (ash pt -32) #xffffffff))
           (tgid (logand pt #xffffffff)))
      (declare (type u64 pt pid tgid))
      (return (+ pid tgid)))"))

(test torture-helper-prandom-branch
  "get-prandom-u32 in branch condition"
  (torture-verify
   "(let ((r (get-prandom-u32)))
      (declare (type u32 r))
      (if (> r #x7fffffff)
          (return 1)
          (return 0)))"))

(test torture-helper-chained
  "Multiple helper calls with results live simultaneously"
  (torture-verify
   "(let* ((t1 (ktime-get-ns))
           (pid (get-current-pid-tgid))
           (r (get-prandom-u32))
           (combined (+ t1 pid r)))
      (declare (type u64 t1 pid combined) (type u32 r))
      (return combined))"))

(test torture-helper-in-one-branch
  "Helper call in only one branch"
  (torture-verify
   "(let ((x (get-prandom-u32)))
      (declare (type u32 x))
      (if (> x 100)
          (return (ktime-get-ns))
          (return 0)))"))

(test torture-helper-across-branch
  "Helper result used after a branch"
  (torture-verify
   "(let* ((t1 (ktime-get-ns))
           (x (get-prandom-u32))
           (y (if (> x 10) (+ x 1) (- x 1))))
      (declare (type u64 t1) (type u32 x) (type u64 y))
      (return (+ t1 y)))"))

;;; ========== Category 7: Setf patterns ==========

(test torture-setf-single
  "Basic variable setf"
  (torture-verify
   "(let ((x 0))
      (declare (type u64 x))
      (setf x 42)
      (return x))"))

(test torture-setf-multi-pair
  "Multi-pair setf"
  (torture-verify
   "(let ((a 0) (b 0) (c 0))
      (declare (type u64 a b c))
      (setf a 1 b 2 c 3)
      (return (+ a b c)))"))

(test torture-setf-in-branch
  "Different setf in each branch"
  (torture-verify
   "(let ((x (get-prandom-u32))
          (result 0))
      (declare (type u32 x) (type u64 result))
      (if (> x 10)
          (setf result 100)
          (setf result 200))
      (return result))"))

(test torture-setf-repeated
  "Repeated setf to same variable"
  (torture-verify
   "(let ((x 0))
      (declare (type u64 x))
      (setf x 1)
      (setf x (+ x 2))
      (setf x (+ x 3))
      (return x))"))

(test torture-setf-store-pattern
  "Setf with struct-alloc stores"
  (torture-verify
   "(let ((buf (struct-alloc 24)))
      (store u64 buf 0 10)
      (store u64 buf 8 20)
      (store u64 buf 16 30)
      (return (+ (load u64 buf 0) (load u64 buf 8) (load u64 buf 16))))"))

;;; ========== Category 8: Mixed width operations ==========

(test torture-width-load-u8-return-u64
  "Load u8, return as u64"
  (torture-verify
   "(let ((data (ctx-load u32 0))
          (data-end (ctx-load u32 4)))
      (declare (type u64 data data-end))
      (when (> (+ data 1) data-end) (return 0))
      (let ((b (load u8 data 0)))
        (declare (type u8 b))
        (return b)))"))

(test torture-width-load-u16-arith-u64
  "Load u16, do u64 arithmetic"
  (torture-verify
   "(let ((data (ctx-load u32 0))
          (data-end (ctx-load u32 4)))
      (declare (type u64 data data-end))
      (when (> (+ data 2) data-end) (return 0))
      (let ((h (load u16 data 0)))
        (declare (type u16 h))
        (return (+ h 1000))))"))

(test torture-width-store-u8
  "Store u8 to stack buffer"
  (torture-verify
   "(let ((buf (struct-alloc 8)))
      (store u8 buf 0 #xff)
      (store u8 buf 1 #xfe)
      (return (+ (load u8 buf 0) (load u8 buf 1))))"))

(test torture-width-store-u16
  "Store u16 to stack buffer"
  (torture-verify
   "(let ((buf (struct-alloc 8)))
      (store u16 buf 0 #xbeef)
      (return (load u16 buf 0)))"))

(test torture-width-cast-chain
  "Cast chain: u32 → u64 arithmetic"
  (torture-verify
   "(let ((x (get-prandom-u32)))
      (declare (type u32 x))
      (let ((wide (cast u64 x)))
        (declare (type u64 wide))
        (return (+ wide #x100000000))))"))

;;; ========== Category 9: Complex programs ==========
;;;
;;; Larger programs combining many features to stress register allocation,
;;; phi nodes, spilling, and control flow interactions.

(test torture-complex-stats-collector
  "Classify packets and maintain per-protocol stats with helpers"
  (torture-verify
   "(with-packet (data data-end :min-len 34)
      (let* ((proto (ipv4-protocol (+ data 14)))
             (pid (get-current-pid-tgid))
             (ts (ktime-get-ns)))
        (declare (type u8 proto) (type u64 pid ts))
        (cond
          ((= proto 6)   ; TCP
           (incf (getmap stats 0))
           (setf (getmap ts-map 0) ts))
          ((= proto 17)  ; UDP
           (incf (getmap stats 1))
           (setf (getmap ts-map 1) ts))
          ((= proto 1)   ; ICMP
           (incf (getmap stats 2)))
          (t
           (incf (getmap stats 3))))))
    XDP_PASS"
   :maps ((stats :type :array :key-size 4 :value-size 8 :max-entries 4)
          (ts-map :type :array :key-size 4 :value-size 8 :max-entries 4))))

(test torture-complex-multi-branch-merge
  "Variables defined in different branches merge at join point"
  (torture-verify
   "(let* ((r1 (get-prandom-u32))
           (r2 (get-prandom-u32))
           (r3 (get-prandom-u32))
           (a (if (> r1 100) (+ r2 1) (+ r3 2)))
           (b (if (> r2 200) (- r1 3) (+ r1 4)))
           (c (if (> r3 300) (logxor a b) (logand a b))))
      (declare (type u32 r1 r2 r3) (type u64 a b c))
      (return c))"))

(test torture-complex-nested-loops
  "Nested dotimes with accumulator"
  (torture-verify
   "(let ((total 0))
      (declare (type u64 total))
      (dotimes (i 4)
        (dotimes (j 4)
          (setf total (+ total i j))))
      (return total))"))

(test torture-complex-loop-with-helper-and-branch
  "Loop calling helpers with conditional logic inside"
  (torture-verify
   "(let ((count 0)
          (sum 0))
      (declare (type u64 count sum))
      (dotimes (i 8)
        (let ((r (get-prandom-u32)))
          (declare (type u32 r))
          (when (> r #x7fffffff)
            (setf count (+ count 1))
            (setf sum (+ sum r)))))
      (return (+ count sum)))"))

(test torture-complex-many-phis
  "Many variables live across a 4-way branch (cond)"
  (torture-verify
   "(let* ((a (get-prandom-u32))
           (b (get-prandom-u32))
           (c (+ a b))
           (d (- a b))
           (e (logxor a b)))
      (declare (type u32 a b) (type u64 c d e))
      (cond
        ((> a 1000) (return (+ c d e a)))
        ((> b 500)  (return (+ c d a)))
        ((> c 2000) (return (+ d e b)))
        (t          (return (+ c e)))))"))

(test torture-complex-spill-across-helper-calls
  "Many variables live across multiple helper calls forcing heavy spilling"
  (torture-verify
   "(let* ((v0 (get-prandom-u32))
           (v1 (get-prandom-u32))
           (v2 (ktime-get-ns))
           (v3 (get-prandom-u32))
           (v4 (ktime-get-ns))
           (v5 (get-prandom-u32))
           (v6 (get-current-pid-tgid))
           (v7 (get-prandom-u32))
           (combined (+ v0 v1 v2 v3 v4 v5 v6 v7)))
      (declare (type u32 v0 v1 v3 v5 v7) (type u64 v2 v4 v6 combined))
      (return combined))"))

(test torture-complex-map-in-loop
  "Map lookups inside a loop with accumulation"
  (torture-verify
   "(let ((total 0))
      (declare (type u64 total))
      (dotimes (i 4)
        (let ((val (getmap counters i)))
          (when val
            (setf total (+ total val)))))
      (return total))"
   :maps ((counters :type :array :key-size 4 :value-size 8 :max-entries 4))))

(test torture-complex-struct-fill-and-map
  "Allocate struct, fill fields, store to map"
  (torture-verify
   "(let* ((pid-tgid (get-current-pid-tgid))
           (pid (logand pid-tgid #xffffffff))
           (ts (ktime-get-ns))
           (buf (struct-alloc 16)))
      (declare (type u64 pid-tgid pid ts))
      (store u64 buf 0 pid)
      (store u64 buf 8 ts)
      (map-update m pid buf 0)
      (return 0))"
   :maps ((m :type :hash :key-size 4 :value-size 16 :max-entries 1024))))

(test torture-complex-diamond-with-maps
  "Diamond CFG with map operations in both branches"
  (torture-verify
   "(let ((key (get-prandom-u32)))
      (declare (type u32 key))
      (let ((val (getmap m key)))
        (if val
            (progn
              (incf (getmap hits 0))
              (return val))
            (progn
              (incf (getmap misses 0))
              (let ((new-val (struct-alloc 8)))
                (store u64 new-val 0 1)
                (map-update m key new-val 0)
                (return 0))))))"
   :maps ((m :type :hash :key-size 4 :value-size 8 :max-entries 256)
          (hits :type :array :key-size 4 :value-size 8 :max-entries 1)
          (misses :type :array :key-size 4 :value-size 8 :max-entries 1))))

(test torture-complex-early-return-ladder
  "Multiple early returns with increasing state"
  (torture-verify
   "(let* ((r (get-prandom-u32))
           (a (+ r 1))
           (b (+ a 2)))
      (declare (type u32 r) (type u64 a b))
      (when (> r 1000)
        (return a))
      (let ((c (+ b 3)))
        (declare (type u64 c))
        (when (> r 500)
          (return (+ b c)))
        (let ((d (+ c 4)))
          (declare (type u64 d))
          (when (> r 100)
            (return (+ c d)))
          (return (+ a b c d)))))"))

(test torture-complex-setf-accumulator-with-branches
  "Repeated setf to accumulator inside branching logic"
  (torture-verify
   "(let ((acc 0))
      (declare (type u64 acc))
      (let ((r1 (get-prandom-u32)))
        (declare (type u32 r1))
        (when (> r1 100) (setf acc (+ acc 10)))
        (when (> r1 200) (setf acc (+ acc 20)))
        (when (> r1 300) (setf acc (+ acc 30)))
        (when (> r1 400) (setf acc (+ acc 40)))
        (when (> r1 500) (setf acc (+ acc 50))))
      (return acc))"))

(test torture-complex-packet-parse-classify
  "Full packet parse with protocol classification and counters"
  (torture-verify
   "(with-packet (data data-end :min-len 34)
      (let ((eth-t (eth-type data)))
        (when (/= eth-t +ethertype-ipv4+)
          (incf (getmap stats 3))
          (return XDP_PASS))
        (let* ((ip (+ data 14))
               (proto (ipv4-protocol ip))
               (src (ipv4-src-addr ip))
               (dst (ipv4-dst-addr ip))
               (hash (logxor src dst)))
          (declare (type u8 proto) (type u64 src dst hash))
          (incf (getmap stats 0))
          (when (= proto 6)
            (when (> (+ data 54) data-end) (return XDP_PASS))
            (incf (getmap stats 1)))
          (when (= proto 17)
            (when (> (+ data 42) data-end) (return XDP_PASS))
            (incf (getmap stats 2))))))
    XDP_PASS"
   :maps ((stats :type :array :key-size 4 :value-size 8 :max-entries 4))))

(test torture-complex-multi-map-pipeline
  "Chain of map lookups: lookup in A, use result as key for B"
  (torture-verify
   "(let ((key1 (get-prandom-u32)))
      (declare (type u32 key1))
      (let ((val1 (getmap lookup-a key1)))
        (if val1
            (let ((key2 (logand val1 #xffffffff)))
              (declare (type u32 key2))
              (let ((val2 (getmap lookup-b key2)))
                (if val2
                    (return (+ val1 val2))
                    (return val1))))
            (return 0))))"
   :maps ((lookup-a :type :hash :key-size 4 :value-size 8 :max-entries 256)
          (lookup-b :type :hash :key-size 4 :value-size 8 :max-entries 256))))

(test torture-complex-wide-let-star
  "15 sequential bindings with interleaved helpers and arithmetic"
  (torture-verify
   "(let* ((a (get-prandom-u32))
           (b (+ a 1))
           (c (ktime-get-ns))
           (d (logand b #xff))
           (e (get-prandom-u32))
           (f (+ c e))
           (g (get-current-pid-tgid))
           (h (logand g #xffffffff))
           (i (ash g -32))
           (j (+ h i))
           (k (logxor f j))
           (l (get-prandom-u32))
           (m (+ k l))
           (n (- m a))
           (o (+ n d)))
      (declare (type u32 a d e h l) (type u64 b c f g i j k m n o))
      (return o))"))

(test torture-complex-branch-in-branch-in-loop
  "Deeply nested control flow inside a loop"
  (torture-verify
   "(let ((result 0))
      (declare (type u64 result))
      (dotimes (i 4)
        (let ((r (get-prandom-u32)))
          (declare (type u32 r))
          (if (> r #x80000000)
              (if (> r #xc0000000)
                  (setf result (+ result 4))
                  (setf result (+ result 2)))
              (when (> r #x40000000)
                (setf result (+ result 1))))))
      (return result))"))

(test torture-complex-memcpy-with-branches
  "Conditional memcpy between stack buffers"
  (torture-verify
   "(let ((src (struct-alloc 32))
          (dst (struct-alloc 32))
          (r (get-prandom-u32)))
      (declare (type u32 r))
      (store u64 src 0 42)
      (store u64 src 8 99)
      (store u64 src 16 7)
      (store u64 src 24 13)
      (if (> r 100)
          (memcpy dst 0 src 0 32)
          (memset dst 0 0 32))
      (return (+ (load u64 dst 0) (load u64 dst 8))))"))

(test torture-complex-ringbuf-conditional
  "Ring buffer reserve in one branch, different action in the other"
  (torture-verify
   "(let ((r (get-prandom-u32)))
      (declare (type u32 r))
      (when (> r #x80000000)
        (with-ringbuf (event events 16)
          (store u64 event 0 (ktime-get-ns))
          (store u64 event 8 (get-current-pid-tgid))))
      (return 0))"
   :maps ((events :type :ringbuf :max-entries 4096))))

(test torture-complex-12-live-across-call
  "12 variables all live across a helper call, forcing extreme spilling"
  (torture-verify
   "(let* ((a (get-prandom-u32))
           (b (get-prandom-u32))
           (c (get-prandom-u32))
           (d (get-prandom-u32))
           (e (+ a b))
           (f (+ c d))
           (g (- a c))
           (h (- b d))
           (i (logxor e f))
           (j (logand g h))
           (k (logior i j))
           (l (+ e f g h)))
      (declare (type u32 a b c d) (type u64 e f g h i j k l))
      ;; Force a helper call with all 12 vars still live
      (let ((ts (ktime-get-ns)))
        (declare (type u64 ts))
        (return (+ a b c d e f g h i j k l ts))))"))

(test torture-complex-phi-storm
  "Many variables merge at a single join point from 3 predecessors"
  (torture-verify
   "(let ((r (get-prandom-u32)))
      (declare (type u32 r))
      (let* ((a (if (> r 100) 10 20))
             (b (if (> r 200) 30 40))
             (c (if (> r 300) 50 60))
             (d (if (> r 400) 70 80))
             (e (if (> r 500) 90 100)))
        (declare (type u64 a b c d e))
        (return (+ a b c d e))))"))

;;; ========== Category 10: Codegen validation ==========
;;;
;;; These tests check that the compiler emits the expected instructions,
;;; not just that the output compiles/verifies.  They catch bugs where
;;; the compiler emits different-but-verifier-safe code.

(test codegen-const-fold-arithmetic
  "Constant folding should fully evaluate (+ (* 100 200) (/ 1000 5))"
  (let ((bytes (w-body "(return (+ (* 100 200) (/ 1000 5)))")))
    ;; Should fold to: mov r0, 20200; exit — exactly 2 instructions
    (is (= 2 (/ (length bytes) 8))
        "Constant expression should fold to 2 instructions (mov + exit)")
    (is (= +alu64-mov-imm+ (nth-insn-opcode bytes 0))
        "First instruction should be mov immediate")
    (is (= 20200 (nth-insn-imm bytes 0))
        "Folded constant should be 20200")
    (is (= +jmp-exit+ (nth-insn-opcode bytes 1))
        "Second instruction should be exit")))

(test codegen-const-fold-complete
  "Pure constant programs should fold to mov+exit"
  (let ((bytes (w-body "(return 42)")))
    (is (= 2 (/ (length bytes) 8)))
    (is (= 42 (nth-insn-imm bytes 0)))))

(test codegen-setf-chain-collapses
  "Repeated setf with constants should collapse via constant folding"
  (let ((bytes (w-body "(let ((x 0))
                           (declare (type u64 x))
                           (setf x 1)
                           (setf x (+ x 2))
                           (setf x (+ x 3))
                           (return x))")))
    ;; Should fold: x=1, x=1+2=3, x=3+3=6 → mov r0,6; exit
    ;; or at worst: mov r0,1; add r0,5; exit (partial fold)
    (is (<= (/ (length bytes) 8) 4)
        "Setf chain with constants should collapse to <= 4 instructions")))

(test codegen-branch-structure
  "if/else should produce conditional jump with two return paths"
  (let ((bytes (w-body "(let ((x (get-prandom-u32)))
                           (declare (type u32 x))
                           (if (> x 10) (return 1) (return 0)))")))
    ;; Must contain: call (get-prandom), conditional jump, two mov+exit pairs
    (is (has-opcode-p bytes +jmp-call+) "Should have a helper call")
    (is (or (has-opcode-p bytes +jmp-jgt-imm+)
            (has-opcode-p bytes +jmp-jle-imm+)
            (has-opcode-p bytes +jmp-jgt-reg+)
            (has-opcode-p bytes +jmp-jle-reg+))
        "Should have a conditional jump")
    (is (>= (count-opcode bytes +jmp-exit+) 2)
        "Should have at least 2 exit instructions (then/else paths)")))

(test codegen-helper-call-id
  "get-prandom-u32 should emit call with helper ID 7"
  (let ((bytes (w-body "(return (get-prandom-u32))")))
    (let ((call-idx (find-opcode bytes +jmp-call+)))
      (is (not (null call-idx)) "Should contain a call instruction")
      (when call-idx
        (is (= 7 (nth-insn-imm bytes call-idx))
            "Call should be to helper 7 (get_prandom_u32)")))))

(test codegen-ktime-helper-id
  "ktime-get-ns should emit call with helper ID 5"
  (let ((bytes (w-body "(return (ktime-get-ns))")))
    (let ((call-idx (find-opcode bytes +jmp-call+)))
      (is (not (null call-idx)))
      (when call-idx
        (is (= 5 (nth-insn-imm bytes call-idx))
            "Call should be to helper 5 (ktime_get_ns)")))))

(test codegen-map-lookup-helper-id
  "map-lookup should emit call with helper ID 1"
  (let ((bytes (w-body "(let ((key 0))
                           (declare (type u32 key))
                           (let ((val (map-lookup m key)))
                             (declare (type u64 val))
                             (if val (return 1) (return 0))))"
                       :maps '((m :type :array :key-size 4
                                   :value-size 8 :max-entries 1)))))
    (let ((call-idx (find-opcode bytes +jmp-call+)))
      (is (not (null call-idx)) "Should contain a call instruction")
      (when call-idx
        (is (= 1 (nth-insn-imm bytes call-idx))
            "Call should be to helper 1 (map_lookup_elem)")))))

(test codegen-map-update-helper-id
  "map-update should emit call with helper ID 2"
  (let ((bytes (w-body "(let ((key 0)
                              (val (struct-alloc 8)))
                           (declare (type u32 key))
                           (store u64 val 0 42)
                           (map-update m key val 0)
                           (return 0))"
                       :maps '((m :type :hash :key-size 4
                                   :value-size 8 :max-entries 256)))))
    (is (has-opcode-p bytes +jmp-call+) "Should contain a call instruction")
    ;; Find the map_update_elem call (helper 2)
    (let ((n (/ (length bytes) 8)))
      (is (loop for i below n
                thereis (and (= +jmp-call+ (nth-insn-opcode bytes i))
                             (= 2 (nth-insn-imm bytes i))))
          "Should contain call to helper 2 (map_update_elem)"))))

(test codegen-map-delete-helper-id
  "map-delete should emit call with helper ID 3"
  (let ((bytes (w-body "(let ((key 0))
                           (declare (type u32 key))
                           (map-delete m key)
                           (return 0))"
                       :maps '((m :type :hash :key-size 4
                                   :value-size 8 :max-entries 256)))))
    (let ((n (/ (length bytes) 8)))
      (is (loop for i below n
                thereis (and (= +jmp-call+ (nth-insn-opcode bytes i))
                             (= 3 (nth-insn-imm bytes i))))
          "Should contain call to helper 3 (map_delete_elem)"))))

(test codegen-loop-has-backward-branch
  "dotimes must produce a backward branch"
  (let ((bytes (w-body "(let ((sum 0))
                           (declare (type u64 sum))
                           (dotimes (i 4)
                             (setf sum (+ sum 1)))
                           (return sum))")))
    ;; A backward branch has a negative offset
    (let* ((n (/ (length bytes) 8))
           (has-back (loop for i below n
                           for op = (nth-insn-opcode bytes i)
                           thereis (and (member op (list +jmp-ja+ +jmp-jgt-imm+ +jmp-jge-imm+
                                                        +jmp-jlt-imm+ +jmp-jle-imm+))
                                        (< (nth-insn-off bytes i) 0)))))
      (is-true has-back "Loop should contain a backward branch"))))

(test codegen-callee-saved-across-helper
  "Variables live across helper calls should use callee-saved registers (R6-R9)"
  (let ((bytes (w-body "(let* ((a (get-prandom-u32))
                                (b (ktime-get-ns)))
                           (declare (type u32 a) (type u64 b))
                           (return (+ a b)))")))
    ;; After the first call (get-prandom), a must be saved to R6-R9.
    ;; Look for a mov to a callee-saved register between the two calls.
    (let* ((n (/ (length bytes) 8))
           (call-indices (loop for i below n
                               when (= +jmp-call+ (nth-insn-opcode bytes i))
                               collect i)))
      (is (= 2 (length call-indices))
          "Should have exactly 2 helper calls")
      (when (= 2 (length call-indices))
        ;; Between calls, there should be a mov to R6-R9
        (let ((has-save (loop for i from (first call-indices) to (second call-indices)
                              for op = (nth-insn-opcode bytes i)
                              for dst = (logand (nth-insn-regs bytes i) #x0f)
                              thereis (and (= op +alu64-mov-reg+)
                                           (<= 6 dst 9)))))
          (is-true has-save
              "Should save first result to callee-saved register before second call"))))))

(test codegen-struct-alloc-uses-stack
  "struct-alloc should use stack (R10-relative addressing)"
  (let ((bytes (w-body "(let ((buf (struct-alloc 16)))
                           (store u64 buf 0 42)
                           (return 0))")))
    ;; Should contain an add to R10 (frame pointer) for the stack address
    (let* ((n (/ (length bytes) 8))
           (has-fp-ref (loop for i below n
                             for op = (nth-insn-opcode bytes i)
                             for regs = (nth-insn-regs bytes i)
                             thereis (and (= op +alu64-add-imm+)
                                          (= (logand regs #x0f) 10)))))
      ;; R10 is read-only in BPF, so the compiler copies it: mov rN, r10; add rN, -offset
      (let ((has-fp-copy (loop for i below n
                               for op = (nth-insn-opcode bytes i)
                               for src = (ash (nth-insn-regs bytes i) -4)
                               thereis (and (= op +alu64-mov-reg+)
                                            (= src 10)))))
        (is-true has-fp-copy
            "struct-alloc should reference frame pointer R10")))))

(test codegen-exit-is-last
  "Every program should end with an exit instruction"
  (let ((bytes (w-body "(return 42)")))
    (let ((n (/ (length bytes) 8)))
      (is (= +jmp-exit+ (nth-insn-opcode bytes (1- n)))
          "Last instruction should be exit"))))

(test codegen-no-helper-46
  "No program should emit helper 46 (was bogus map-lookup-and-delete)"
  (dolist (source '("(return 0)"
                    "(return (get-prandom-u32))"
                    "(let ((sum 0))
                       (declare (type u64 sum))
                       (dotimes (i 4) (setf sum (+ sum 1)))
                       (return sum))"))
    (let* ((bytes (compile-insn-bytes (read-whistler-forms source)))
           (n (/ (length bytes) 8)))
      (is (not (loop for i below n
                     thereis (and (= +jmp-call+ (nth-insn-opcode bytes i))
                                  (= 46 (nth-insn-imm bytes i)))))
          (format nil "Should never emit call to helper 46: ~a" source)))))

;;; ========== Category 11: Generated ALU tests ==========

(defun substitute-type-template (template type)
  "Replace {type} in TEMPLATE with TYPE string."
  (let ((result template)
        (target "{type}"))
    (loop for pos = (search target result)
          while pos
          do (setf result (concatenate 'string
                                       (subseq result 0 pos)
                                       type
                                       (subseq result (+ pos (length target))))))
    result))

(defun make-alu-test-source (op type operand-expr)
  "Generate source for an ALU torture test.
   Uses get-prandom-u32 for scalar input (ctx-load returns packet pointers
   on XDP, which the verifier prohibits arithmetic on)."
  (format nil "(let ((x (get-prandom-u32)))
  (declare (type ~a x))
  (return (~a x ~a)))"
          type op operand-expr))

(defun make-cmp-test-source (cmp operand-expr)
  "Generate source for a comparison torture test."
  (format nil "(let ((x (get-prandom-u32)))
  (declare (type u64 x))
  (if (~a x ~a) (return 1) (return 0)))"
          cmp operand-expr))

(defun register-alu-torture-tests ()
  "Generate and register ALU torture tests."
  (let ((ops '("+" "-" "*" "/" "mod" "logior" "logand" "logxor"))
        (shift-ops '("<<" ">>" ">>>"))
        (types '("u64" "u32"))
        (operand-kinds '(("imm1" . "1")
                         ("imm42" . "42")
                         ("imm-large" . "#x7fff")))
        (shift-operand-kinds '(("imm1" . "1")
                               ("imm8" . "8")
                               ("imm31" . "31"))))
    ;; Non-shift ALU ops
    (dolist (op ops)
      (dolist (type types)
        (dolist (kind operand-kinds)
          (let* ((kind-name (car kind))
                 (operand (cdr kind))
                 (test-name (intern (format nil "TORTURE-ALU-~:@(~a~)-~:@(~a~)-~:@(~a~)"
                                            op type kind-name)
                                    :whistler/tests))
                 (source (make-alu-test-source op type operand)))
            (eval `(test ,test-name
                     ,(format nil "ALU torture: ~a ~a ~a" op type kind-name)
                     (torture-verify ,source)))))))
    ;; Shift ops with shift-safe operands
    (dolist (op shift-ops)
      (dolist (type types)
        (dolist (kind shift-operand-kinds)
          (let* ((kind-name (car kind))
                 (operand (cdr kind))
                 (test-name (intern (format nil "TORTURE-ALU-~:@(~a~)-~:@(~a~)-~:@(~a~)"
                                            op type kind-name)
                                    :whistler/tests))
                 (source (make-alu-test-source op type operand)))
            (eval `(test ,test-name
                     ,(format nil "ALU torture: ~a ~a ~a" op type kind-name)
                     (torture-verify ,source)))))))))

(defun register-cmp-torture-tests ()
  "Generate and register comparison torture tests."
  (let ((cmps '("=" "/=" ">" ">=" "<" "<=" "s>" "s>=" "s<" "s<="))
        (operand-kinds '(("imm" . "42")
                         ("imm0" . "0"))))
    (dolist (cmp cmps)
      (dolist (kind operand-kinds)
        (let* ((kind-name (car kind))
               (operand (cdr kind))
               (test-name (intern (format nil "TORTURE-CMP-~:@(~a~)-~:@(~a~)"
                                          cmp kind-name)
                                  :whistler/tests))
               (source (make-cmp-test-source cmp operand)))
          (eval `(test ,test-name
                   ,(format nil "CMP torture: ~a ~a" cmp kind-name)
                   (torture-verify ,source))))))))

(defun register-width-torture-tests ()
  "Generate and register mixed-width load/store/return tests."
  (let ((load-types '("u8" "u16" "u32" "u64"))
        (min-sizes '(1 2 4 8)))
    (loop for lt in load-types
          for min-sz in min-sizes
          do (let* ((test-name (intern (format nil "TORTURE-WIDTH-LOAD-~:@(~a~)-RETURN"
                                               lt)
                                       :whistler/tests))
                    (source (format nil
                                   "(let ((data (ctx-load u32 0))
                                          (data-end (ctx-load u32 4)))
                                      (declare (type u64 data data-end))
                                      (when (> (+ data ~d) data-end) (return 0))
                                      (let ((v (load ~a data 0)))
                                        (declare (type ~a v))
                                        (return v)))"
                                   min-sz lt lt)))
               (eval `(test ,test-name
                        ,(format nil "Width torture: load ~a return" lt)
                        (torture-verify ,source)))))))

;;; ========== Register generated tests ==========

(register-alu-torture-tests)
(register-cmp-torture-tests)
(register-width-torture-tests)

;;; ========== Summary ==========

(test torture-summary
  "Print torture test summary and clean up temp directory"
  (format t "~&;; Torture summary: ~d compiled, ~d kernel-verified~%"
          *torture-compiled* *torture-verified*)
  ;; Clean up private temp directory
  (when *torture-tmpdir*
    (handler-case
        (progn
          (dolist (f (directory (merge-pathnames "*.*" *torture-tmpdir*)))
            (delete-file f))
          (sb-posix:rmdir *torture-tmpdir*))
      (error () nil))
    (setf *torture-tmpdir* nil))
  (pass))
