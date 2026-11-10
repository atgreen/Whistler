(in-package #:whistler/tests)

(in-suite optimization-suite)

;;; ========== Phi-threading regression tests (issue #12) ==========
;;;
;;; When phi-branch-threading redirects a predecessor, the corresponding
;;; phi input must be removed.  Otherwise simplify-cfg's block merge
;;; drops the phi definition while its uses survive, leaving an undefined
;;; vreg that the emitter assigns to a random callee-saved register.

(test phi-threading-removes-stale-input
  "Phi-threading must remove the redirected input from the phi (issue #12).
   After threading + simplify-cfg, every vreg used in the IR must have a definition."
  (let* ((body (read-whistler-forms
                "(let* ((pid-tgid (get-current-pid-tgid))
                        (pid (logand (ash pid-tgid -32) #xffffffff))
                        (now (ktime-get-ns))
                        (val (getmap stats pid)))
                   (if val
                       (progn
                         (store u64 val 0 (+ (load u64 val 0) 1))
                         (store u64 val 32 now))
                       (let ((init (struct-alloc 40)))
                         (store u64 init 0 1)
                         (store u64 init 32 now)
                         (map-update stats pid init 0))))"))
         (maps '((stats :type :hash :key-size 4 :value-size 40 :max-entries 256)))
         (map-structs
          (loop for (name . rest) in maps
                for idx from 0
                collect (whistler/compiler::make-bpf-map
                         :name name
                         :type (whistler/compiler:resolve-map-type (getf rest :type))
                         :key-size (getf rest :key-size)
                         :value-size (getf rest :value-size)
                         :max-entries (getf rest :max-entries)
                         :flags 0 :index idx)))
         ;; Macro-expand and constant-fold
         (expanded (let ((whistler::*maps* maps))
                     (mapcar (lambda (form)
                               (whistler/compiler:constant-fold-sexpr
                                (whistler/compiler:whistler-macroexpand form)))
                             body)))
         (ir (whistler/ir:lower-program "tp" "GPL" map-structs expanded)))
    ;; Run the optimizer (includes phi-branch-threading)
    (whistler/ir:optimize-ir ir)
    ;; Collect all defined vregs and all used vregs
    (let ((defined (make-hash-table))
          (used (make-hash-table)))
      (dolist (block (whistler/ir:ir-program-blocks ir))
        (dolist (insn (whistler/ir:basic-block-insns block))
          (when (whistler/ir:ir-insn-dst insn)
            (setf (gethash (whistler/ir:ir-insn-dst insn) defined) t))
          (dolist (vreg (whistler/ir::ir-insn-all-vreg-uses insn))
            (setf (gethash vreg used) t))))
      ;; Every used vreg must have a definition
      (let ((undefined nil))
        (maphash (lambda (vreg _)
                   (declare (ignore _))
                   (unless (gethash vreg defined)
                     (push vreg undefined)))
                 used)
        (is (null undefined)
            (format nil "Vregs used without definition: ~a" undefined))))))

(test phi-threading-helper-call-before-getmap
  "let* with helper call + getmap must not assign getmap result to the helper's register.
   Regression test for issue #12: ktime-get-ns result in R7 clobbered getmap's phi."
  (let* ((maps '((stats :type :hash :key-size 4 :value-size 40 :max-entries 256)))
         (bytes (let ((whistler::*maps* maps))
                  (w-body "(let* ((pid-tgid (get-current-pid-tgid))
                                  (pid (logand (ash pid-tgid -32) #xffffffff))
                                  (now (ktime-get-ns))
                                  (val (getmap stats pid)))
                             (if val
                                 (progn
                                   (store u64 val 0 (+ (load u64 val 0) 1))
                                   (store u64 val 32 now))
                                 (let ((init (struct-alloc 40)))
                                   (store u64 init 0 1)
                                   (store u64 init 32 now)
                                   (map-update stats pid init 0))))"
                         :maps maps)))
         (n (/ (length bytes) 8)))
    ;; Find the map_lookup_elem call (helper 1)
    (let ((map-call-idx
           (loop for i below n
                 when (and (= +jmp-call+ (nth-insn-opcode bytes i))
                           (= 1 (nth-insn-imm bytes i)))
                   return i)))
      (is (not (null map-call-idx))
          "Should contain a map_lookup_elem call")
      (when map-call-idx
        ;; After the map_lookup_elem call, the inner null check should test R0
        ;; (the return register), not R7 (a callee-saved register holding ktime).
        ;; Find the first conditional jump after the map_lookup call.
        (let ((first-cond-idx
               (loop for i from (1+ map-call-idx) below n
                     when (member (nth-insn-opcode bytes i)
                                  (list +jmp-jeq-imm+ +jmp-jne-imm+
                                        +jmp-jeq-reg+ +jmp-jne-reg+))
                       return i)))
          (when first-cond-idx
            (let* ((reg-byte (nth-insn-regs bytes first-cond-idx))
                   (dst-reg (logand reg-byte #x0f)))
              ;; The null check must test the map_lookup_elem return value
              ;; (R0 or a caller-saved reg it was moved to), not R7
              ;; (ktime-get-ns result stashed in callee-saved).
              (is (<= dst-reg 5)
                  (format nil "Inner null check should use caller-saved reg, got R~d" dst-reg)))))))))

(test probe-read-user-arg-order
  "probe-read-user must set R1=dest R2=size R3=src without clobbering (issue #31).
   When dest involves pointer arithmetic and src comes from a caller-saved
   register, the argument setup must not clobber dest when loading the size
   immediate into R2."
  (let* ((maps '((events :type :ringbuf :max-entries 16384)))
         (bytes (let ((whistler::*maps* maps))
                  (w-body "(let ((buf (get-prandom-u32)))
                             (declare (type u64 buf))
                             (when buf
                               (let ((dst (struct-alloc 64)))
                                 (probe-read-user dst 64 buf)
                                 (return 0)))
                             (return 0))"
                          :maps maps)))
         (n (/ (length bytes) 8)))
    ;; Find the probe_read_user call (helper 112)
    (let ((call-idx
           (loop for i below n
                 when (and (= +jmp-call+ (nth-insn-opcode bytes i))
                           (= 112 (nth-insn-imm bytes i)))
                   return i)))
      (is (not (null call-idx))
          "Should contain a call to helper 112 (probe_read_user)")
      (when call-idx
        ;; Walk backward from the call to find the R2 = 64 immediate load.
        ;; R2 must contain the size (64), not a clobbered pointer.
        (let ((r2-imm-idx
               (loop for i from (1- call-idx) downto 0
                     when (and (= +alu64-mov-imm+ (nth-insn-opcode bytes i))
                               (= 2 (logand (nth-insn-regs bytes i) #x0f))
                               (= 64 (nth-insn-imm bytes i)))
                       return i)))
          (is (not (null r2-imm-idx))
              "R2 should be loaded with immediate 64 (the size argument)")
          (when r2-imm-idx
            ;; Between R2=64 and the CALL, there must be no other write to R2
            ;; (that was the clobbering bug: dest ptr was computed into R2,
            ;; then size=64 overwrote it, then R1=R2 copied the wrong value)
            (let ((r2-clobber
                   (loop for i from (1+ r2-imm-idx) below call-idx
                         for opcode = (nth-insn-opcode bytes i)
                         for dst-reg = (logand (nth-insn-regs bytes i) #x0f)
                         when (and (= dst-reg 2)
                                   ;; Exclude the R2=64 itself
                                   (not (= i r2-imm-idx)))
                           return i)))
              (is (null r2-clobber)
                  (format nil "R2 clobbered at insn ~d between size load and call"
                          r2-clobber)))))))))

(test probe-read-user-branched-arg-order
  "probe-read-user in else branch must not clobber args (issue #31).
   This is the specific pattern from the bug report: probe-read-user
   where src comes from a chain of pointer dereferences in a branch."
  (let* ((maps '((events :type :ringbuf :max-entries 16384)))
         (bytes (let ((whistler::*maps* maps))
                  (w-body "(let ((ubuf (get-prandom-u32))
                                 (dst (struct-alloc 64)))
                             (declare (type u64 ubuf))
                             (if ubuf
                                 (probe-read-user dst 64 ubuf)
                                 (let ((alt-src (get-prandom-u32)))
                                   (declare (type u64 alt-src))
                                   (when alt-src
                                     (probe-read-user dst 64 alt-src))))
                             (return 0))"
                          :maps maps)))
         (n (/ (length bytes) 8)))
    ;; Find ALL probe_read_user calls — there should be 2
    (let ((call-indices
           (loop for i below n
                 when (and (= +jmp-call+ (nth-insn-opcode bytes i))
                           (= 112 (nth-insn-imm bytes i)))
                   collect i)))
      (is (= 2 (length call-indices))
          (format nil "Expected 2 probe_read_user calls, got ~d"
                  (length call-indices)))
      ;; For each call, verify R2=64 is set and not clobbered before the call
      (dolist (call-idx call-indices)
        (let ((r2-imm-idx
               (loop for i from (1- call-idx) downto (max 0 (- call-idx 10))
                     when (and (= +alu64-mov-imm+ (nth-insn-opcode bytes i))
                               (= 2 (logand (nth-insn-regs bytes i) #x0f))
                               (= 64 (nth-insn-imm bytes i)))
                       return i)))
          (is (not (null r2-imm-idx))
              (format nil "R2=64 not found before call at insn ~d" call-idx)))))))

(test phi-threading-getmap-without-helper-call
  "getmap without a preceding helper call in let* should still work correctly."
  (let* ((maps '((m :type :hash :key-size 4 :value-size 8 :max-entries 256)))
         (n (let ((whistler::*maps* maps))
              (w-count "(let* ((pid-tgid (get-current-pid-tgid))
                               (pid (logand (ash pid-tgid -32) #xffffffff))
                               (val (getmap m pid)))
                          (if val (return val) (return 0)))"
                       :maps maps))))
    ;; Should compile without issues
    (is (> n 5) "getmap without helper call should compile")))

;;; ========== Spill-reload scratch regression (whistler-snx) ==========
;;;
;;; Spill reloads must never clobber a live caller-saved vreg. The old
;;; emitter reloaded spilled operands into fixed R1/R2/R3 scratch at
;;; non-call instructions; with six values live across helper calls one
;;; spills, and its reload silently corrupted whichever vreg regalloc had
;;; placed in the scratch register — a wrong-value miscompile the
;;; verifier accepts. Now R0 (never allocated) is the first scratch and
;;; R5 (reserved from the caller pool whenever anything spills) the
;;; second. This test *executes* the emitted scalar code in a mini
;;; interpreter, so any scratch clobber shows up as a wrong sum no
;;; matter which registers the emitter picks.

(test spill-reload-scratch-preserves-live-values
  "A spilled operand's reload must not corrupt live registers (whistler-snx).
   Six helper-call results overflow the callee-saved pool, spilling one;
   summing them exercises spill reloads at ALU instructions while the
   partial sums are live in caller-saved registers."
  (let ((bytes (w-body "(let ((a (get-prandom-u32))
                              (b (get-prandom-u32))
                              (c (get-prandom-u32))
                              (d (get-prandom-u32))
                              (e (get-prandom-u32))
                              (f (get-prandom-u32)))
                          (return (+ (+ (+ a b) (+ c d)) (+ e f))))")))
    (is (= 63 (interpret-scalar-bpf bytes '(1 2 4 8 16 32)))
        "sum of six call results must be 63 — a wrong value means a spill
         reload clobbered a live register")))

(test log2-preserves-live-source
  "log2 must not shift a still-live source register in place (whistler-dtx)."
  (let ((bytes (w-body "(let ((x (get-prandom-u32)))
                          (return (+ (log2 x) x)))")))
    ;; log2(1000) = 9 (floor), so the result must be 1009.
    (is (= 1009 (interpret-scalar-bpf bytes '(1000)))
        "log2 corrupted its source: (+ (log2 1000) 1000) must be 1009")))

;;; Spill homes have storage lifetimes beyond register allocation decisions.
(defun spill-compaction-test-program (instructions)
  (whistler/ir::make-ir-program
   :entry 'entry
   :blocks (list (whistler/ir::make-basic-block
                  :label 'entry
                  :insns (mapcar (lambda (spec)
                                   (destructuring-bind (op dst args) spec
                                     (whistler/ir::make-ir-insn :op op :dst dst :args args :type :u64)))
                                 instructions)))))

(defun forced-spill-homes (&rest vregs)
  (let ((result (make-hash-table)))
    (loop for vreg in vregs for offset from 1
          do (setf (gethash vreg result) (list :stack (* -8 offset))))
    result))

(test spill-compaction-keeps-inclusive-boundaries
  "A result cannot overwrite an operand that is still consumed at the same instruction."
  (let ((prog (spill-compaction-test-program
               '((:mov 1 ((:imm 11))) (:add 2 (1 (:imm 1)))
                 (:mov 3 ((:imm 99))) (:ret nil (3)))))
        (homes (forced-spill-homes 1 2 3)))
    (multiple-value-bind (result extent) (whistler/ir::compact-spill-slots prog homes)
      (is (not (equal (gethash 1 result) (gethash 2 result))))
      (is (equal (gethash 1 result) (gethash 3 result)))
      (is (= -16 extent)))))

(test spill-compaction-preserves-address-backed-storage
  "Emitter caches can continue using address-backed values after their register use ends."
  (let ((prog (spill-compaction-test-program
               '((:mov 1 ((:imm 11))) (:stack-addr 2 (1))
                 (:mov 3 ((:imm 22))) (:call nil ((:helper 7) 2 3))
                 (:struct-alloc 4 ((:imm 16))) (:mov 5 ((:imm 33))) (:ret nil (5)))))
        (homes (forced-spill-homes 1 2 3 4 5)))
    (multiple-value-bind (result extent) (whistler/ir::compact-spill-slots prog homes)
      (dolist (private '(1 2 4))
        (is (not (equal (gethash private result) (gethash 3 result))))
        (is (not (equal (gethash private result) (gethash 5 result)))))
      (is (equal (gethash 3 result) (gethash 5 result)))
      (is (= -32 extent)))))

(test spill-compaction-preserves-phi-edge-copies
  "PHI homes become live on predecessor edges, before their textual definitions."
  (let* ((entry (whistler/ir::make-basic-block
                 :label 'entry :succs '(join)
                 :insns (list (whistler/ir::make-ir-insn :op :mov :dst 1 :args '((:imm 11)) :type :u64)
                              (whistler/ir::make-ir-insn :op :mov :dst 2 :args '((:imm 22)) :type :u64)
                              (whistler/ir::make-ir-insn :op :br :args '((:label join))))))
         (join (whistler/ir::make-basic-block
                :label 'join :preds '(entry)
                :insns (list (whistler/ir::make-ir-insn :op :phi :dst 3 :args '((2 (:label entry))) :type :u64)
                             (whistler/ir::make-ir-insn :op :phi :dst 4 :args '((1 (:label entry))) :type :u64)
                             (whistler/ir::make-ir-insn :op :add :dst 5 :args '(3 4) :type :u64)
                             (whistler/ir::make-ir-insn :op :ret :args '(5)))))
         (prog (whistler/ir::make-ir-program :entry 'entry :blocks (list entry join)))
         (homes (forced-spill-homes 1 2 3 4 5)))
    (multiple-value-bind (result extent) (whistler/ir::compact-spill-slots prog homes)
      (is (not (equal (gethash 1 result) (gethash 3 result))))
      (is (not (equal (gethash 2 result) (gethash 4 result))))
      (is (not (equal (gethash 3 result) (gethash 4 result))))
      (is (= -32 extent)))))

(test disjoint-spill-pressure-fits-bpf-stack
  "Many disjoint helper-result groups must fit and execute correctly without accumulating homes."
  (let* ((body (format nil "(let ((total u64 0)) ~{~A~%~} (return total))"
                       (loop repeat 80 collect
                         "(setf total (+ total (let ((a (get-prandom-u32)) (b (get-prandom-u32))
                                                    (c (get-prandom-u32)) (d (get-prandom-u32))
                                                    (e (get-prandom-u32)) (f (get-prandom-u32)))
                                               (+ (+ (+ a b) (+ c d)) (+ e f)))))")))
         (bytes (w-body body))
         (values (loop repeat 80 append '(1 2 4 8 16 32))))
    (is (= (* 80 63) (interpret-scalar-bpf bytes values)))))

(test spill-liveness-stays-a-set-across-diamonds
  "A long-lived spilled value must not multiply by the number of CFG paths."
  (let* ((body (format nil
                       "(let ((a (get-prandom-u32)) (b (get-prandom-u32))
                              (c (get-prandom-u32)) (d (get-prandom-u32))
                              (e (get-prandom-u32)) (f (get-prandom-u32)))
                          (let ((total u64 0)) ~{~A~%~}
                            (return (+ total (+ (+ (+ a b) (+ c d)) (+ e f))))))"
                       (loop repeat 25 collect
                         "(setf total (if (> (get-prandom-u32) 0) (+ total 1) (+ total 2)))")))
         (bytes (w-body body)))
    (is (= 88 (interpret-scalar-bpf bytes (append '(1 2 4 8 16 32) (make-list 25 :initial-element 1)))))))

(test spilled-buffer-address-preserves-live-caller-register
  "Stack buffer/address emission must use reserved R0, never overwrite an allocated R1."
  (dolist (address-op '(:struct-alloc :stack-addr))
    (let* ((prog (spill-compaction-test-program
                  (append '((:call 1 ((:helper 7))))
                          (if (eq address-op :struct-alloc)
                              '((:struct-alloc 2 ((:imm 16))))
                              '((:stack-addr 2 (1))))
                          '((:ret nil (1))))))
           (homes (make-hash-table)))
      (setf (gethash 1 homes) '(:reg 1) (gethash 2 homes) '(:stack -8))
      (sb-int:encapsulate 'whistler/ir::linear-scan-alloc 'force-buffer-spill
                         (lambda (function &rest arguments)
                           (declare (ignore function arguments))
                           (values homes -8)))
      (unwind-protect
           (let* ((cu (whistler/ir::emit-ir-to-bpf prog))
                  (bytes (whistler/bpf:insn-bytes (whistler/compiler:cu-insns cu))))
             (is (= 42 (interpret-scalar-bpf bytes '(42)))))
        (sb-int:unencapsulate 'whistler/ir::linear-scan-alloc 'force-buffer-spill)))))

(test context-entry-loads-after-map-helpers-require-a-saved-context
  "Pure map lookups still clobber the register carrying the entry context."
  (dolist (op '(:map-lookup :map-lookup-ptr :map-update :map-delete :call
                :tail-call :get-stackid :kfunc-call :ringbuf-reserve))
    (dolist (access '(:ctx-load :ctx-store :load :store))
      (let ((prog (spill-compaction-test-program
                   `((:arg0 1 ()) (,op 2 ()) (,access 3 (1 (:imm 48))) (:ret nil (3))))))
        (is-false (whistler/ir::ctx-loads-early-p prog)))))
  (dolist (op '(:map-lookup :map-lookup-ptr))
    (let ((prog (spill-compaction-test-program
                 `((:arg0 1 ()) (:ctx-load 2 (1 (:imm 76))) (,op 3 ()) (:ret nil (2))))))
      (is-true (whistler/ir::ctx-loads-early-p prog)))))

(defun compile-context-helper-regression (body)
  (let* ((maps '((whistler::ctx-test :type :array :key-size 4 :value-size 8 :max-entries 1)))
         (whistler::*maps* maps)
         (cu (whistler::compile-program "classifier" "GPL" maps
                                        (read-whistler-forms body) :prog-type :tc)))
    (whistler/bpf:insn-bytes (whistler/compiler:cu-insns cu))))

(test emitted-context-load-after-map-lookup-survives-helper-clobber
  "Execute the map-first context read with the full R1-R5 helper poison model."
  (let ((bytes (compile-context-helper-regression
                "(let ((hit (map-lookup ctx-test 0))
                       (data (ctx u32 76)) (end (ctx u32 80)))
                   (return (+ data (+ end (if (/= hit 0) 7 9)))))")))
    (is (= 7 (interpret-scalar-bpf bytes '(42))))
    (is (= 9 (interpret-scalar-bpf bytes '(0))))))

(test emitted-raw-context-store-after-map-lookup-survives-helper-clobber
  "Raw ctx-ptr use is also live across the helper, even without a ctx-load op."
  (let ((bytes (compile-context-helper-regression
                "(let ((hit (map-lookup ctx-test 0)))
                   (when (/= hit 0) (store u32 (ctx-ptr) 48 123))
                   (return 2))")))
    (is (= 2 (interpret-scalar-bpf bytes '(42))))
    (is (= 2 (interpret-scalar-bpf bytes '(0))))))

(test helper-and-kfunc-immediates-preserve-full-width
  "Observe every argument register at the call boundary, including constants
propagated into a helper/kfunc and values whose low32 sign bit is set."
  (dolist (kind '(:helper :kfunc))
    (dolist (propagated '(nil t))
      (dolist (value '(0 #x7fffffff #x80000000 #xffffffff #x100000000
                      #x0e00000000000053 #x8000000000000000 #xffffffffffffffff
                      -102 -2147483648 #xffffffff80000000))
        (loop for target from 1 to 5 do
          (let* ((ctx (whistler/ir::make-emit-ctx))
                 (arguments
                   (loop for reg from 1 to 5
                         for constant = (if (= reg target) value (+ reg 10))
                         collect (if propagated
                                     (progn (setf (gethash reg (whistler/ir::emit-ctx-const-values ctx)) constant) reg)
                                     (list :imm constant)))))
            (if (eq kind :helper)
                (whistler/ir::emit-call-insn ctx nil (cons '(:helper 7) arguments))
                (whistler/ir::emit-kfunc-call-insn ctx nil (cons '(:kfunc "test") arguments)))
            ;; Replace CALL with an observation of its argument. Setup is the
            ;; real emitter path; the scalar oracle would otherwise poison R1-R5.
            (pop (whistler/ir::emit-ctx-insns ctx))
            (whistler/ir::ectx-emit ctx (whistler/bpf:emit-mov64-reg 0 target))
            (whistler/ir::ectx-emit ctx (whistler/bpf:emit-exit))
            (let ((bytes (whistler/bpf:insn-bytes (reverse (whistler/ir::emit-ctx-insns ctx)))))
              (is (= (ldb (byte 64 0) value) (interpret-scalar-bpf bytes nil))))))))))

(test phi-threading-preserves-values-after-validation
  "A merged value remains live after a later conditional early return."
  (dolist (initial '(0 7))
    (dolist (selected '(1 102))
      (dolist (nested '(nil t))
        (let* ((source
                 (format nil
                         "(let ((offset u32 ~D))
                            (when (= (get-prandom-u32) 1) (setf offset ~D))
                            (when (/= offset 0)
                              ~A)
                            (return offset))"
                         initial selected
                         (if nested
                             "(let ((local u32 0))
                                (unless (= (get-prandom-u32) 1) (return 2))
                                (if (= (get-prandom-u32) 1)
                                    (setf local 10) (setf local 20))
                                (unless (= local 10) (return 3)))"
                             "(unless (= (get-prandom-u32) 1) (return 2))")))
               (bytes (compile-insn-bytes (read-whistler-forms source))))
          (dolist (choose '(0 1))
            (dolist (allow '(0 1))
              (dolist (inner '(0 1))
                (let* ((value (if (= choose 1) selected initial))
                       (expected (cond ((zerop value) value)
                                       ((zerop allow) 2)
                                       ((and nested (zerop inner)) 3)
                                       (t value))))
                  (is (= expected (interpret-scalar-bpf bytes (list choose allow inner)))
                      "~A inputs ~S" source (list choose allow inner)))))))))))

(test peephole-map-relocations-retain-surviving-identities
  "Deleting unreachable map references cannot relabel a later program array."
  (dolist (dead-count '(1 2 3))
    (dolist (live-count '(1 2 3))
      (let* ((maps '((dead-map :type :hash :key-size 4 :value-size 8 :max-entries 1)
                     (live-map :type :hash :key-size 4 :value-size 8 :max-entries 1)
                     (stages :type :prog-array :key-size 4 :value-size 4 :max-entries 4)))
             (source (format nil
                             "(when (= (get-prandom-u32) 1) (return 0) ~{~A~})
                              ~{~A~} (tail-call stages 3) (return 2)"
                             (make-list dead-count :initial-element "(map-delete dead-map 0) ")
                             (make-list live-count :initial-element "(map-delete live-map 0) ")))
             (cu (compile-single (read-whistler-forms source) :maps maps))
             (relocs (whistler/compiler:cu-map-relocs cu))
             (indices (mapcar #'second relocs))
             (bytes (whistler/bpf:insn-bytes (whistler/compiler:cu-insns cu))))
        (is (not (null (member 1 indices))))
        (is (not (null (member 2 indices))))
        (is (not (member 0 indices)))
        (is (= 2 (car (last indices))))
        (dolist (reloc relocs)
          (is (= #x18 (aref bytes (first reloc))))
          (is (= 1 (ash (aref bytes (1+ (first reloc))) -4))))))))

(test peephole-kfunc-relocations-retain-surviving-identities
  "Deleting an unreachable kfunc cannot replace the names of surviving calls."
  (let ((whistler/compiler:*builtin-kfuncs* whistler/compiler:*builtin-kfuncs*))
    (dolist (name '("dead-probe" "first-probe" "second-probe"))
      (whistler/compiler:register-kfunc name (substitute #\_ #\- name) nil 'whistler::u64 nil))
    (dolist (dead-count '(1 2 3))
      (let* ((source (format nil
                             "(when (= (get-prandom-u32) 1) (return 0) ~{~A~})
                              (first-probe) (second-probe) (return 2)"
                             (make-list dead-count :initial-element "(dead-probe) ")))
             (cu (compile-single (read-whistler-forms source)))
             (relocs (whistler/compiler:cu-kfunc-relocs cu))
             (bytes (whistler/bpf:insn-bytes (whistler/compiler:cu-insns cu))))
        (is (equal '("first_probe" "second_probe") (mapcar #'second relocs)))
        (dolist (reloc relocs)
          (is (= #x85 (aref bytes (first reloc))))
          (is (= whistler/bpf:+bpf-pseudo-kfunc-call+
                 (ash (aref bytes (1+ (first reloc))) -4))))))))

(test call-spanning-packet-bounds-retain-the-checked-pointer
  "Register pressure must not replace a bounded packet pointer after a helper."
  (let* ((maps '((pointer-state :type :hash :key-size 4 :value-size 8 :max-entries 3)))
         (bytes (compile-insn-bytes
                 (read-whistler-forms
                  "(let ((data u64 (ctx u32 76)) (end u64 (ctx u32 80)))
                     (when (> (+ data 34) end) (return 2))
                     (let ((row (map-lookup pointer-state 0))
                           (row1 (map-lookup pointer-state 1))
                           (row2 (map-lookup pointer-state 2)))
                       (when (or (= row 0) (= row1 0) (= row2 0)) (return 2))
                       (get-prandom-u32)
                       (when (< (ctx u32 0) 34) (return 2))
                       (return (+ (load u8 data 26) (load u64 row 0)
                                  (load u64 row1 0) (load u64 row2 0)))))")
                 :maps maps)))
    (is (= 1 (loop for offset from 0 below (length bytes) by 8
                   count (and (= (aref bytes offset) #x61)
                              (= (nth-insn-off bytes (/ offset 8)) 76)))))))

(test context-loads-are-not-rematerialized-after-helpers
  "Context reloads require explicit source bounds, even after pure helpers."
  (let ((spanning (make-hash-table)) (definitions (make-hash-table)))
    (setf (gethash 1 spanning) t)
    (dolist (offset '(0 4 76 80 140))
      (let ((load (whistler/ir::make-ir-insn :op :ctx-load :dst 2
                                          :args (list 1 (list :imm offset)) :type :u32)))
        (is-false (whistler/ir::reloadable-insn-p load spanning definitions))
        (is-false (whistler/ir::reloadable-insn-p load spanning))
        (dolist (helper '(1 2 3 5 7 26 50))
          (is-false (whistler/ir::reloadable-after-call-p
                     load (whistler/ir::make-ir-insn :op :call :args (list (list :helper helper)))
                     spanning definitions)))))))
