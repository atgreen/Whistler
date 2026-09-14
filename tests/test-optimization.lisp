(in-package #:whistler/tests)

(in-suite optimization-suite)

;;; ========== CFG simplification ==========

(test cfg-fold-true-branch
  "Constant true condition should fold to taken branch"
  ;; (> 10 5) is true → should become (return 1), 2 insns
  (is (= 2 (w-count "(if (> 10 5) (return 1) (return 0))"))))

(test cfg-fold-false-branch
  "Constant false condition should fold to else branch"
  ;; (> 3 5) is false → should become (return 0)
  (let ((bytes (w-body "(if (> 3 5) (return 99) (return 42))")))
    (is (= 42 (nth-insn-imm bytes 0))
        "Should return 42 from else branch")))

(test cfg-fold-eq-true
  "(= 5 5) should fold to true"
  (is (= 2 (w-count "(if (= 5 5) (return 1) (return 0))"))))

(test cfg-fold-eq-false
  "(= 5 6) should fold to false"
  (let ((bytes (w-body "(if (= 5 6) (return 99) (return 42))")))
    (is (= 42 (nth-insn-imm bytes 0)))))

(test cfg-fold-signed-gt
  "(s> 5 3) should fold to true"
  (is (= 2 (w-count "(if (s> 5 3) (return 1) (return 0))"))))

(test cfg-fold-let-constant-if
  "Let-bound constant in if should fold via CFG simplification"
  ;; (let ((x 10)) (if (> x 5) ...)) folds because x=10 is in const-map
  (is (= 2 (w-count "(let ((x 10))
                        (declare (type u32 x))
                        (if (> x 5) (return 1) (return 0)))"))))

;;; ========== Dead code elimination ==========

(test dce-unused-map-lookup
  "Unused map-lookup result should be eliminated by DCE"
  ;; A map-lookup whose result is never tested or used should be eliminated
  ;; Compare with a version that actually uses the result
  (let ((n-used (w-count "(let ((key 0))
                            (declare (type u32 key))
                            (let ((val (map-lookup m key)))
                              (declare (type u64 val))
                              (if val (return 1) (return 0))))"
                         :maps '((m :type :array :key-size 4
                                    :value-size 8 :max-entries 1))))
        (n-unused (w-count "(let ((key 0))
                              (declare (type u32 key))
                              (let ((val (map-lookup m key)))
                                (declare (type u64 val))
                                (return 42)))"
                           :maps '((m :type :array :key-size 4
                                      :value-size 8 :max-entries 1)))))
    (is (< n-unused n-used)
        "Unused map-lookup result should produce fewer instructions")))

(test dce-unused-computation
  "Unused arithmetic should be eliminated"
  ;; (+ x y) result is unused, x and y loads should also be dead
  (is (= 2 (w-count "(let ((x (ctx-load u32 0))
                           (y (ctx-load u32 4)))
                        (declare (type u32 x) (type u32 y))
                        (let ((z (+ x y)))
                          (declare (type u32 z))
                          (return 42)))"))))

;;; ========== Common subexpression elimination ==========

(test cse-duplicate-ctx-load
  "Two ctx-loads at the same offset should CSE to one"
  (let ((n-dup (w-count "(let ((a (ctx-load u32 0))
                               (b (ctx-load u32 0)))
                           (declare (type u32 a) (type u32 b))
                           (return (+ a b)))"))
        (n-single (w-count "(let ((a (ctx-load u32 0)))
                              (declare (type u32 a))
                              (return (+ a a)))")))
    (is (= n-dup n-single)
        "Duplicate ctx-loads should CSE to the same instruction count as single")))

(test cse-different-offsets-not-eliminated
  "ctx-loads at different offsets should NOT be CSE'd"
  (let ((n (w-count "(let ((a (ctx-load u32 0))
                           (b (ctx-load u32 4)))
                       (declare (type u32 a) (type u32 b))
                       (return (+ a b)))")))
    ;; Need at least: 2 loads + add + mov r0 + exit = 5
    (is (>= n 4) "Different offsets should produce separate loads")))

;;; ========== Store-to-load forwarding ==========

(test stlf-basic-forward
  "Store followed by load at same location should forward"
  ;; Compare: store+load vs just using the value directly
  ;; The forwarded version should have the same or fewer instructions
  (let ((n-direct (w-count "(let ((key 0))
                              (declare (type u32 key))
                              (when-let ((p u64 (map-lookup m key)))
                                (return 42))
                              (return 0))"
                           :maps '((m :type :array :key-size 4
                                      :value-size 8 :max-entries 1)))))
    ;; Just verify it compiles — the forwarding is internal
    (is (> n-direct 3) "Should compile with multiple instructions")))

;;; ========== Constant propagation ==========

(test constprop-through-let
  "Constants should propagate through let bindings"
  ;; (let ((x 42)) (return x)) → (return 42) → 2 insns
  (is (= 2 (w-count "(let ((x 42)) (declare (type u64 x)) (return x))"))))

(test constprop-arithmetic
  "Constant arithmetic should fold"
  (is (= 2 (w-count "(return (+ 10 20))"))))

(test constprop-nested-let
  "Constants should propagate through nested lets"
  (is (= 2 (w-count "(let ((x 10))
                        (declare (type u64 x))
                        (let ((y x))
                          (declare (type u64 y))
                          (return y)))"))))

;;; ========== Narrow ALU types ==========

(test narrow-and-mask
  "(logand x 0xff) should narrow to 32-bit ALU"
  (let ((bytes (w-body "(let ((x (get-prandom-u32)))
                          (declare (type u64 x))
                          (return (logand x #xff)))")))
    ;; Should use alu32 and (0x54) instead of alu64 and (0x57)
    (is (has-opcode-p bytes #x54)
        "Expected alu32 and imm for small mask")))

;;; ========== Loop-invariant code motion ==========

(test licm-dotimes-compact
  "LICM should hoist constants out of dotimes loop body"
  ;; Without LICM: mov 0 + mov N + mov 1 all in loop = more insns
  ;; With LICM: constants hoisted to preheader, loop body is tight
  (let ((n (w-count "(let ((sum 0))
                       (declare (type u64 sum))
                       (dotimes (i 10)
                         (setf sum (+ sum 1)))
                       (return sum))")))
    ;; With LICM + peephole + loop-carried phis: should be compact (<=15 insns)
    (is (<= n 15) "LICM should produce a compact dotimes loop")))

(test licm-invariant-computation
  "LICM should hoist loop-invariant arithmetic"
  ;; (+ a b) where a and b are defined outside the loop should be hoisted
  (let ((n (w-count "(let ((a (get-prandom-u32))
                           (b (get-prandom-u32))
                           (sum 0))
                       (declare (type u32 a) (type u32 b) (type u64 sum))
                       (dotimes (i 4)
                         (let ((x (+ a b)))
                           (declare (type u32 x))
                           (setf sum (+ sum x))))
                       (return sum))")))
    ;; The (+ a b) should be hoisted, loop body just does sum += x
    (is (> n 5) "Should compile with loop")))

;;; ========== Fixpoint canonicalization ==========

(test fixpoint-cascading-fold
  "Fixpoint iteration should catch cascading constant folds"
  ;; Constant prop → trivial phi elim → simplify-cfg → DCE, repeated
  (is (= 2 (w-count "(let ((x 10))
                        (declare (type u32 x))
                        (let ((y x))
                          (declare (type u32 y))
                          (if (> y 5) (return 1) (return 0))))"))))

;;; ========== Trivial phi elimination ==========

(test trivial-phi-single-pred
  "PHI with a single predecessor should be eliminated"
  ;; After CFG simplification, some blocks have one pred → trivial phi
  ;; This should compile as tight as a straight-line program
  (let ((n (w-count "(let ((x (get-prandom-u32)))
                       (declare (type u32 x))
                       (when (> x 0)
                         (return x))
                       (return 0))")))
    (is (<= n 7) "Simple when should be compact after phi elimination")))

;;; ========== Peephole: basic smoke tests ==========

(test peephole-no-redundant-exit
  "Peephole should not leave redundant exit instructions"
  (let ((bytes (w-body "(return 42)")))
    (is (= 1 (count-opcode bytes +jmp-exit+))
        "Should have exactly one exit instruction")))

(test peephole-branch-to-next
  "Branch to the immediately next instruction should be eliminated"
  ;; Simple if/else where one branch is trivial may produce this
  (let ((n (w-count "(let ((x (get-prandom-u32)))
                       (declare (type u32 x))
                       (if (> x 0)
                           (return 1)
                           (return 0)))")))
    ;; With peephole, this should be compact
    (is (<= n 8) "Simple if/else should be compact after peephole")))

(test jumps-threaded-through-trampolines
  "A program whose early-exit paths share a return value produces tail-merged
   epilogues; the final cleanup loop must thread branches through the resulting
   goto trampolines and delete them. Invariant: after peephole, no jump targets
   an unconditional jump (JA, opcode 0x05). Regression for tail-merge
   trampolines surviving the final cleanup loop."
  (let* ((bytes (w-body "(with-tcp (data data-end tcp)
                           (when (= (tcp-dst-port tcp) 80)
                             (return XDP_DROP)))
                         XDP_PASS"))
         (n (floor (length bytes) 8)))
    (flet ((opc (i) (aref bytes (* i 8)))
           (joff (i)
             (let ((raw (logior (aref bytes (+ (* i 8) 2))
                                (ash (aref bytes (+ (* i 8) 3)) 8))))
               (if (>= raw #x8000) (- raw #x10000) raw))))
      (loop for i below n
            for op = (opc i)
            ;; a jump (JMP/JMP32 class) that is not call (0x85) or exit (0x95)
            when (and (member (logand op #x07) '(#x05 #x06))
                      (/= op #x85) (/= op #x95))
            do (let ((tgt (+ i 1 (joff i))))
                 (when (and (>= tgt 0) (< tgt n))
                   (is (/= (opc tgt) #x05)
                       (format nil "insn ~d targets unconditional jump at ~d" i tgt))))))))

;;; ========== Issue #42 family: CFG folds and peephole vs shared code ==========

(test fold-return-preserves-jump-target-paths
  "peephole-fold-return must not delete a shared `mov r0, rX' that other
   paths jump to directly (issue #42 family, found by differential fuzz).
   The then-path's value used to be lost, returning x1 instead of the
   logand."
  (let ((bytes (w-body "(let ((x1 (get-prandom-u32)) (x2 (get-prandom-u32)))
                          (declare (type u64 x1 x2))
                          (return (if (= x1 x1)
                                      (logand x1 x2)
                                      (if (<= 1 x1) 1 x2))))")))
    (is (= (logand 3667470010 3411868279)
           (interpret-scalar-bpf bytes '(3667470010 3411868279))))))

(test narrow-alu-keeps-lsh-carry-bits
  "narrow-alu-types must not emit lsh32 when the shifted value can carry
   past bit 31: (u32-masked << 13) needs up to 44 bits."
  (let ((bytes (w-body "(let ((x1 (get-prandom-u32)))
                          (declare (type u64 x1))
                          (return (ash (logand x1 1258033823) 13)))")))
    (is (= (ash (logand 3715303140 1258033823) 13)
           (interpret-scalar-bpf bytes '(3715303140))))))

(test narrow-alu-keeps-mul-product-bits
  "narrow-alu-types must not emit mul32 for a product that needs more
   than 32 bits: (u32-masked * u32-masked) can need 62."
  (let ((bytes (w-body "(let ((x1 (get-prandom-u32)) (x2 (get-prandom-u32)))
                          (declare (type u64 x1 x2))
                          (return (* (logand x1 #x7fffffff) (logand x2 #x7fffffff))))")))
    (is (= (ldb (byte 64 0) (* (logand 3715303140 #x7fffffff)
                               (logand 2921185455 #x7fffffff)))
           (interpret-scalar-bpf bytes '(3715303140 2921185455))))))

(test issue-42-nested-constant-conditions
  "The issue #42 repro shape — unless/when over constant conditions —
   must compile without dangling branches and return the right value."
  (let ((bytes (w-body "(let* ((bf 0))
                          (let* ((cf 0))
                            (unless cf
                              (when (= cf 0)
                                (setf bf 1))))
                          (return bf))")))
    (is (= 1 (interpret-scalar-bpf bytes '())))))

;;; ========== fuse-mov-alu-mov must not orphan rX (whistler-jt8) ==========
;;;
;;; The pass rewrites
;;;     mov rX, rY ; alu rX, rZ ; mov rY, rX
;;; to a single `alu rY, rZ', which stops writing rX altogether. That is
;;; only sound while nothing downstream still reads rX — otherwise the
;;; read sees whatever rX held before the pattern, and the ALU result it
;;; expected is simply gone. The pass checked jump targets but never
;;; asked this, so a fall-through reader was miscompiled silently.
;;;
;;; These build instructions directly rather than compiling source: the
;;; emitter does not currently produce a shape where rX outlives the
;;; pattern, which is exactly why the hole went unnoticed. Note that the
;;; passes rewrite in place, so each case needs its own instructions.

(defun peephole-insn (code dst src &optional (imm 0))
  (whistler/bpf::insn code dst src 0 imm))

(defun mov-alu-mov-pattern ()
  "mov64 r1, r2 ; add64 r1, r3 ; mov64 r2, r1 — the fusable shape."
  (list (peephole-insn #xbf 1 2)
        (peephole-insn #x0f 1 3)
        (peephole-insn #xbf 2 1)))

(defun fuses-p (tail)
  "Does fuse-mov-alu-mov rewrite the pattern when TAIL follows it?"
  (let ((insns (append (mov-alu-mov-pattern) tail)))
    (< (length (whistler/ir::peephole-fuse-mov-alu-mov insns))
       (length insns))))

(test fuse-mov-alu-mov-still-fires-when-rx-is-dead
  ;; Guarding the pass must not disable it: rX overwritten before any
  ;; read is the case the fusion exists for.
  (is (fuses-p (list (peephole-insn #xb7 1 0 99)   ; mov64 r1, 99 — kills rX
                     (peephole-insn #x95 0 0)))
      "the pattern should still fuse when rX is overwritten afterwards"))

(test fuse-mov-alu-mov-spares-a-later-reader-of-rx
  (is (not (fuses-p (list (peephole-insn #xbf 4 1)  ; mov64 r4, r1 — reads rX
                          (peephole-insn #x95 0 0))))
      "fusing here drops the definition of r1 that the next insn reads")
  (is (not (fuses-p (list (peephole-insn #x7b 10 1) ; stx [r10+0], r1 — reads rX
                          (peephole-insn #x95 0 0))))
      "a store reading rX keeps it live just as a mov does"))

(test fuse-mov-alu-mov-is-conservative-around-control-flow
  ;; Nothing past a branch, a call, or an exit is this block's to judge,
  ;; so rX must be treated as live rather than guessed at.
  (is (not (fuses-p (list (peephole-insn #x05 0 0)   ; ja
                          (peephole-insn #x95 0 0))))
      "rX cannot be proven dead across an unconditional jump")
  (is (not (fuses-p (list (peephole-insn #x85 0 0)   ; call
                          (peephole-insn #x95 0 0))))
      "a call reads R1-R5 as arguments, so rX=r1 is live into it")
  (is (not (fuses-p (list (peephole-insn #x95 0 0))))
      "rX cannot be proven dead when the block just exits"))

;;; ========== fold-swap-add vs the back edge (whistler-c4s) ==========
;;;
;;; The fold clobbers rC, so it needs rA and rC dead past the pattern.
;;; It used to decide that with a scan that read an unconditional jump as
;;; "the path ends here, so anything unread is dead". The jump closing a
;;; loop body is a back edge: the code it returns to reads those
;;; registers again on the next turn. A loop-invariant constant
;;; materialised in the preheader was therefore destroyed by the first
;;; iteration, and every later one computed from the wreckage. The scan
;;; also gave up after 16 instructions and called the registers dead, and
;;; never asked whether another branch lands inside the range it read.

(test loop-invariant-survives-the-back-edge
  "A constant set before the loop must still be that constant on every
   turn. This returned 4C-3x instead of 3C-2x; the loop did the work of
   2^(n-1) turns rather than n."
  (let* ((x 1895525382)
         (c 467281060)
         (bytes (w-body "(let ((x3 (get-prandom-u32)))
                           (declare (type u64 x3))
                           (let ((acc x3))
                             (declare (type u64 acc))
                             (dotimes (i 3)
                               (setf acc (- 467281060 (- x3 acc))))
                             (return acc)))")))
    (is (= (ldb (byte 64 0)
                (let ((acc x))
                  (dotimes (turn 3 acc)
                    (setf acc (- c (- x acc))))))
           (interpret-scalar-bpf bytes (list x))))))

(test loop-invariant-survives-longer-loops
  "The error compounded with the trip count, so check more than one."
  (dolist (turns '(1 2 3 4 5))
    (let* ((x 1895525382)
           (c 467281060)
           (bytes (compile-insn-bytes
                   `((let ((x3 (get-prandom-u32)))
                       (declare (type u64 x3))
                       (let ((acc x3))
                         (declare (type u64 acc))
                         (dotimes (i ,turns)
                           (setf acc (- 467281060 (- x3 acc))))
                         (return acc)))))))
      (is (= (ldb (byte 64 0)
                  (let ((acc x))
                    (dotimes (turn turns acc)
                      (setf acc (- c (- x acc))))))
             (interpret-scalar-bpf bytes (list x)))
          "~D-turn loop computed the wrong value" turns))))

(defun swap-add-pattern ()
  "mov64 r1, r2 ; mov64 r2, r3 ; add64 r2, r1 — rA=r1, rB=r2, rC=r3."
  (list (peephole-insn #xbf 1 2)
        (peephole-insn #xbf 2 3)
        (peephole-insn #x0f 2 1)))

(defun folds-p (tail)
  (let ((insns (append (swap-add-pattern) tail)))
    (< (length (whistler/ir::peephole-fold-swap-add insns))
       (length insns))))

(test fold-swap-add-still-fires-when-both-are-dead
  (is (folds-p (list (peephole-insn #xb7 1 0)    ; kills rA
                     (peephole-insn #xb7 3 0)    ; kills rC
                     (peephole-insn #x95 0 0)))
      "the fold should still happen when rA and rC are both overwritten"))

(test fold-swap-add-refuses-across-a-jump
  (is (not (folds-p (list (peephole-insn #x05 0 0)   ; ja — may be a back edge
                          (peephole-insn #x95 0 0))))
      "a jump is not proof the registers are dead; it may re-enter a loop")
  (is (not (folds-p (list (peephole-insn #xb7 1 0)   ; kills rA only
                          (peephole-insn #xbf 4 3)   ; reads rC
                          (peephole-insn #x95 0 0))))
      "rC is read afterwards, and the fold clobbers it"))

;;; ========== fold-stack-addr must see every use (whistler-5b4) ==========
;;;
;;; The fold deletes `mov rA, r10; add rA, K' and rewrites the memory
;;; instructions that used rA as a base to address r10 directly. That is
;;; sound only if it finds *every* read of rA before the register dies,
;;; since the ones it does not find keep naming a register whose
;;; definition just went away. The scan used to stop after eight
;;; instructions, or at the first branch, and call the fold safe either
;;; way.

(defun stack-addr-head ()
  "mov64 r1, r10 ; add64 r1, -8 — a stack address in r1."
  (list (peephole-insn #xbf 1 10)
        (whistler/bpf::insn #x07 1 0 0 -8)))

(defun stack-addr-fold (tail)
  "Run fold-stack-addr over the pattern plus TAIL. Returns (values
   folded-p leftover-use-p)."
  (let* ((insns (append (stack-addr-head) tail))
         (out (whistler/ir::peephole-fold-stack-addr insns)))
    (values (< (length out) (length insns))
            (and (some (lambda (i) (eql 1 (whistler/ir::bpf-mem-base-reg i))) out)
                 t))))

(test fold-stack-addr-still-folds-a-plain-use
  (multiple-value-bind (folded leftover)
      (stack-addr-fold (list (peephole-insn #x7b 1 2)   ; stx [r1+0], r2
                             (peephole-insn #x95 0 0)))
    (is-true folded "a single memory-base use should still fold")
    (is-false leftover "no use of r1 should survive the fold")))

;;; The invariant below is the one that matters, and it holds whichever
;;; way the pass decides: refusing leaves the uses alone *and* their
;;; definition, which is fine. What must never happen is deleting the
;;; definition while a use of it survives.

(test fold-stack-addr-never-deletes-a-def-a-use-still-needs
  ;; Eight filler instructions push the second use beyond the horizon the
  ;; scan used to stop at.
  (multiple-value-bind (folded leftover)
      (stack-addr-fold (append (list (peephole-insn #x7b 1 2))
                               (loop repeat 7
                                     collect (whistler/bpf::insn #x07 5 0 0 1))
                               (list (peephole-insn #x79 3 1)  ; ldx r3, [r1+0]
                                     (peephole-insn #x95 0 0))))
    (is-false (and folded leftover)
              "a use past the old 8-instruction horizon was left reading a deleted r1"))
  ;; And on the far side of a jump, which the scan used to treat as proof
  ;; that nothing could still want the register.
  (multiple-value-bind (folded leftover)
      (stack-addr-fold (list (peephole-insn #x7b 1 2)
                             (peephole-insn #x05 0 0)    ; ja
                             (peephole-insn #x79 3 1)    ; ldx r3, [r1+0]
                             (peephole-insn #x95 0 0)))
    (is-false (and folded leftover)
              "a use on the far side of a jump was left reading a deleted r1")))
