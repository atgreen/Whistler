;;; -*- Mode: Lisp -*-
;;;
;;; Copyright (c) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; SPDX-License-Identifier: MIT

;;; peephole.lisp — Post-regalloc BPF instruction peephole optimizer
;;;
;;; Runs on the final BPF instruction list to eliminate redundancies:
;;;   1. Redundant mov elimination (mov rX, rX)
;;;   2. Branch inversion (jCC +1; ja +N → j!CC +N)
;;;   3. Jump-to-next elimination (ja +0)
;;;   4. Jump threading (ja → ja becomes single ja)
;;;   5. Dead code after exit/unconditional-jump elimination
;;;   6. Return value folding (mov rX, IMM; mov r0, rX; exit → mov r0, IMM; exit)

(in-package #:whistler/ir)

(defun peephole-optimize (insns)
  "Apply peephole optimizations to a list of BPF instructions.
   Returns a new list of optimized instructions."
  (let ((result insns))
    (setf result (peephole-eliminate-redundant-movs result))
    (setf result (peephole-fold-stack-addr result))
    (setf result (peephole-invert-branch result))
    (setf result (peephole-eliminate-dead-jumps result))
    (setf result (peephole-thread-jumps result))
    (setf result (peephole-eliminate-dead-jumps result))
    (setf result (peephole-fold-return result))
    (setf result (peephole-tail-merge result))
    (setf result (peephole-eliminate-dead-after-exit result))
    (setf result (peephole-store-load-elimination result))
    (setf result (peephole-load-load-forwarding result))
    (setf result (peephole-fuse-mov-alu-mov result))
    (setf result (peephole-fold-swap-add result))
    (setf result (peephole-eliminate-copy-for-alu result))
    (setf result (peephole-eliminate-redundant-imm result))
    (setf result (peephole-eliminate-redundant-mask result))
    (setf result (peephole-eliminate-dead-stores result))
    (setf result (peephole-merge-zero-stores result))
    (setf result (peephole-eliminate-dead-reg-writes result))
    (setf result (peephole-eliminate-local-dead-writes result))
    (setf result (peephole-forward-cross-reg-imm result))
    (setf result (peephole-coalesce-copy result))
    ;; Final cleanup pass — iterate branch inversion + dead-jump removal
    ;; since dead-jump removal can expose new inversion candidates
    (setf result (peephole-eliminate-redundant-movs result))
    (setf result (peephole-fold-stack-addr result))
    (loop
      (let ((prev-len (length result)))
        (setf result (peephole-invert-branch result))
        (setf result (peephole-eliminate-dead-jumps result))
        (when (= (length result) prev-len)
          (return))))
    result))

;;; ========== Instruction predicates ==========

(defun bpf-mov64-reg-p (insn)
  "Is this a mov64 reg-to-reg instruction?"
  (= (whistler/bpf:bpf-insn-code insn)
     (logior whistler/bpf:+bpf-alu64+ whistler/bpf:+bpf-mov+ whistler/bpf:+bpf-x+)))

(defun bpf-mov64-imm-p (insn)
  "Is this a mov64 immediate instruction?"
  (= (whistler/bpf:bpf-insn-code insn)
     (logior whistler/bpf:+bpf-alu64+ whistler/bpf:+bpf-mov+ whistler/bpf:+bpf-k+)))

(defun bpf-self-mov-p (insn)
  "Is this mov rX, rX?"
  (and (bpf-mov64-reg-p insn)
       (= (whistler/bpf:bpf-insn-dst insn) (whistler/bpf:bpf-insn-src insn))))

(defun bpf-unconditional-jmp-p (insn)
  "Is this JA (unconditional jump)?"
  (= (whistler/bpf:bpf-insn-code insn) #x05))

(defun bpf-conditional-jmp-p (insn)
  "Is this a conditional jump?"
  (let ((code (whistler/bpf:bpf-insn-code insn)))
    (and (= (logand code #x07) whistler/bpf:+bpf-jmp+)  ; JMP class
         (/= code #x05)       ; not JA
         (/= code #x85)       ; not CALL
         (/= code #x95))))    ; not EXIT

(defun bpf-exit-p (insn)
  "Is this an EXIT instruction?"
  (= (whistler/bpf:bpf-insn-code insn) #x95))

;;; ========== Redundant mov elimination ==========

(defun peephole-eliminate-redundant-movs (insns)
  "Remove mov rX, rX instructions."
  (let* ((vec (coerce insns 'vector))
         (len (length vec))
         (to-delete (make-hash-table)))
    (loop for i from 0 below len
          when (bpf-self-mov-p (aref vec i))
          do (setf (gethash i to-delete) t))
    (if (plusp (hash-table-count to-delete))
        (reindex-after-deletion vec to-delete)
        insns)))

;;; ========== Branch inversion ==========
;;; Pattern: jCC rX, Y, +1; ja +N → j!CC rX, Y, +N

(defun invert-jmp-code (code)
  "Invert a conditional jump opcode. Returns nil if not invertible."
  (let* ((class (logand code #x07))    ; instruction class
         (src (logand code #x08))      ; source type (K or X)
         (op (logand code #xf0)))      ; jump operation (already in position)
    (when (= class whistler/bpf:+bpf-jmp+)
      (let ((inv-op (cond
                      ((= op whistler/bpf:+bpf-jeq+)  whistler/bpf:+bpf-jne+)
                      ((= op whistler/bpf:+bpf-jne+)  whistler/bpf:+bpf-jeq+)
                      ((= op whistler/bpf:+bpf-jgt+)  whistler/bpf:+bpf-jle+)
                      ((= op whistler/bpf:+bpf-jle+)  whistler/bpf:+bpf-jgt+)
                      ((= op whistler/bpf:+bpf-jge+)  whistler/bpf:+bpf-jlt+)
                      ((= op whistler/bpf:+bpf-jlt+)  whistler/bpf:+bpf-jge+)
                      ((= op whistler/bpf:+bpf-jsgt+) whistler/bpf:+bpf-jsle+)
                      ((= op whistler/bpf:+bpf-jsle+) whistler/bpf:+bpf-jsgt+)
                      ((= op whistler/bpf:+bpf-jsge+) whistler/bpf:+bpf-jslt+)
                      ((= op whistler/bpf:+bpf-jslt+) whistler/bpf:+bpf-jsge+)
                      (t nil)))) ; JSET has no direct inverse
        (when inv-op
          (logior inv-op src class))))))

(defun peephole-invert-branch (insns)
  "Transform jCC +1; ja +N into j!CC +N."
  (let ((vec (coerce insns 'vector))
        (len (length insns))
        (to-delete (make-hash-table)))
    (loop for i from 0 below (1- len)
          for insn = (aref vec i)
          for next = (aref vec (1+ i))
          when (and (bpf-conditional-jmp-p insn)
                    (= (whistler/bpf:bpf-insn-off insn) 1)
                    (bpf-unconditional-jmp-p next))
          do (let ((inv-code (invert-jmp-code (whistler/bpf:bpf-insn-code insn))))
               (when inv-code
                 ;; Invert the condition and take the JA's target
                 ;; New offset = JA's target relative to current position
                 ;; JA target = (i+1) + 1 + ja-offset = i + 2 + ja-offset
                 ;; New offset from i = (i + 2 + ja-offset) - i - 1 = 1 + ja-offset
                 (setf (whistler/bpf:bpf-insn-code insn) inv-code)
                 (setf (whistler/bpf:bpf-insn-off insn)
                       (+ 1 (whistler/bpf:bpf-insn-off next)))
                 (setf (gethash (1+ i) to-delete) t))))
    ;; Remove deleted instructions and recompute offsets
    (if (zerop (hash-table-count to-delete))
        insns
        (reindex-after-deletion vec to-delete))))

;;; ========== Jump-to-next elimination ==========

(defun peephole-eliminate-dead-jumps (insns)
  "Remove unconditional jumps to the next instruction (ja +0).
   Preserves the last such jump if removing it would leave conditional
   branches targeting past-the-end of the instruction stream."
  (let* ((vec (coerce insns 'vector))
         (len (length vec))
         (to-delete (make-hash-table))
         ;; Find all conditional/unconditional jump targets
         (jump-targets (make-hash-table)))
    ;; Collect all jump targets
    (loop for i from 0 below len
          for insn = (aref vec i)
          when (or (bpf-unconditional-jmp-p insn)
                   (bpf-conditional-jmp-p insn))
          do (let ((target (+ i 1 (whistler/bpf:bpf-insn-off insn))))
               (setf (gethash target jump-targets) t)))
    ;; Mark goto pc+0 for deletion, but NOT if it's a jump target itself
    ;; (another branch needs to land here)
    (loop for i from 0 below len
          for insn = (aref vec i)
          when (and (bpf-unconditional-jmp-p insn)
                    (= (whistler/bpf:bpf-insn-off insn) 0)
                    (not (gethash i jump-targets)))
          do (setf (gethash i to-delete) t))
    (if (zerop (hash-table-count to-delete))
        insns
        (reindex-after-deletion vec to-delete))))

;;; ========== Common reindexing after instruction deletion ==========

(defun reindex-after-deletion (vec to-delete)
  "Remove instructions marked in TO-DELETE and recompute jump offsets."
  (let* ((len (length vec))
         (old-to-new (make-array (1+ len) :initial-element -1))
         (new-idx 0)
         (result '()))
    ;; Build old→new index mapping
    (loop for i from 0 below len
          do (if (gethash i to-delete)
                 nil
                 (progn
                   (setf (aref old-to-new i) new-idx)
                   (push (aref vec i) result)
                   (incf new-idx))))
    ;; Map for past-the-end
    (setf (aref old-to-new len) new-idx)
    ;; Back-fill deleted entries: map each deleted index to the next
    ;; non-deleted instruction's new index (so jumps targeting deleted
    ;; instructions land on the correct successor).
    (loop for i from (1- len) downto 0
          when (gethash i to-delete)
          do (setf (aref old-to-new i) (aref old-to-new (1+ i))))
    ;; Fixup jump offsets
    (let ((new-insns (nreverse result)))
      (loop for i from 0 below len
            for new-i = (aref old-to-new i)
            when (and (not (gethash i to-delete))
                      (let ((insn (aref vec i)))
                        (or (bpf-unconditional-jmp-p insn)
                            (bpf-conditional-jmp-p insn))))
            do (let* ((insn (nth new-i new-insns))
                      (old-target (+ i 1 (whistler/bpf:bpf-insn-off insn)))
                      (clamped (min (max old-target 0) len))
                      (new-target (aref old-to-new clamped)))
                 (setf (whistler/bpf:bpf-insn-off insn)
                       (- new-target new-i 1))))
      new-insns)))

;;; ========== Jump threading ==========

(defun peephole-thread-jumps (insns)
  "If a jump targets another unconditional jump, retarget to final destination."
  (let ((vec (coerce insns 'vector))
        (len (length insns)))
    (loop for i from 0 below len
          for insn = (aref vec i)
          when (or (bpf-unconditional-jmp-p insn)
                   (bpf-conditional-jmp-p insn))
          do (let* ((target (+ i 1 (whistler/bpf:bpf-insn-off insn))))
               (when (and (>= target 0) (< target len)
                          (bpf-unconditional-jmp-p (aref vec target)))
                 (let ((final-target (+ target 1 (whistler/bpf:bpf-insn-off (aref vec target)))))
                   (setf (whistler/bpf:bpf-insn-off insn)
                         (- final-target i 1))))))
    (coerce vec 'list)))

;;; ========== Return value folding ==========
;;; Pattern: mov rX, IMM; mov r0, rX; exit → mov r0, IMM; exit

(defun peephole-fold-return (insns)
  "Fold mov rX, IMM; mov r0, rX; exit into mov r0, IMM; exit."
  (let ((vec (coerce insns 'vector))
        (len (length insns))
        (to-delete (make-hash-table))
        (changed nil))
    (loop for i from 0 below (- len 2)
          for a = (aref vec i)
          for b = (aref vec (1+ i))
          for c = (aref vec (+ i 2))
          when (and (bpf-mov64-imm-p a)
                    (bpf-mov64-reg-p b)
                    (= (whistler/bpf:bpf-insn-dst b) 0) ; dst is r0
                    (= (whistler/bpf:bpf-insn-src b)
                       (whistler/bpf:bpf-insn-dst a)) ; src matches
                    (bpf-exit-p c))
          do ;; Replace: a becomes mov r0, IMM; delete b
             (setf (whistler/bpf:bpf-insn-dst a) 0)
             (setf (gethash (1+ i) to-delete) t)
             (setf changed t))
    (if changed
        (reindex-after-deletion vec to-delete)
        insns)))

;;; ========== Tail merging ==========
;;; Unify duplicate "mov r0, IMM; exit" epilogues. Keep the first
;;; occurrence for each return value, replace subsequent ones with
;;; a jump to the first.

(defun peephole-tail-merge (insns)
  "Replace duplicate mov r0, IMM; exit sequences with jumps to the last.
   Keeping the last occurrence ensures earlier duplicates jump forward,
   which is required by the BPF verifier (no backward jumps)."
  (let ((vec (coerce insns 'vector))
        (len (length insns))
        (last-exit (make-hash-table))   ; imm-value → last occurrence index
        (all-exits (make-hash-table)))  ; imm-value → list of all indices
    ;; Pass 1: find all "mov r0, IMM; exit" pairs, record last occurrence
    (loop for i from 0 below (1- len)
          for insn = (aref vec i)
          for next = (aref vec (1+ i))
          when (and (bpf-mov64-imm-p insn)
                    (= (whistler/bpf:bpf-insn-dst insn) 0) ; dst is r0
                    (bpf-exit-p next))
          do (let ((imm (whistler/bpf:bpf-insn-imm insn)))
               (push i (gethash imm all-exits))
               (setf (gethash imm last-exit) i)))
    ;; Build replacement list: all occurrences except the last jump to the last
    (let ((to-replace '()))
      (maphash (lambda (imm indices)
                 (let ((keep (gethash imm last-exit)))
                   (dolist (idx indices)
                     (unless (= idx keep)
                       (push (cons idx keep) to-replace)))))
               all-exits)
      (if to-replace
          ;; Pass 2: replace earlier duplicates with forward jumps to the last
          (let ((to-delete (make-hash-table)))
            (dolist (pair to-replace)
              (let ((dup-idx (car pair))
                    (target-idx (cdr pair)))
                ;; Replace the mov with a jump to the last occurrence
                (let ((insn (aref vec dup-idx)))
                  (setf (whistler/bpf:bpf-insn-code insn) #x05) ; JA
                  (setf (whistler/bpf:bpf-insn-dst insn) 0)
                  (setf (whistler/bpf:bpf-insn-src insn) 0)
                  (setf (whistler/bpf:bpf-insn-off insn)
                        (- target-idx dup-idx 1))
                  (setf (whistler/bpf:bpf-insn-imm insn) 0))
                ;; Mark the exit for deletion
                (setf (gethash (1+ dup-idx) to-delete) t)))
            (reindex-after-deletion vec to-delete))
          insns))))

;;; ========== Dead code after exit ==========

(defun peephole-eliminate-dead-after-exit (insns)
  "Remove unreachable code after exit or unconditional jump."
  (let* ((vec (coerce insns 'vector))
         (len (length vec))
         (targets (make-hash-table))
         (to-delete (make-hash-table)))
    ;; Mark all jump targets
    (loop for i from 0 below len
          for insn = (aref vec i)
          when (or (bpf-unconditional-jmp-p insn)
                   (bpf-conditional-jmp-p insn))
          do (let ((target (+ i 1 (whistler/bpf:bpf-insn-off insn))))
               (when (and (>= target 0) (<= target len))
                 (setf (gethash target targets) t))))
    ;; Mark dead code
    (let ((dead nil))
      (loop for i from 0 below len
            for insn = (aref vec i)
            do (cond
                 ((gethash i targets)
                  (setf dead nil))
                 (dead
                  (setf (gethash i to-delete) t)))
               (when (and (not (gethash i to-delete))
                          (or (bpf-exit-p insn)
                              (bpf-unconditional-jmp-p insn)))
                 (setf dead t))))
    (if (zerop (hash-table-count to-delete))
        insns
        (reindex-after-deletion vec to-delete))))

;;; ========== Store-load elimination ==========
;;; Pattern: stx [r10+OFF], rX; ldx rY, [r10+OFF] → stx [r10+OFF], rX; mov rY, rX
;;; This eliminates redundant stack reloads.

(defun bpf-stx-p (insn)
  "Is this a STX (store register to memory) instruction?"
  (let ((code (whistler/bpf:bpf-insn-code insn)))
    (= (logand code #x07) whistler/bpf:+bpf-stx+)))

(defun bpf-ldx-p (insn)
  "Is this a LDX (load from memory to register) instruction?"
  (let ((code (whistler/bpf:bpf-insn-code insn)))
    (= (logand code #x07) whistler/bpf:+bpf-ldx+)))

(defun bpf-stack-store-p (insn)
  "Is this a store to the stack frame (base = R10)?"
  (and (bpf-stx-p insn)
       (= (whistler/bpf:bpf-insn-dst insn) whistler/bpf:+bpf-reg-10+)))

(defun bpf-stack-load-p (insn)
  "Is this a load from the stack frame (base = R10)?"
  (and (bpf-ldx-p insn)
       (= (whistler/bpf:bpf-insn-src insn) whistler/bpf:+bpf-reg-10+)))

(defun peephole-store-load-elimination (insns)
  "Replace stx [r10+off], rX; ldx rY, [r10+off] with stx + mov rY, rX."
  (let ((vec (coerce insns 'vector))
        (len (length insns)))
    (loop for i from 0 below (1- len)
          for store = (aref vec i)
          when (bpf-stack-store-p store)
          do (let ((store-off (whistler/bpf:bpf-insn-off store))
                   (store-src (whistler/bpf:bpf-insn-src store)))
               ;; Look ahead for a load from the same offset
               (loop for j from (1+ i) below (min (+ i 8) len)
                     for insn = (aref vec j)
                     do (cond
                          ;; Found a load from the same stack slot
                          ((and (bpf-stack-load-p insn)
                                (= (whistler/bpf:bpf-insn-off insn) store-off))
                           ;; Only forward if store-src register was not modified
                           ;; between the store and this load
                           (let ((src-clobbered nil))
                             (loop for k from (1+ i) below j
                                   when (bpf-reg-written-p (aref vec k) store-src)
                                   do (setf src-clobbered t) (return))
                             (unless src-clobbered
                               (let ((load-dst (whistler/bpf:bpf-insn-dst insn)))
                                 ;; Replace ldx rY, [r10+off] → mov rY, rX
                                 (setf (whistler/bpf:bpf-insn-code insn)
                                       (logior whistler/bpf:+bpf-alu64+
                                               whistler/bpf:+bpf-mov+
                                               whistler/bpf:+bpf-x+))
                                 (setf (whistler/bpf:bpf-insn-src insn) store-src)
                                 (setf (whistler/bpf:bpf-insn-dst insn) load-dst)
                                 (setf (whistler/bpf:bpf-insn-off insn) 0)
                                 (setf (whistler/bpf:bpf-insn-imm insn) 0))))
                           (return))
                          ;; Another store to the same slot invalidates
                          ((and (bpf-stack-store-p insn)
                                (= (whistler/bpf:bpf-insn-off insn) store-off))
                           (return))
                          ;; A call clobbers caller-saved registers
                          ((= (whistler/bpf:bpf-insn-code insn) #x85)
                           (return))
                          ;; Jump means control flow diverges
                          ((or (bpf-unconditional-jmp-p insn)
                               (bpf-conditional-jmp-p insn))
                           (return))))))
    (coerce vec 'list)))

;;; ========== Stack-addr folding ==========
;;; Pattern: mov rA, r10; add rA, K; stx/ldx [rA+off], rB → stx/ldx [r10+(K+off)], rB
;;; Deletes the mov+add when rA is not used afterward (before being redefined).

(defun bpf-add64-imm-p (insn)
  "Is this ALU64 ADD immediate?"
  (= (whistler/bpf:bpf-insn-code insn)
     (logior whistler/bpf:+bpf-alu64+ whistler/bpf:+bpf-add+ whistler/bpf:+bpf-k+)))

(defun bpf-mem-base-reg (insn)
  "Return the base register of a memory instruction, or nil."
  (cond
    ((bpf-stx-p insn) (whistler/bpf:bpf-insn-dst insn))   ; stx [dst+off], src
    ((bpf-ldx-p insn) (whistler/bpf:bpf-insn-src insn))   ; ldx dst, [src+off]
    (t nil)))

(defun bpf-reg-written-p (insn reg)
  "Does this instruction write to REG?"
  (let ((code (whistler/bpf:bpf-insn-code insn)))
    (cond
      ;; ALU/MOV writes to dst
      ((or (= (logand code #x07) whistler/bpf:+bpf-alu64+)
           (= (logand code #x07) whistler/bpf:+bpf-alu+))
       (= (whistler/bpf:bpf-insn-dst insn) reg))
      ;; LDX writes to dst
      ((bpf-ldx-p insn)
       (= (whistler/bpf:bpf-insn-dst insn) reg))
      ;; LD writes to dst
      ((= (logand code #x07) whistler/bpf:+bpf-ld+)
       (= (whistler/bpf:bpf-insn-dst insn) reg))
      ;; CALL clobbers r0-r5
      ((= code #x85) (<= reg 5))
      (t nil))))

(defun bpf-reg-read-p (insn reg)
  "Does this instruction read REG (other than as a memory base that we'll fold)?"
  (let ((code (whistler/bpf:bpf-insn-code insn)))
    (cond
      ;; ALU/MOV reg-src
      ((and (or (= (logand code #x07) whistler/bpf:+bpf-alu64+)
                (= (logand code #x07) whistler/bpf:+bpf-alu+))
            (= (logand code #x08) whistler/bpf:+bpf-x+))
       (or (= (whistler/bpf:bpf-insn-src insn) reg)
           ;; ALU also reads dst for non-MOV ops
           (and (/= (logand code #xf0) whistler/bpf:+bpf-mov+)
                (= (whistler/bpf:bpf-insn-dst insn) reg))))
      ;; ALU imm reads dst (for non-MOV)
      ((and (or (= (logand code #x07) whistler/bpf:+bpf-alu64+)
                (= (logand code #x07) whistler/bpf:+bpf-alu+))
            (= (logand code #x08) whistler/bpf:+bpf-k+))
       (and (/= (logand code #xf0) whistler/bpf:+bpf-mov+)
            (= (whistler/bpf:bpf-insn-dst insn) reg)))
      ;; STX: reads src (value) and dst (base)
      ((bpf-stx-p insn)
       (or (= (whistler/bpf:bpf-insn-src insn) reg)
           (= (whistler/bpf:bpf-insn-dst insn) reg)))
      ;; LDX: reads src (base)
      ((bpf-ldx-p insn)
       (= (whistler/bpf:bpf-insn-src insn) reg))
      ;; JMP reads operands
      ((bpf-conditional-jmp-p insn)
       (or (= (whistler/bpf:bpf-insn-dst insn) reg)
           (and (= (logand code #x08) whistler/bpf:+bpf-x+)
                (= (whistler/bpf:bpf-insn-src insn) reg))))
      ;; CALL: reads r1-r5 as arguments
      ((= code #x85) (and (>= reg 1) (<= reg 5)))
      ;; EXIT reads r0
      ((bpf-exit-p insn) (zerop reg))
      (t nil))))

(defun peephole-fold-stack-addr (insns)
  "Fold mov rA, r10; add rA, K; mem [rA+off] into mem [r10+(K+off)]."
  (let ((vec (coerce insns 'vector))
        (len (length insns))
        (to-delete (make-hash-table))
        (changed nil))
    (loop for i from 0 below (- len 2)
          for mov-insn = (aref vec i)
          for add-insn = (aref vec (1+ i))
          ;; Match: mov rA, r10; add rA, K
          when (and (bpf-mov64-reg-p mov-insn)
                    (= (whistler/bpf:bpf-insn-src mov-insn) whistler/bpf:+bpf-reg-10+)
                    (bpf-add64-imm-p add-insn)
                    (= (whistler/bpf:bpf-insn-dst add-insn)
                       (whistler/bpf:bpf-insn-dst mov-insn)))
          do (let ((ra (whistler/bpf:bpf-insn-dst mov-insn))
                   (k (whistler/bpf:bpf-insn-imm add-insn))
                   (all-mem t)
                   (any-use nil))
               ;; Scan forward: check if all uses of rA are as memory base regs
               (loop for j from (+ i 2) below (min (+ i 10) len)
                     for insn = (aref vec j)
                     do (let ((base (bpf-mem-base-reg insn)))
                          (cond
                            ;; rA used as memory base — candidate for folding
                            ((and base (= base ra))
                             (setf any-use t))
                            ;; rA is read in a non-memory context → can't delete mov+add
                            ((bpf-reg-read-p insn ra)
                             (setf all-mem nil)
                             (return))
                            ;; rA is redefined → stop scanning
                            ((bpf-reg-written-p insn ra)
                             (return))
                            ;; Control flow → stop
                            ((or (bpf-unconditional-jmp-p insn)
                                 (bpf-conditional-jmp-p insn)
                                 (bpf-exit-p insn)
                                 (= (whistler/bpf:bpf-insn-code insn) #x85))
                             ;; A call reads rA if it's r1-r5
                             (when (and (= (whistler/bpf:bpf-insn-code insn) #x85)
                                        (<= ra 5))
                               (setf all-mem nil))
                             (return)))))
               ;; If all uses of rA are as memory bases, fold them and delete mov+add
               (when (and all-mem any-use)
                 (loop for j from (+ i 2) below (min (+ i 10) len)
                       for insn = (aref vec j)
                       do (let ((base (bpf-mem-base-reg insn)))
                            (cond
                              ((and base (= base ra))
                               ;; Fold: change base to r10, adjust offset
                               (if (bpf-stx-p insn)
                                   (setf (whistler/bpf:bpf-insn-dst insn) whistler/bpf:+bpf-reg-10+)
                                   (setf (whistler/bpf:bpf-insn-src insn) whistler/bpf:+bpf-reg-10+))
                               (incf (whistler/bpf:bpf-insn-off insn) k))
                              ((bpf-reg-written-p insn ra) (return))
                              ((or (bpf-unconditional-jmp-p insn)
                                   (bpf-conditional-jmp-p insn)
                                   (bpf-exit-p insn)
                                   (= (whistler/bpf:bpf-insn-code insn) #x85))
                               (return)))))
                 (setf (gethash i to-delete) t)
                 (setf (gethash (1+ i) to-delete) t)
                 (setf changed t))))
    (if changed
        (reindex-after-deletion vec to-delete)
        insns)))

;;; ========== Load-load forwarding ==========
;;; Pattern: ldx rA, [r10+off]; ...; ldx rB, [r10+off] → ldx rA + mov rB, rA
;;; When: no intervening store to same offset, rA not redefined, no calls/jumps.

(defun peephole-load-load-forwarding (insns)
  "Replace redundant stack loads from the same offset with a register copy."
  (let ((vec (coerce insns 'vector))
        (len (length insns)))
    (loop for i from 0 below len
          for load1 = (aref vec i)
          when (bpf-stack-load-p load1)
          do (let ((load-off (whistler/bpf:bpf-insn-off load1))
                   (load-dst (whistler/bpf:bpf-insn-dst load1)))
               ;; Look ahead for another load from the same stack offset
               (loop for j from (1+ i) below (min (+ i 16) len)
                     for insn = (aref vec j)
                     do (cond
                          ;; Found another load from same stack slot
                          ((and (bpf-stack-load-p insn)
                                (= (whistler/bpf:bpf-insn-off insn) load-off))
                           ;; Replace with mov rB, rA
                           (let ((load2-dst (whistler/bpf:bpf-insn-dst insn)))
                             (setf (whistler/bpf:bpf-insn-code insn)
                                   (logior whistler/bpf:+bpf-alu64+
                                           whistler/bpf:+bpf-mov+
                                           whistler/bpf:+bpf-x+))
                             (setf (whistler/bpf:bpf-insn-src insn) load-dst)
                             (setf (whistler/bpf:bpf-insn-dst insn) load2-dst)
                             (setf (whistler/bpf:bpf-insn-off insn) 0)
                             (setf (whistler/bpf:bpf-insn-imm insn) 0))
                           (return))
                          ;; Store to same offset invalidates
                          ((and (bpf-stack-store-p insn)
                                (= (whistler/bpf:bpf-insn-off insn) load-off))
                           (return))
                          ;; rA is redefined — can't forward
                          ((and (not (bpf-exit-p insn))
                                (not (bpf-unconditional-jmp-p insn))
                                (= (whistler/bpf:bpf-insn-dst insn) load-dst))
                           (return))
                          ;; Call clobbers caller-saved registers
                          ((= (whistler/bpf:bpf-insn-code insn) #x85)
                           (return))
                          ;; Jump/exit means control flow diverges
                          ((or (bpf-unconditional-jmp-p insn)
                               (bpf-conditional-jmp-p insn)
                               (bpf-exit-p insn))
                           (return))))))
    (coerce vec 'list)))

;;; ========== Fuse mov+alu+mov ==========
;;; Pattern: mov rX, rY; alu rX, rZ; mov rY, rX → alu rY, rZ
;;; Requires: rY is not modified by the alu instruction (rZ != rY),
;;; and rX is not used after the third instruction except through rY.

(defun bpf-alu64-reg-p (insn)
  "Is this a 64-bit ALU operation with register source?"
  (let ((code (whistler/bpf:bpf-insn-code insn)))
    (and (= (logand code #x07) whistler/bpf:+bpf-alu64+)
         (= (logand code #x08) whistler/bpf:+bpf-x+)
         ;; Exclude MOV (which is not really an ALU op for this purpose)
         (/= (logand code #xf0) (ash whistler/bpf:+bpf-mov+ 4)))))

(defun bpf-alu64-imm-p (insn)
  "Is this a 64-bit ALU operation with immediate source?"
  (let ((code (whistler/bpf:bpf-insn-code insn)))
    (and (= (logand code #x07) whistler/bpf:+bpf-alu64+)
         (= (logand code #x08) whistler/bpf:+bpf-k+)
         (/= (logand code #xf0) (ash whistler/bpf:+bpf-mov+ 4)))))

(defun peephole-fuse-mov-alu-mov (insns)
  "Fuse mov rX, rY; alu rX, ...; mov rY, rX into alu rY, ..."
  (let ((vec (coerce insns 'vector))
        (len (length insns))
        (to-delete (make-hash-table))
        (changed nil))
    (loop for i from 0 below (- len 2)
          for a = (aref vec i)
          for b = (aref vec (1+ i))
          for c = (aref vec (+ i 2))
          ;; Pattern: mov rX, rY; alu rX, ...; mov rY, rX
          when (and (bpf-mov64-reg-p a)
                    (or (bpf-alu64-reg-p b) (bpf-alu64-imm-p b))
                    (bpf-mov64-reg-p c)
                    ;; mov rX, rY: a.dst = rX, a.src = rY
                    ;; alu rX, ...: b.dst = rX
                    ;; mov rY, rX: c.dst = rY, c.src = rX
                    (= (whistler/bpf:bpf-insn-dst a) (whistler/bpf:bpf-insn-dst b))
                    (= (whistler/bpf:bpf-insn-dst a) (whistler/bpf:bpf-insn-src c))
                    (= (whistler/bpf:bpf-insn-src a) (whistler/bpf:bpf-insn-dst c))
                    ;; For reg ALU: rZ (src of ALU) must not be rY
                    (or (bpf-alu64-imm-p b)
                        (/= (whistler/bpf:bpf-insn-src b)
                            (whistler/bpf:bpf-insn-src a))))
          do ;; Fuse: change alu to operate on rY directly, delete mov's
             (setf (whistler/bpf:bpf-insn-dst b) (whistler/bpf:bpf-insn-src a))
             (setf (gethash i to-delete) t)
             (setf (gethash (+ i 2) to-delete) t)
             (setf changed t))
    (if changed
        (reindex-after-deletion vec to-delete)
        insns)))

;;; ========== Swap-add folding ==========
;;; Pattern: mov rA, rB; mov rB, rC; alu rB, rA → alu rC, rB; mov rB, rC
;;; Saves 1 instruction when rA and rC are dead afterward.
;;; Result: rB = rC op old_rB (same as original).

(defun peephole-fold-swap-add (insns)
  "Fold mov rA, rB; mov rB, rC; alu rB, rA into alu rC, rB; mov rB, rC."
  (let ((vec (coerce insns 'vector))
        (len (length insns))
        (to-delete (make-hash-table))
        (changed nil))
    (loop for i from 0 below (- len 2)
          for a = (aref vec i)
          for b = (aref vec (1+ i))
          for c = (aref vec (+ i 2))
          ;; Match: mov rA, rB; mov rB, rC; alu rB, rA (reg-src)
          when (and (bpf-mov64-reg-p a)
                    (bpf-mov64-reg-p b)
                    (let ((cc (whistler/bpf:bpf-insn-code c)))
                      (and (or (= (logand cc #x07) whistler/bpf:+bpf-alu64+)
                               (= (logand cc #x07) whistler/bpf:+bpf-alu+))
                           (= (logand cc #x08) whistler/bpf:+bpf-x+)))
                    ;; mov rA, rB: a.dst=rA, a.src=rB
                    ;; mov rB, rC: b.dst=rB, b.src=rC (b.dst == a.src)
                    (= (whistler/bpf:bpf-insn-dst b) (whistler/bpf:bpf-insn-src a))
                    ;; alu rB, rA: c.dst=rB, c.src=rA (c.dst==b.dst, c.src==a.dst)
                    (= (whistler/bpf:bpf-insn-dst c) (whistler/bpf:bpf-insn-dst b))
                    (= (whistler/bpf:bpf-insn-src c) (whistler/bpf:bpf-insn-dst a)))
          do (let ((ra (whistler/bpf:bpf-insn-dst a))
                   (rc (whistler/bpf:bpf-insn-src b))
                   (ra-dead t)
                   (rc-dead t))
               ;; Check if rA and rC are dead after i+2
               (loop for j from (+ i 3) below (min (+ i 19) len)
                     for insn = (aref vec j)
                     do ;; Check reads first
                        (when (bpf-reg-read-p insn ra)
                          (setf ra-dead nil))
                        (when (bpf-reg-read-p insn rc)
                          (setf rc-dead nil))
                        (when (or (not ra-dead) (not rc-dead))
                          (return))
                        ;; Path-ending: exit reads r0, goto/exit end the path
                        (when (or (bpf-exit-p insn)
                                  (bpf-unconditional-jmp-p insn))
                          ;; Path ends — unread registers are dead here
                          (return))
                        ;; Conditional jump: conservative for branch target
                        (when (bpf-conditional-jmp-p insn)
                          (setf ra-dead nil rc-dead nil)
                          (return))
                        ;; Track redefinitions
                        (when (bpf-reg-written-p insn ra)
                          (setf ra-dead t))
                        (when (bpf-reg-written-p insn rc)
                          (setf rc-dead t)))
               (when (and ra-dead rc-dead)
                 ;; Transform: delete insn i, change i+1 to alu rC, rB, change i+2 to mov rB, rC
                 (let ((rb (whistler/bpf:bpf-insn-src a)))
                   ;; insn i+1: was mov rB, rC → becomes alu rC, rB
                   (setf (whistler/bpf:bpf-insn-code b) (whistler/bpf:bpf-insn-code c))
                   (setf (whistler/bpf:bpf-insn-dst b) rc)
                   (setf (whistler/bpf:bpf-insn-src b) rb)
                   (setf (whistler/bpf:bpf-insn-imm b) (whistler/bpf:bpf-insn-imm c))
                   ;; insn i+2: was alu rB, rA → becomes mov rB, rC
                   (setf (whistler/bpf:bpf-insn-code c)
                         (logior whistler/bpf:+bpf-alu64+ whistler/bpf:+bpf-mov+ whistler/bpf:+bpf-x+))
                   (setf (whistler/bpf:bpf-insn-dst c) rb)
                   (setf (whistler/bpf:bpf-insn-src c) rc)
                   (setf (whistler/bpf:bpf-insn-imm c) 0)
                   (setf (whistler/bpf:bpf-insn-off c) 0)
                   ;; Delete the original mov rA, rB
                   (setf (gethash i to-delete) t)
                   (setf changed t)))))
    (if changed
        (reindex-after-deletion vec to-delete)
        insns)))

;;; ========== Copy-for-ALU elimination ==========
;;; Pattern: mov rA, rB; alu rC, rA → alu rC, rB (delete the mov)
;;; when rA is dead after the ALU instruction.

(defun peephole-eliminate-copy-for-alu (insns)
  "Eliminate mov rA, rB; alu rC, rA when rA is dead after the ALU."
  (let ((vec (coerce insns 'vector))
        (len (length insns))
        (to-delete (make-hash-table))
        (changed nil))
    (loop for i from 0 below (1- len)
          for mov = (aref vec i)
          for alu = (aref vec (1+ i))
          ;; Match: mov rA, rB (reg); alu rC, rA (reg-src)
          when (and (bpf-mov64-reg-p mov)
                    (let ((c (whistler/bpf:bpf-insn-code alu)))
                      (and (or (= (logand c #x07) whistler/bpf:+bpf-alu64+)
                               (= (logand c #x07) whistler/bpf:+bpf-alu+))
                           (= (logand c #x08) whistler/bpf:+bpf-x+)))
                    ;; ALU src == mov dst (rA)
                    (= (whistler/bpf:bpf-insn-src alu)
                       (whistler/bpf:bpf-insn-dst mov))
                    ;; rA != ALU dst (rC) — mov target is only used as src
                    (/= (whistler/bpf:bpf-insn-dst mov)
                        (whistler/bpf:bpf-insn-dst alu)))
          do (let ((ra (whistler/bpf:bpf-insn-dst mov))
                   (rb (whistler/bpf:bpf-insn-src mov))
                   (dead t))
               ;; Check if rA is dead after the ALU instruction
               (loop for j from (+ i 2) below (min (+ i 18) len)
                     for insn = (aref vec j)
                     do (cond
                          ;; rA is read → not dead
                          ((bpf-reg-read-p insn ra)
                           (setf dead nil)
                           (return))
                          ;; rA is redefined → dead
                          ((bpf-reg-written-p insn ra)
                           (return))
                          ;; Unconditional jump or exit ends the path — rA is dead
                          ((or (bpf-unconditional-jmp-p insn)
                               (bpf-exit-p insn))
                           (return))
                          ;; Conditional jump: conservative
                          ((bpf-conditional-jmp-p insn)
                           (setf dead nil)
                           (return))))
               (when dead
                 ;; Replace ALU src with rB, delete the mov
                 (setf (whistler/bpf:bpf-insn-src alu) rb)
                 (setf (gethash i to-delete) t)
                 (setf changed t))))
    (if changed
        (reindex-after-deletion vec to-delete)
        insns)))

;;; ========== Redundant immediate elimination ==========
;;; Pattern: mov rX, IMM; ...; mov rX, IMM → delete the second mov
;;; when no intervening instruction writes to rX and no jump targets
;;; or control flow changes occur between the two.

(defun peephole-eliminate-redundant-imm (insns)
  "Remove mov rX, IMM instructions where rX already holds that value."
  (let* ((vec (coerce insns 'vector))
         (len (length vec))
         (targets (make-hash-table))
         (to-delete (make-hash-table))
         ;; Track known register values: reg → imm (or nil if unknown)
         (known (make-array 11 :initial-element nil)))
    ;; Mark all jump targets (we must invalidate knowledge at targets)
    (loop for i from 0 below len
          for insn = (aref vec i)
          when (or (bpf-unconditional-jmp-p insn)
                   (bpf-conditional-jmp-p insn))
          do (let ((target (+ i 1 (whistler/bpf:bpf-insn-off insn))))
               (when (and (>= target 0) (<= target len))
                 (setf (gethash target targets) t))))
    ;; Walk instructions tracking known immediate values
    (loop for i from 0 below len
          for insn = (aref vec i)
          do ;; At jump targets, invalidate all knowledge
             (when (gethash i targets)
               (fill known nil))
             (cond
               ;; mov64 rX, IMM — check if redundant
               ((bpf-mov64-imm-p insn)
                (let ((dst (whistler/bpf:bpf-insn-dst insn))
                      (imm (whistler/bpf:bpf-insn-imm insn)))
                  (if (eql (aref known dst) imm)
                      ;; Already holds this value — delete
                      (setf (gethash i to-delete) t)
                      ;; Record the new value
                      (setf (aref known dst) imm))))
               ;; mov32 rX, IMM — similar
               ((let ((code (whistler/bpf:bpf-insn-code insn)))
                  (= code (logior whistler/bpf:+bpf-alu+ whistler/bpf:+bpf-mov+
                                  whistler/bpf:+bpf-k+)))
                (let ((dst (whistler/bpf:bpf-insn-dst insn))
                      (imm (whistler/bpf:bpf-insn-imm insn)))
                  (if (eql (aref known dst) imm)
                      (setf (gethash i to-delete) t)
                      (setf (aref known dst) imm))))
               (t
                ;; Any instruction that writes a register invalidates its known value
                (unless (bpf-exit-p insn)
                  (let ((dst (whistler/bpf:bpf-insn-dst insn)))
                    (when (and dst (< dst 11))
                      ;; Instructions that write to dst
                      (let ((code (whistler/bpf:bpf-insn-code insn)))
                        (when (or (= (logand code #x07) whistler/bpf:+bpf-alu64+)
                                  (= (logand code #x07) whistler/bpf:+bpf-alu+)
                                  (bpf-ldx-p insn)
                                  (= (logand code #x07) whistler/bpf:+bpf-ld+))
                          (setf (aref known dst) nil))))))
                ;; CALL clobbers r0-r5
                (when (= (whistler/bpf:bpf-insn-code insn) #x85)
                  (loop for r from 0 to 5 do (setf (aref known r) nil)))
                ;; Jumps: invalidate all (conservative for backward jumps)
                (when (or (bpf-unconditional-jmp-p insn)
                          (bpf-conditional-jmp-p insn))
                  (fill known nil)))))
    (if (plusp (hash-table-count to-delete))
        (reindex-after-deletion vec to-delete)
        insns)))

;;; ========== Redundant mask elimination ==========
;;; Pattern: and rX, 0xffff after an operation that already produces a
;;; value fitting in 16 bits (e.g., rsh rX, 16 or ldx_h rX, [...]).
;;; Tracks known bit-widths through the instruction stream.

(defun bpf-and32-imm-p (insn)
  "Is this ALU32 AND immediate?"
  (= (whistler/bpf:bpf-insn-code insn)
     (logior whistler/bpf:+bpf-alu+ whistler/bpf:+bpf-and+ whistler/bpf:+bpf-k+)))

(defun bpf-and64-imm-p (insn)
  "Is this ALU64 AND immediate?"
  (= (whistler/bpf:bpf-insn-code insn)
     (logior whistler/bpf:+bpf-alu64+ whistler/bpf:+bpf-and+ whistler/bpf:+bpf-k+)))

(defun peephole-eliminate-redundant-mask (insns)
  "Remove and rX, MASK when rX is already known to fit within MASK."
  (let* ((vec (coerce insns 'vector))
         (len (length vec))
         (targets (make-hash-table))
         (to-delete (make-hash-table))
         ;; Track known max bit-width per register (nil = unknown/64-bit)
         (widths (make-array 11 :initial-element nil)))
    ;; Mark jump targets
    (loop for i from 0 below len
          for insn = (aref vec i)
          when (or (bpf-unconditional-jmp-p insn)
                   (bpf-conditional-jmp-p insn))
          do (let ((target (+ i 1 (whistler/bpf:bpf-insn-off insn))))
               (when (and (>= target 0) (<= target len))
                 (setf (gethash target targets) t))))
    ;; Walk instructions
    (loop for i from 0 below len
          for insn = (aref vec i)
          do (when (gethash i targets)
               (fill widths nil))
             (let ((code (whistler/bpf:bpf-insn-code insn))
                   (dst (whistler/bpf:bpf-insn-dst insn))
                   (imm (whistler/bpf:bpf-insn-imm insn)))
               (cond
                 ;; AND rX, MASK — check if redundant, then update width
                 ((or (bpf-and32-imm-p insn) (bpf-and64-imm-p insn))
                  (let* ((known-w (aref widths dst))
                         ;; Compute effective mask width as bit-length of the mask.
                         ;; 0x0f→4, 0xff→8, 0xffff→16, 0xffffffff→32
                         (mask-w (if (zerop imm) 0 (integer-length imm))))
                    ;; AND is a no-op only if register width < mask width
                    ;; (all possible values already fit within the mask)
                    (if (and known-w (< known-w mask-w))
                        (setf (gethash i to-delete) t)
                        ;; Update width: AND narrows to mask width
                        (setf (aref widths dst) mask-w))))

                 ;; RSH rX, N — narrows the value
                 ;; ALU32 RSH caps input at 32 bits; ALU64 uses full 64
                 ((and (or (= code (logior whistler/bpf:+bpf-alu+
                                           whistler/bpf:+bpf-rsh+ whistler/bpf:+bpf-k+))
                           (= code (logior whistler/bpf:+bpf-alu64+
                                           whistler/bpf:+bpf-rsh+ whistler/bpf:+bpf-k+)))
                       (plusp imm))
                  (let* ((is-alu32 (= (logand code #x07) whistler/bpf:+bpf-alu+))
                         (max-w (if is-alu32 32 64))
                         (input-w (min (or (aref widths dst) max-w) max-w)))
                    (setf (aref widths dst)
                          (max 1 (- input-w imm)))))

                 ;; LDX with specific sizes
                 ((bpf-ldx-p insn)
                  (let ((size (logand code #x18)))
                    (setf (aref widths dst)
                          (cond ((= size whistler/bpf:+bpf-b+) 8)
                                ((= size whistler/bpf:+bpf-h+) 16)
                                ((= size whistler/bpf:+bpf-w+) 32)
                                (t nil)))))

                 ;; MOV32 imm — result is 32-bit
                 ((let ((c (whistler/bpf:bpf-insn-code insn)))
                    (= c (logior whistler/bpf:+bpf-alu+ whistler/bpf:+bpf-mov+
                                 whistler/bpf:+bpf-k+)))
                  (let ((v (logand imm #xffffffff)))
                    (setf (aref widths dst)
                          (cond ((<= v #xff) 8)
                                ((<= v #xffff) 16)
                                (t 32)))))

                 ;; MOV64 imm — track width
                 ((bpf-mov64-imm-p insn)
                  (let ((v (if (< imm 0) (lognot imm) imm)))
                    (setf (aref widths dst)
                          (cond ((<= v #xff) 8)
                                ((<= v #xffff) 16)
                                ((<= v #xffffffff) 32)
                                (t nil)))))

                 ;; XOR rX, IMM — preserves width if both operands fit
                 ((or (= code (logior whistler/bpf:+bpf-alu+
                                      whistler/bpf:+bpf-xor+ whistler/bpf:+bpf-k+))
                      (= code (logior whistler/bpf:+bpf-alu64+
                                      whistler/bpf:+bpf-xor+ whistler/bpf:+bpf-k+)))
                  (let ((input-w (aref widths dst))
                        (imm-w (cond ((<= imm #xff) 8)
                                     ((<= imm #xffff) 16)
                                     ((<= imm #xffffffff) 32)
                                     (t 64))))
                    (if (and input-w (<= input-w imm-w))
                        nil  ; width unchanged
                        (setf (aref widths dst) (max (or input-w 64) imm-w)))))

                 ;; MOD rX, rY — result width <= divisor width
                 ((or (= code (logior whistler/bpf:+bpf-alu64+
                                      whistler/bpf:+bpf-mod+ whistler/bpf:+bpf-x+))
                      (= code (logior whistler/bpf:+bpf-alu+
                                      whistler/bpf:+bpf-mod+ whistler/bpf:+bpf-x+)))
                  (let ((src (whistler/bpf:bpf-insn-src insn)))
                    (setf (aref widths dst)
                          (or (and (< src 11) (aref widths src))
                              (if (= (logand code #x07) whistler/bpf:+bpf-alu+) 32 nil)))))

                 ;; MOD rX, IMM — result width <= width of immediate
                 ((or (= code (logior whistler/bpf:+bpf-alu64+
                                      whistler/bpf:+bpf-mod+ whistler/bpf:+bpf-k+))
                      (= code (logior whistler/bpf:+bpf-alu+
                                      whistler/bpf:+bpf-mod+ whistler/bpf:+bpf-k+)))
                  (let ((v (if (< imm 0) (lognot imm) imm)))
                    (setf (aref widths dst)
                          (cond ((<= v #xff) 8)
                                ((<= v #xffff) 16)
                                ((<= v #xffffffff) 32)
                                (t nil)))))

                 ;; MOV64 reg — propagate width from source
                 ((bpf-mov64-reg-p insn)
                  (let ((src (whistler/bpf:bpf-insn-src insn)))
                    (setf (aref widths dst)
                          (when (< src 11) (aref widths src)))))

                 ;; Other writes to dst: reset width
                 (t
                  (when (and dst (< dst 11)
                             (not (bpf-exit-p insn))
                             (not (bpf-stx-p insn)))
                    (let ((c (whistler/bpf:bpf-insn-code insn)))
                      (when (or (= (logand c #x07) whistler/bpf:+bpf-alu64+)
                                (= (logand c #x07) whistler/bpf:+bpf-alu+)
                                (= (logand c #x07) whistler/bpf:+bpf-ld+))
                        (setf (aref widths dst) nil))))))

               ;; CALL clobbers r0-r5
               (when (= code #x85)
                 (loop for r from 0 to 5 do (setf (aref widths r) nil)))))
    (if (plusp (hash-table-count to-delete))
        (reindex-after-deletion vec to-delete)
        insns)))

;;; ========== Dead store elimination ==========
;;; Remove stack stores whose entire byte range is overwritten by subsequent
;;; stores before being read.

(defun bpf-insn-mem-size (insn)
  "Return the byte size of a memory instruction's access."
  (let ((size-bits (logand (whistler/bpf:bpf-insn-code insn) #x18)))
    (cond ((= size-bits whistler/bpf:+bpf-b+)  1)
          ((= size-bits whistler/bpf:+bpf-h+)  2)
          ((= size-bits whistler/bpf:+bpf-w+)  4)
          ((= size-bits whistler/bpf:+bpf-dw+) 8)
          (t 0))))

(defun peephole-eliminate-dead-stores (insns)
  "Remove stack stores whose bytes are fully overwritten before being read."
  (let* ((vec (coerce insns 'vector))
         (len (length vec))
         (to-delete (make-hash-table)))
    (loop for i from 0 below len
          for store = (aref vec i)
          when (bpf-stack-store-p store)
          do (let* ((off (whistler/bpf:bpf-insn-off store))
                    (size (bpf-insn-mem-size store))
                    (uncovered (1- (ash 1 size)))
                    (dead nil))
               ;; Scan forward
               (loop for j from (1+ i) below (min (+ i 16) len)
                     for insn = (aref vec j)
                     do (cond
                          ;; Another store to overlapping stack region
                          ((bpf-stack-store-p insn)
                           (let* ((s-off (whistler/bpf:bpf-insn-off insn))
                                  (s-size (bpf-insn-mem-size insn))
                                  (rel-start (- s-off off))
                                  (rel-end (+ rel-start s-size)))
                             (when (and (< rel-start size) (plusp rel-end))
                               (loop for b from (max 0 rel-start)
                                     below (min size rel-end)
                                     do (setf uncovered
                                              (logand uncovered
                                                      (lognot (ash 1 b)))))
                               (when (zerop uncovered)
                                 (setf dead t)
                                 (return)))))
                          ;; Load from overlapping stack region — store is live
                          ((bpf-stack-load-p insn)
                           (let* ((l-off (whistler/bpf:bpf-insn-off insn))
                                  (l-size (bpf-insn-mem-size insn))
                                  (l-end (+ l-off l-size)))
                             (when (and (< l-off (+ off size))
                                        (> l-end off))
                               (return))))
                          ;; Call/jump/exit: stop scanning
                          ((or (= (whistler/bpf:bpf-insn-code insn) #x85)
                               (bpf-unconditional-jmp-p insn)
                               (bpf-conditional-jmp-p insn)
                               (bpf-exit-p insn))
                           (return))))
               (when dead
                 (setf (gethash i to-delete) t))))
    (if (plusp (hash-table-count to-delete))
        (reindex-after-deletion vec to-delete)
        insns)))

;;; ========== Dead register write elimination ==========
;;; Remove mov rX, IMM/reg where rX is never read anywhere in the program.

(defun peephole-eliminate-dead-reg-writes (insns)
  "Remove mov rX, IMM/reg when the register is never read in the program."
  (let* ((vec (coerce insns 'vector))
         (len (length vec))
         ;; Find all registers that are read by any instruction
         (read-regs (make-array 11 :initial-element nil))
         (to-delete (make-hash-table)))
    ;; Pass 1: mark all registers that are read
    (loop for i from 0 below len
          for insn = (aref vec i)
          do (loop for r from 0 to 10
                   when (bpf-reg-read-p insn r)
                   do (setf (aref read-regs r) t)))
    ;; Pass 2: delete mov instructions that write to never-read registers
    (loop for i from 0 below len
          for insn = (aref vec i)
          when (or (bpf-mov64-imm-p insn) (bpf-mov64-reg-p insn))
          do (let ((dst (whistler/bpf:bpf-insn-dst insn)))
               (when (and (< dst 11) (not (aref read-regs dst)))
                 (setf (gethash i to-delete) t))))
    (if (plusp (hash-table-count to-delete))
        (reindex-after-deletion vec to-delete)
        insns)))

;;; ========== Store merging ==========
;;; Merge st-mem u64 [R10+off] = 0 followed by st-mem u32 [R10+off] = N
;;; into st-mem u64 [R10+off] = N (little-endian: N in low 32 bits, 0 in high).

(defun bpf-st-imm-p (insn)
  "Is this a ST (immediate store to memory) instruction?"
  (let ((code (whistler/bpf:bpf-insn-code insn)))
    (= (logand code #x07) whistler/bpf:+bpf-st+)))

(defun bpf-st-imm-stack-p (insn)
  "Is this a st-mem to the stack frame (base = R10)?"
  (and (bpf-st-imm-p insn)
       (= (whistler/bpf:bpf-insn-dst insn) whistler/bpf:+bpf-reg-10+)))

(defun peephole-merge-zero-stores (insns)
  "Merge zero-init u64 store + constant u32 overwrite at same offset into one u64 store."
  (let* ((vec (coerce insns 'vector))
         (len (length vec))
         (to-delete (make-hash-table))
         (to-modify (make-hash-table)))
    (loop for i from 0 below len
          for store = (aref vec i)
          ;; Look for st-mem u64 [R10+off] = 0
          when (and (bpf-st-imm-stack-p store)
                    (= (whistler/bpf:bpf-insn-code store) #x7a)  ; st-mem u64
                    (= (whistler/bpf:bpf-insn-imm store) 0))
          do (let ((off (whistler/bpf:bpf-insn-off store)))
               ;; Scan forward for st-mem u32 [R10+off] = N
               (block scan
                 (loop for j from (1+ i) below (min (+ i 8) len)
                       for next = (aref vec j)
                       do (cond
                            ;; Found: st-mem u32 [R10+off] = N at same offset
                            ((and (bpf-st-imm-stack-p next)
                                  (= (whistler/bpf:bpf-insn-code next) #x62)  ; st-mem u32
                                  (= (whistler/bpf:bpf-insn-off next) off))
                             ;; Merge: change the u64 store to use the u32's value
                             ;; and delete the u32 store
                             (setf (gethash i to-modify)
                                   (whistler/bpf:bpf-insn-imm next))
                             (setf (gethash j to-delete) t)
                             (return-from scan))
                            ;; Load/call/jump from this region — stop
                            ((or (and (bpf-stack-load-p next)
                                      (let ((l-off (whistler/bpf:bpf-insn-off next)))
                                        (and (>= l-off off) (< l-off (+ off 8)))))
                                 (= (whistler/bpf:bpf-insn-code next) #x85)
                                 (bpf-unconditional-jmp-p next)
                                 (bpf-conditional-jmp-p next)
                                 (bpf-exit-p next))
                             (return-from scan)))))))
    (if (or (plusp (hash-table-count to-delete))
            (plusp (hash-table-count to-modify)))
        (progn
          ;; Apply modifications
          (maphash (lambda (i new-imm)
                     (let ((insn (aref vec i)))
                       (setf (aref vec i)
                             (whistler/bpf:insn
                              (whistler/bpf:bpf-insn-code insn)
                              (whistler/bpf:bpf-insn-dst insn)
                              (whistler/bpf:bpf-insn-src insn)
                              (whistler/bpf:bpf-insn-off insn)
                              new-imm))))
                   to-modify)
          (if (plusp (hash-table-count to-delete))
              (reindex-after-deletion vec to-delete)
              (coerce vec 'list)))
        insns)))

;;; ========== Local dead register write elimination ==========
;;; Remove mov rX, IMM when rX is overwritten before being read
;;; within the same basic block.

(defun peephole-eliminate-local-dead-writes (insns)
  "Remove mov rX, IMM/reg when rX is overwritten before being read."
  (let* ((vec (coerce insns 'vector))
         (len (length vec))
         (to-delete (make-hash-table)))
    (loop for i from 0 below len
          for insn = (aref vec i)
          when (or (bpf-mov64-imm-p insn) (bpf-mov64-reg-p insn))
          do (let ((dst (whistler/bpf:bpf-insn-dst insn)))
               ;; Scan forward: is dst read before being written?
               (block scan
                 (loop for j from (1+ i) below (min (+ i 20) len)
                       for next = (aref vec j)
                       do (cond
                            ;; dst is read — mov is live
                            ((bpf-reg-read-p next dst)
                             (return-from scan))
                            ;; dst is written — mov is dead
                            ((bpf-reg-written-p next dst)
                             (setf (gethash i to-delete) t)
                             (return-from scan))
                            ;; call/jump/exit — stop (dst might be live)
                            ((or (= (whistler/bpf:bpf-insn-code next) #x85)
                                 (bpf-unconditional-jmp-p next)
                                 (bpf-conditional-jmp-p next)
                                 (bpf-exit-p next))
                             (return-from scan)))))))
    (if (plusp (hash-table-count to-delete))
        (reindex-after-deletion vec to-delete)
        insns)))

;;; ========== Cross-register immediate forwarding ==========
;;; When mov rB, IMM and some other register rA already holds IMM,
;;; replace uses of rB with rA in subsequent instructions and delete the mov.

(defun peephole-forward-cross-reg-imm (insns)
  "Forward immediate values across registers to eliminate redundant movs."
  (let* ((vec (coerce insns 'vector))
         (len (length vec))
         (targets (make-hash-table))
         (to-delete (make-hash-table))
         ;; Track known register values: reg → imm (or nil if unknown)
         (known (make-array 11 :initial-element nil))
         (changed nil))
    ;; Mark all jump targets
    (loop for i from 0 below len
          for insn = (aref vec i)
          when (or (bpf-unconditional-jmp-p insn)
                   (bpf-conditional-jmp-p insn))
          do (let ((target (+ i 1 (whistler/bpf:bpf-insn-off insn))))
               (when (and (>= target 0) (<= target len))
                 (setf (gethash target targets) t))))
    ;; Walk instructions
    (loop for i from 0 below len
          for insn = (aref vec i)
          do (when (gethash i targets)
               (fill known nil))
             (cond
               ;; mov64 rB, IMM — check if another reg already holds this value
               ((bpf-mov64-imm-p insn)
                (let* ((dst (whistler/bpf:bpf-insn-dst insn))
                       (imm (whistler/bpf:bpf-insn-imm insn))
                       (donor (loop for r from 0 below 11
                                    when (and (/= r dst) (eql (aref known r) imm))
                                    return r)))
                  (when donor
                    ;; Scan forward: replace src-field uses of dst with donor
                    (let ((forwarded nil)
                          (can-delete t))
                      (loop for j from (1+ i) below len
                            for next = (aref vec j)
                            do ;; Stop at jump targets (merge points)
                               (when (gethash j targets)
                                 (setf can-delete nil)
                                 (return))
                               ;; If donor is overwritten, stop
                               (when (bpf-reg-written-p next donor)
                                 (return))
                               ;; If dst is written by this instruction, stop
                               (when (bpf-reg-written-p next dst)
                                 ;; If dst is also READ here, we can't delete the mov
                                 (when (bpf-reg-read-p next dst)
                                   (setf can-delete nil))
                                 (return))
                               ;; Replace src-field reads of dst with donor
                               (let ((replaced nil))
                                 ;; STX: src is the value being stored
                                 (when (and (bpf-stx-p next)
                                            (= (whistler/bpf:bpf-insn-src next) dst))
                                   (setf (whistler/bpf:bpf-insn-src next) donor)
                                   (setf replaced t))
                                 ;; ALU reg ops: src is second operand
                                 (when (and (not replaced)
                                            (let ((c (whistler/bpf:bpf-insn-code next)))
                                              (and (or (= (logand c #x07) whistler/bpf:+bpf-alu64+)
                                                       (= (logand c #x07) whistler/bpf:+bpf-alu+))
                                                   (= (logand c #x08) whistler/bpf:+bpf-x+)))
                                            (= (whistler/bpf:bpf-insn-src next) dst))
                                   (setf (whistler/bpf:bpf-insn-src next) donor)
                                   (setf replaced t))
                                 (when replaced (setf forwarded t))
                                 ;; If dst is still read in some other way, bail
                                 (when (and (not replaced) (bpf-reg-read-p next dst))
                                   (setf can-delete nil)
                                   (return)))
                               ;; Stop at control flow
                               (when (or (bpf-unconditional-jmp-p next)
                                         (bpf-conditional-jmp-p next)
                                         (bpf-exit-p next)
                                         (= (whistler/bpf:bpf-insn-code next) #x85))
                                 (setf can-delete nil)
                                 (return)))
                      (when (and forwarded can-delete)
                        (setf (gethash i to-delete) t)
                        (setf changed t))))
                  ;; Record the value
                  (setf (aref known dst) imm)))
               ;; mov32 rX, IMM
               ((let ((code (whistler/bpf:bpf-insn-code insn)))
                  (= code (logior whistler/bpf:+bpf-alu+ whistler/bpf:+bpf-mov+
                                  whistler/bpf:+bpf-k+)))
                (setf (aref known (whistler/bpf:bpf-insn-dst insn))
                      (whistler/bpf:bpf-insn-imm insn)))
               (t
                ;; Any instruction that writes a register invalidates its known value
                (unless (bpf-exit-p insn)
                  (let ((dst (whistler/bpf:bpf-insn-dst insn)))
                    (when (and dst (< dst 11))
                      (let ((code (whistler/bpf:bpf-insn-code insn)))
                        (when (or (= (logand code #x07) whistler/bpf:+bpf-alu64+)
                                  (= (logand code #x07) whistler/bpf:+bpf-alu+)
                                  (bpf-ldx-p insn)
                                  (= (logand code #x07) whistler/bpf:+bpf-ld+))
                          (setf (aref known dst) nil))))))
                ;; CALL clobbers r0-r5
                (when (= (whistler/bpf:bpf-insn-code insn) #x85)
                  (loop for r from 0 to 5 do (setf (aref known r) nil)))
                ;; Jumps: invalidate all
                (when (or (bpf-unconditional-jmp-p insn)
                          (bpf-conditional-jmp-p insn))
                  (fill known nil)))))
    (if changed
        (reindex-after-deletion vec to-delete)
        insns)))

;;; ========== Copy coalescing ==========
;;; When mov rA, rB and rB is dead after the mov, rename rA→rB in subsequent
;;; straight-line code and delete the mov.

(defun coalesce-regs-dead-at (vec len start ra rb)
  "Check if registers RA and RB are both dead from position START onward.
   Uses a limited forward scan, following unconditional jumps."
  (let ((ra-dead nil)
        (rb-dead nil)
        (pos start)
        (budget 20))
    (block scan
      (loop while (and (>= pos 0) (< pos len) (plusp budget))
            do (let* ((insn (aref vec pos))
                      (followed nil))
                 (decf budget)
                 ;; Check reads before writes
                 (when (and (not ra-dead) (bpf-reg-read-p insn ra))
                   (return-from scan nil))
                 (when (and (not rb-dead) (bpf-reg-read-p insn rb))
                   (return-from scan nil))
                 ;; Track writes
                 (when (bpf-reg-written-p insn ra) (setf ra-dead t))
                 (when (bpf-reg-written-p insn rb) (setf rb-dead t))
                 (when (and ra-dead rb-dead)
                   (return-from scan t))
                 ;; At exit: only r0 is live
                 (when (bpf-exit-p insn)
                   (return-from scan
                     (and (or ra-dead (/= ra 0))
                          (or rb-dead (/= rb 0)))))
                 ;; Unconditional jump: follow to target
                 (when (bpf-unconditional-jmp-p insn)
                   (setf pos (+ pos 1 (whistler/bpf:bpf-insn-off insn)))
                   (setf followed t))
                 ;; Conditional jump or call: conservative bail
                 (when (or (bpf-conditional-jmp-p insn)
                           (= (whistler/bpf:bpf-insn-code insn) #x85))
                   (return-from scan nil))
                 (unless followed (incf pos))))
      nil)))

(defun peephole-coalesce-copy (insns)
  "Eliminate register-to-register copies by renaming when the source is dead."
  (let* ((vec (coerce insns 'vector))
         (len (length vec))
         (targets (make-hash-table))
         (to-delete (make-hash-table))
         (changed nil))
    ;; Mark all jump targets
    (loop for i from 0 below len
          for insn = (aref vec i)
          when (or (bpf-unconditional-jmp-p insn)
                   (bpf-conditional-jmp-p insn))
          do (let ((target (+ i 1 (whistler/bpf:bpf-insn-off insn))))
               (when (and (>= target 0) (<= target len))
                 (setf (gethash target targets) t))))
    ;; Look for mov rA, rB candidates
    (loop for i from 0 below len
          for insn = (aref vec i)
          when (and (bpf-mov64-reg-p insn)
                    (not (bpf-self-mov-p insn))
                    (not (gethash i to-delete)))
          do (let ((ra (whistler/bpf:bpf-insn-dst insn))
                   (rb (whistler/bpf:bpf-insn-src insn))
                   (safe t)
                   (end-j nil))
               ;; Phase 1: Check if coalescing is safe
               ;; rB must not appear independently in any instruction in the window
               (block check
                 (loop for j from (1+ i) below len
                       for next = (aref vec j)
                       do ;; At jump target: stop rename window, check liveness
                          (when (gethash j targets)
                            ;; rA and rB must be dead from here forward
                            (setf end-j (1- j))
                            (when (coalesce-regs-dead-at vec len j ra rb)
                              (return-from check))
                            (setf safe nil)
                            (return-from check))
                          ;; At a call: bail
                          (when (= (whistler/bpf:bpf-insn-code next) #x85)
                            (setf safe nil)
                            (return-from check))
                          ;; At exit: bail if rA or rB is r0
                          (when (bpf-exit-p next)
                            (when (or (zerop ra) (zerop rb))
                              (setf safe nil))
                            (setf end-j j)
                            (return-from check))
                          ;; At conditional jump: bail
                          (when (bpf-conditional-jmp-p next)
                            (setf safe nil)
                            (return-from check))
                          ;; Check if rB appears independently of rA
                          (let ((dst (whistler/bpf:bpf-insn-dst next))
                                (src (whistler/bpf:bpf-insn-src next)))
                            (when (and (or (= dst rb) (= src rb))
                                       (not (or (= dst ra) (= src ra))))
                              (setf safe nil)
                              (return-from check))
                            ;; Both rA and rB in same instruction: bail
                            (when (and (or (= dst rb) (= src rb))
                                       (or (= dst ra) (= src ra)))
                              (setf safe nil)
                              (return-from check)))
                          ;; At unconditional jump: end of block
                          (when (bpf-unconditional-jmp-p next)
                            (let ((target (+ j 1 (whistler/bpf:bpf-insn-off next))))
                              (if (and (>= target 0) (< target len)
                                       (coalesce-regs-dead-at vec len target ra rb))
                                  (setf end-j j)
                                  (setf safe nil)))
                            (return-from check))))
               ;; Phase 2: If safe, perform the rename
               (when (and safe end-j)
                 (loop for j from (1+ i) to end-j
                       for next = (aref vec j)
                       ;; Skip JA instructions — they don't use register fields
                       ;; and the BPF verifier rejects non-zero reserved fields.
                       unless (bpf-unconditional-jmp-p next)
                       do (when (= (whistler/bpf:bpf-insn-dst next) ra)
                            (setf (whistler/bpf:bpf-insn-dst next) rb))
                          (when (= (whistler/bpf:bpf-insn-src next) ra)
                            (setf (whistler/bpf:bpf-insn-src next) rb)))
                 (setf (gethash i to-delete) t)
                 (setf changed t))))
    (if changed
        (reindex-after-deletion vec to-delete)
        insns)))
