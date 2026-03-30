;;; -*- Mode: Lisp -*-
;;;
;;; Copyright (c) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; SPDX-License-Identifier: MIT

;;; emit.lisp — Emit BPF instructions from SSA IR
;;;
;;; Register allocation is done by linear-scan (regalloc.lisp) before
;;; emission. This file maps the allocated physical registers to BPF
;;; instructions, handles stack layout, map fd loading, and CO-RE tracking.

(in-package #:whistler/ir)

;;; ========== Emission context ==========

(defstruct emit-ctx
  (insns '())          ; BPF instructions (reverse order)
  (vreg-map (make-hash-table))  ; vreg → physical location (:reg N) or (:stack OFF)
  (next-callee 7)      ; next callee-saved register (7-9, R6 reserved for ctx)
  (stack-offset 0)     ; current stack usage
  (map-relocs '())     ; (byte-offset map-index) pairs
  (ir-prog nil)        ; the IR program
  (fixups '())         ; (bpf-insn-idx target-label) pairs for jump patching
  (key-cache (make-hash-table :test 'equal)) ; canonical key → stack-offset
  (vreg-types (make-hash-table))   ; vreg → type symbol (for size-aware stack alloc)
  (struct-offsets (make-hash-table))   ; vreg → R10-relative offset (for struct base elim)
  (const-values (make-hash-table))    ; vreg → integer constant value
  (map-fd-cache (make-hash-table))    ; map-name → callee-saved register number
  (map-fd-cache-block (make-hash-table)) ; map-name → block-label where cached
  (free-callee-regs '())             ; callee-saved regs not used by regalloc
  (map-ref-counts (make-hash-table)) ; map-name → reference count
  (dom-map nil)                      ; dominator map for control-flow-aware caching
  (current-block-label nil)          ; label of the block currently being emitted
  (core-relocs '())                  ; (bpf-insn-object struct-name field-name) for CO-RE
  (ptr-cache (make-hash-table))     ; R10-relative offset → stack slot holding cached ptr
  (struct-ptr-uses (make-hash-table)) ; struct vreg → count of map-ptr uses
  (phi-moves (make-hash-table :test 'equal)) ; (src-label . tgt-label) → ((phi-dst . src-vreg) ...)
  (stack-ledger '()))                 ; ((category . size) ...) for stack usage breakdown

(defun ectx-emit (ctx insn-list)
  (dolist (insn insn-list)
    (push insn (emit-ctx-insns ctx))))

(defun ectx-current-idx (ctx)
  (length (emit-ctx-insns ctx)))

(defun format-stack-breakdown (ledger)
  "Format stack ledger entries into a human-readable breakdown string.
   Aggregates entries by category and sorts by total bytes descending."
  (let ((totals (make-hash-table :test 'equal)))
    (dolist (entry ledger)
      (cl:incf (gethash (car entry) totals 0) (cdr entry)))
    (let ((sorted (sort (loop for cat being the hash-keys of totals
                              using (hash-value bytes)
                              collect (cons cat bytes))
                        #'> :key #'cdr)))
      (with-output-to-string (s)
        (dolist (entry sorted)
          (format s "~&    ~4d bytes  ~a" (cdr entry) (car entry)))))))

(defun ectx-alloc-stack (ctx size &optional (category "other"))
  "Allocate SIZE bytes on the stack with natural alignment.
   CATEGORY is a string describing the allocation purpose for diagnostics.
   Returns the (negative) offset from R10."
  (let* ((align (min size 8))
         (cur (emit-ctx-stack-offset ctx))
         (new-off (- cur size))
         ;; Align down to natural boundary (works for power-of-2 alignment)
         (aligned (logand new-off (- align))))
    (push (cons category (- cur aligned)) (emit-ctx-stack-ledger ctx))
    (when (< aligned -512)
      (whistler/compiler:whistler-error
       :what (format nil "stack frame exceeds BPF 512-byte limit (~d bytes needed)~%  breakdown:~a"
                     (- aligned) (format-stack-breakdown (emit-ctx-stack-ledger ctx)))
       :expected "total stack usage <= 512 bytes"
       :hint "reduce struct sizes, reuse buffers, or split logic across tail-called programs"))

    (setf (emit-ctx-stack-offset ctx) aligned)
    aligned))

(defun ectx-alloc-callee (ctx)
  "Allocate a callee-saved register. Returns reg number or nil."
  (let ((r (emit-ctx-next-callee ctx)))
    (when (<= r 9)
      (incf (emit-ctx-next-callee ctx))
      r)))

;;; ========== Register allocation ==========
;;;
;;; Uses linear-scan allocation from regalloc.lisp.
;;; The vreg-map is pre-computed before emission begins.

(defun allocate-vreg (ctx vreg)
  "Look up pre-computed physical location for a vreg."
  (or (gethash vreg (emit-ctx-vreg-map ctx))
      ;; Fallback: allocate on the fly (for vregs created during emission)
      (let ((loc (let ((reg (ectx-alloc-callee ctx)))
                   (if reg
                       (list :reg reg)
                       (list :stack (ectx-alloc-stack ctx 8 "register spills"))))))
        (setf (gethash vreg (emit-ctx-vreg-map ctx)) loc)
        loc)))

(defun vreg-to-physical (ctx vreg tmp-reg)
  "Get the value of VREG into TMP-REG if needed. Returns the physical register."
  (let ((loc (allocate-vreg ctx vreg)))
    (ecase (car loc)
      (:reg (cadr loc))
      (:stack
       (ectx-emit ctx (whistler/bpf:emit-ldx-mem
                        whistler/bpf:+bpf-dw+ tmp-reg
                        whistler/bpf:+bpf-reg-10+ (cadr loc)))
       tmp-reg))))

(defun store-to-vreg (ctx vreg src-reg)
  "Store SRC-REG into the physical location for VREG."
  (let ((loc (allocate-vreg ctx vreg)))
    (ecase (car loc)
      (:reg
       (unless (= src-reg (cadr loc))
         (ectx-emit ctx (whistler/bpf:emit-mov64-reg (cadr loc) src-reg))))
      (:stack
       (ectx-emit ctx (whistler/bpf:emit-stx-mem
                        whistler/bpf:+bpf-dw+
                        whistler/bpf:+bpf-reg-10+ src-reg (cadr loc)))))))

;;; ========== Immediate argument helpers ==========

(defun imm-arg-value (arg)
  "Extract integer from (:imm N) arg."
  (and (consp arg) (eq (first arg) :imm) (second arg)))

(defun map-arg-name (arg)
  "Extract map name from (:map NAME) arg."
  (and (consp arg) (eq (first arg) :map) (second arg)))

(defun helper-arg-id (arg)
  "Extract helper id from (:helper N) arg."
  (and (consp arg) (eq (first arg) :helper) (second arg)))

(defun label-arg-name (arg)
  "Extract label from (:label NAME) arg."
  (and (consp arg) (eq (first arg) :label) (second arg)))

(defun type-arg-name (arg)
  "Extract type from (:type NAME) arg."
  (and (consp arg) (eq (first arg) :type) (second arg)))

(defun cmp-arg-op (arg)
  "Extract comparison op from (:cmp OP) arg."
  (and (consp arg) (eq (first arg) :cmp) (second arg)))

(defun core-arg-info (args)
  "Find a (:core STRUCT-NAME FIELD-NAME) tag in an args list.
   Returns (STRUCT-NAME FIELD-NAME) or nil."
  (dolist (arg args)
    (when (and (consp arg) (eq (first arg) :core))
      (return (rest arg)))))

(defun commutative-alu-op-p (op)
  "Return true when OP is safe to evaluate with swapped operands."
  (member op '(:add :mul :and :or :xor)))

;;; ========== Size helpers ==========

(defun ir-type-to-bpf-size (type-kw)
  (let ((name (string-upcase (string type-kw))))
    (cond
      ((or (string= name "U8")  (string= name "I8"))  whistler/bpf:+bpf-b+)
      ((or (string= name "U16") (string= name "I16")) whistler/bpf:+bpf-h+)
      ((or (string= name "U32") (string= name "I32")) whistler/bpf:+bpf-w+)
      (t whistler/bpf:+bpf-dw+))))

;;; ========== BPF jump op mapping ==========

(defun ir-cmp-to-bpf-jmp (op)
  (ecase op
    (:jeq whistler/bpf:+bpf-jeq+)
    (:jne whistler/bpf:+bpf-jne+)
    (:jgt whistler/bpf:+bpf-jgt+)
    (:jge whistler/bpf:+bpf-jge+)
    (:jlt whistler/bpf:+bpf-jlt+)
    (:jle whistler/bpf:+bpf-jle+)
    (:jsgt whistler/bpf:+bpf-jsgt+)
    (:jsge whistler/bpf:+bpf-jsge+)
    (:jslt whistler/bpf:+bpf-jslt+)
    (:jsle whistler/bpf:+bpf-jsle+)))

(defun ir-alu-to-bpf (op)
  (ecase op
    (:add whistler/bpf:+bpf-add+)
    (:sub whistler/bpf:+bpf-sub+)
    (:mul whistler/bpf:+bpf-mul+)
    (:div whistler/bpf:+bpf-div+)
    (:mod whistler/bpf:+bpf-mod+)
    (:and whistler/bpf:+bpf-and+)
    (:or  whistler/bpf:+bpf-or+)
    (:xor whistler/bpf:+bpf-xor+)
    (:lsh whistler/bpf:+bpf-lsh+)
    (:rsh whistler/bpf:+bpf-rsh+)
    (:arsh whistler/bpf:+bpf-arsh+)))

;;; ========== Block ordering and label resolution ==========

(defun flatten-blocks (prog)
  "Return all instructions in program order with block labels resolved to indices."
  ;; First pass: collect all IR instructions in block order
  (let ((block-order (order-blocks prog)))
    (values block-order
            (let ((insn-list '()))
              (dolist (block block-order)
                (dolist (insn (basic-block-insns block))
                  (push insn insn-list)))
              (nreverse insn-list)))))

(defun block-has-ret-p (block)
  "Does this block end with a :ret instruction?"
  (let ((last-insn (car (last (basic-block-insns block)))))
    (and last-insn (eq (ir-insn-op last-insn) :ret))))

(defun order-blocks (prog)
  "Order blocks: keep creation order but move :ret blocks to the end
   when there are multiple of them (from explicit return statements).
   This ensures return statements always produce forward jumps, avoiding
   the kernel BPF verifier's infinite loop detection.
   When there is only one :ret block, keep original order (it is
   already the natural fall-through target)."
  (let* ((blocks (ir-program-blocks prog))
         (entry-label (ir-program-entry prog))
         (non-ret '())
         (ret-blocks '()))
    (dolist (b blocks)
      (if (and (block-has-ret-p b)
               (not (eq (basic-block-label b) entry-label)))
          (push b ret-blocks)
          (push b non-ret)))
    (if (> (length ret-blocks) 1)
        ;; Multiple return blocks: move them all to end
        (nconc (nreverse non-ret) (nreverse ret-blocks))
        ;; Zero or one return block: keep original order
        blocks)))

;;; ========== Main emission ==========

(defun build-vreg-type-map (prog)
  "Build a hash table mapping vreg → type symbol from IR instructions."
  (let ((map (make-hash-table)))
    (dolist (block (ir-program-blocks prog))
      (dolist (insn (basic-block-insns block))
        (when (and (ir-insn-dst insn) (ir-insn-type insn))
          (setf (gethash (ir-insn-dst insn) map) (ir-insn-type insn)))))
    map))

(defun ir-type-to-byte-size (type-kw)
  "Return byte size for an IR type keyword."
  (if type-kw
      (let ((name (string-upcase (string type-kw))))
        (cond
          ((or (string= name "U8")  (string= name "I8"))  1)
          ((or (string= name "U16") (string= name "I16")) 2)
          ((or (string= name "U32") (string= name "I32")) 4)
          (t 8)))
      8))

(defun find-free-callee-regs (alloc-map)
  "Return a list of callee-saved registers (6-9) not used by any vreg."
  (let ((used (make-hash-table)))
    (maphash (lambda (vreg loc)
               (declare (ignore vreg))
               (when (and (consp loc) (eq (car loc) :reg)
                          (<= 6 (cadr loc) 9))
                 (setf (gethash (cadr loc) used) t)))
             alloc-map)
    (loop for r from 6 to 9
          unless (gethash r used) collect r)))

(defun count-map-fd-refs (prog)
  "Count how many times each map is referenced in the IR program.
   Returns a hash table: map-name → count."
  (let ((counts (make-hash-table)))
    (dolist (block (ir-program-blocks prog))
      (dolist (insn (basic-block-insns block))
        (when (member (ir-insn-op insn) '(:map-lookup :map-lookup-ptr
                                          :map-lookup-delete :tail-call
                                          :map-update :map-update-ptr
                                          :map-delete :map-delete-ptr
                                          :ringbuf-reserve))
          (let ((map-name (map-arg-name (first (ir-insn-args insn)))))
            (when map-name
              (incf (gethash map-name counts 0)))))))
    counts))

(defun count-struct-ptr-uses (prog)
  "Count how many times each struct-alloc vreg is used as a key/value pointer
   in map-*-ptr operations. Returns a hash table: vreg → count."
  (let ((counts (make-hash-table)))
    (dolist (block (ir-program-blocks prog))
      (dolist (insn (basic-block-insns block))
        (when (member (ir-insn-op insn) '(:map-lookup-ptr :map-update-ptr :map-delete-ptr))
          (let ((ptr-vreg (second (ir-insn-args insn))))
            (when (integerp ptr-vreg)
              (incf (gethash ptr-vreg counts 0)))))
        ;; Also count val-ptr in map-update-ptr (3rd arg)
        (when (eq (ir-insn-op insn) :map-update-ptr)
          (let ((val-vreg (third (ir-insn-args insn))))
            (when (integerp val-vreg)
              (incf (gethash val-vreg counts 0)))))))
    counts))

(defun emit-ir-to-bpf (prog &key reserve-callee-count (auto-reserve-helper-setup t))
  "Emit BPF instructions from optimized SSA IR.
   Returns a compilation-unit compatible structure."
  (multiple-value-bind (alloc-map regalloc-stack)
      (linear-scan-alloc prog
                         :ctx-early (ctx-loads-early-p prog)
                         :reserve-callee-count reserve-callee-count
                         :auto-reserve-helper-setup auto-reserve-helper-setup)
    (let* ((ctx-early (ctx-loads-early-p prog))
           (free-callee (find-free-callee-regs alloc-map))
           (map-refs (count-map-fd-refs prog))
           (struct-uses (count-struct-ptr-uses prog))
           (dom-map (compute-dominators prog))
           (ctx (make-emit-ctx :ir-prog prog :vreg-map alloc-map
                               :stack-offset regalloc-stack
                               :stack-ledger (when (< regalloc-stack 0)
                                               (list (cons "register spills (regalloc)"
                                                           (- regalloc-stack))))
                               :vreg-types (build-vreg-type-map prog)
                               :free-callee-regs free-callee
                               :map-ref-counts map-refs
                               :struct-ptr-uses struct-uses
                               :dom-map dom-map))
           (blocks (order-blocks prog))
           (block-positions (make-hash-table)))

    ;; Populate const-values: vreg → integer for mov %v (:imm N)
    (dolist (block blocks)
      (dolist (insn (basic-block-insns block))
        (when (and (eq (ir-insn-op insn) :mov)
                   (ir-insn-dst insn)
                   (let ((arg (first (ir-insn-args insn))))
                     (and (consp arg) (eq (car arg) :imm))))
          (setf (gethash (ir-insn-dst insn) (emit-ctx-const-values ctx))
                (second (first (ir-insn-args insn)))))))

    ;; Build phi resolution table: for each phi in a block, record the moves
    ;; needed at each predecessor's branch to that block.
    (dolist (block blocks)
      (dolist (insn (basic-block-insns block))
        (when (and (eq (ir-insn-op insn) :phi) (ir-insn-dst insn))
          (let ((phi-dst (ir-insn-dst insn))
                (tgt-label (basic-block-label block)))
            (dolist (arg (ir-insn-args insn))
              (when (and (consp arg) (integerp (first arg))
                         (consp (second arg)) (eq (car (second arg)) :label))
                (let* ((src-vreg (first arg))
                       (src-label (cadr (second arg)))
                       (key (cons src-label tgt-label)))
                  (push (cons phi-dst src-vreg)
                        (gethash key (emit-ctx-phi-moves ctx))))))))))

    ;; Emit ctx save only if ctx-loads happen after calls (need R6)
    (let ((ctx-vreg (find-ctx-vreg prog)))
      (when (and ctx-vreg (vreg-used-p prog ctx-vreg) (not ctx-early))
        (ectx-emit ctx (whistler/bpf:emit-mov64-reg
                        whistler/bpf:+bpf-reg-6+ whistler/bpf:+bpf-reg-1+))))

    ;; Emit each block
    (dolist (block blocks)
      (setf (emit-ctx-current-block-label ctx) (basic-block-label block))
      (setf (gethash (basic-block-label block) block-positions)
            (ectx-current-idx ctx))
      (dolist (insn (basic-block-insns block))
        (emit-ir-insn ctx insn block-positions)))

    ;; Patch jump offsets
    (let ((bpf-insns (nreverse (emit-ctx-insns ctx))))
      (dolist (fixup (emit-ctx-fixups ctx))
        (destructuring-bind (bpf-idx target-label) fixup
          (let* ((target-pos (gethash target-label block-positions))
                 (offset (- target-pos bpf-idx 1))
                 (insn (nth bpf-idx bpf-insns)))
            (setf (whistler/bpf:bpf-insn-off insn) offset))))

      ;; Apply peephole optimizations
      (setf bpf-insns (peephole-optimize bpf-insns))

      ;; Rebuild map relocations after peephole.
      ;; The peephole may remove instructions, shifting byte offsets.
      ;; Scan for ld_imm64 with src=BPF_PSEUDO_MAP_FD (1) and pair
      ;; with original relocs (which are in the same order of appearance).
      (let ((new-relocs '())
            (old-relocs (nreverse (emit-ctx-map-relocs ctx))))
        (loop for insn in bpf-insns
              for idx from 0
              when (and (= (whistler/bpf:bpf-insn-code insn)
                           (logior whistler/bpf:+bpf-ld+
                                   whistler/bpf:+bpf-dw+
                                   whistler/bpf:+bpf-imm+))
                        (= (whistler/bpf:bpf-insn-src insn) 1))
              do (let ((map-idx (second (pop old-relocs))))
                   (push (list (* idx 8) map-idx) new-relocs)))

        ;; Rebuild CO-RE relocations after peephole.
        ;; Scan for eq-identical BPF insn objects recorded during emission.
        (let ((core-reloc-map (make-hash-table :test 'eq))
              (final-core-relocs '()))
          (dolist (entry (emit-ctx-core-relocs ctx))
            (destructuring-bind (insn-obj struct-name field-name) entry
              (setf (gethash insn-obj core-reloc-map)
                    (list struct-name field-name))))
          (loop for insn in bpf-insns
                for idx from 0
                do (let ((info (gethash insn core-reloc-map)))
                     (when info
                       (push (list (* idx 8) (first info) (second info))
                             final-core-relocs))))

          ;; Build result
          (let ((cu (whistler/compiler:make-compilation-unit
                     :section (ir-program-section prog)
                     :license (ir-program-license prog))))
            (setf (whistler/compiler:cu-insns cu) bpf-insns)
            (setf (whistler/compiler:cu-maps cu) (ir-program-maps prog))
            (setf (whistler/compiler:cu-map-relocs cu) (nreverse new-relocs))
            (setf (whistler/compiler:cu-core-relocs cu) (nreverse final-core-relocs))
            cu)))))))

(defun find-ctx-vreg (prog)
  "Find the vreg assigned to %%CTX (the arg0 instruction)."
  (dolist (block (ir-program-blocks prog))
    (dolist (insn (basic-block-insns block))
      (when (eq (ir-insn-op insn) :arg0)
        (return-from find-ctx-vreg (ir-insn-dst insn)))))
  nil)

(defun vreg-used-p (prog vreg)
  "Is VREG referenced in any instruction args?"
  (dolist (block (ir-program-blocks prog))
    (dolist (insn (basic-block-insns block))
      (dolist (arg (ir-insn-args insn))
        (when (and (integerp arg) (= arg vreg))
          (return-from vreg-used-p t))
        (when (and (consp arg) (integerp (first arg)) (= (first arg) vreg))
          (return-from vreg-used-p t)))))
  nil)

;;; ========== Per-instruction emission ==========

(defun emit-ir-insn (ctx insn block-positions)
  (declare (ignore block-positions))
  (let* ((op (ir-insn-op insn))
         (dst (ir-insn-dst insn))
         (args (ir-insn-args insn)))
    (cond
     ((eq op :arg0) nil)

     ((eq op :mov)
      (emit-mov-insn ctx dst args))

     ((member op '(:add :sub :mul :div :mod :and :or :xor :lsh :rsh :arsh))
      (emit-alu-insn ctx op dst args (ir-insn-type insn)))

     ((eq op :neg)
      (emit-neg-insn ctx dst args))

     ((eq op :cmp)       (emit-cmp-insn ctx dst args))
     ((eq op :load)      (emit-load-insn ctx dst args))
     ((eq op :ctx-load)  (emit-ctx-load-insn ctx dst args))
     ((eq op :store)     (emit-store-insn ctx args))
     ((eq op :atomic-add)(emit-atomic-add-insn ctx args))
     ((eq op :call)      (emit-call-insn ctx dst args))
     ((eq op :tail-call) (emit-tail-call-insn ctx dst args))
     ((eq op :map-lookup)(emit-map-lookup-insn ctx dst args))
     ((eq op :map-lookup-ptr)(emit-map-lookup-ptr-insn ctx dst args))
     ((eq op :struct-alloc)(emit-struct-alloc-insn ctx dst args))
     ((eq op :map-lookup-delete)(emit-map-lookup-delete-insn ctx dst args))
     ((eq op :map-update)(emit-map-update-insn ctx dst args))
     ((eq op :map-update-ptr)(emit-map-update-ptr-insn ctx dst args))
     ((eq op :map-delete)(emit-map-delete-insn ctx dst args))
     ((eq op :map-delete-ptr)(emit-map-delete-ptr-insn ctx dst args))
     ((eq op :ringbuf-reserve)(emit-ringbuf-reserve-insn ctx dst args))
     ((eq op :ringbuf-submit)(emit-ringbuf-submit-insn ctx dst args))
     ((eq op :ringbuf-discard)(emit-ringbuf-discard-insn ctx dst args))
     ((eq op :log2)      (emit-log2-insn ctx dst args))
     ((eq op :cast)      (emit-cast-insn ctx dst args))
     ((eq op :stack-addr)(emit-stack-addr-insn ctx dst args))

     ((member op '(:bswap16 :bswap32 :bswap64))
      (emit-bswap-insn ctx op dst args))

     ((eq op :phi)
      ;; Phi resolution moves are emitted at predecessor branches, not here.
      nil)

     ((eq op :br)
      (let ((target (label-arg-name (first args))))
        ;; Emit phi resolution moves before the jump
        (let ((moves (gethash (cons (emit-ctx-current-block-label ctx) target)
                              (emit-ctx-phi-moves ctx))))
          (dolist (move moves)
            (let* ((phi-dst (car move))
                   (src-vreg (cdr move))
                   (src-reg (vreg-to-physical ctx src-vreg whistler/bpf:+bpf-reg-0+))
                   (dst-loc (gethash phi-dst (emit-ctx-vreg-map ctx))))
              (when dst-loc
                (cond
                  ((and (eq (car dst-loc) :reg)
                        (/= (cadr dst-loc) src-reg))
                   (ectx-emit ctx (whistler/bpf:emit-mov64-reg (cadr dst-loc) src-reg)))
                  ((eq (car dst-loc) :stack)
                   (ectx-emit ctx (whistler/bpf:emit-stx-mem
                                    whistler/bpf:+bpf-dw+
                                    whistler/bpf:+bpf-reg-10+ src-reg (cadr dst-loc)))))))))
        (push (list (ectx-current-idx ctx) target) (emit-ctx-fixups ctx))
        (ectx-emit ctx (whistler/bpf:emit-jmp-a 0))))

     ((eq op :br-cond)
      (emit-br-cond-insn ctx args))

     ((eq op :ret)
      (let ((val (first args)))
        (when (integerp val)
          (let ((src-reg (vreg-to-physical ctx val whistler/bpf:+bpf-reg-1+)))
            (unless (= src-reg whistler/bpf:+bpf-reg-0+)
              (ectx-emit ctx (whistler/bpf:emit-mov64-reg whistler/bpf:+bpf-reg-0+ src-reg)))))
        (ectx-emit ctx (whistler/bpf:emit-exit))))

     (t (error "Unknown IR op for emission: ~a" op)))))

(defun emit-mov-insn (ctx dst args)
  "Emit a mov instruction (vreg-to-vreg copy or immediate load)."
  (when dst
    (let ((arg (first args)))
      (cond
       ((integerp arg)
        (let ((src-phys (vreg-to-physical ctx arg whistler/bpf:+bpf-reg-1+)))
          (store-to-vreg ctx dst src-phys)))
       ((consp arg)
        (let ((imm (imm-arg-value arg)))
          (when imm
            (let ((dst-loc (allocate-vreg ctx dst)))
              (ecase (car dst-loc)
                (:reg
                 (if (typep imm '(signed-byte 32))
                     (ectx-emit ctx (whistler/bpf:emit-mov64-imm (cadr dst-loc) imm))
                     (ectx-emit ctx (whistler/bpf:emit-ld-imm64 (cadr dst-loc) imm))))
                (:stack
                 (let ((tmp whistler/bpf:+bpf-reg-1+))
                   (if (typep imm '(signed-byte 32))
                       (ectx-emit ctx (whistler/bpf:emit-mov64-imm tmp imm))
                       (ectx-emit ctx (whistler/bpf:emit-ld-imm64 tmp imm)))
                   (ectx-emit ctx (whistler/bpf:emit-stx-mem
                                   whistler/bpf:+bpf-dw+
                                   whistler/bpf:+bpf-reg-10+ tmp (cadr dst-loc))))))))))))))

(defun emit-neg-insn (ctx dst args)
  "Emit a negation instruction."
  (let ((src-reg (vreg-to-physical ctx (first args) whistler/bpf:+bpf-reg-1+))
        (dst-loc (allocate-vreg ctx dst)))
    (ecase (car dst-loc)
      (:reg
       (unless (= src-reg (cadr dst-loc))
         (ectx-emit ctx (whistler/bpf:emit-mov64-reg (cadr dst-loc) src-reg)))
       (ectx-emit ctx (whistler/bpf:emit-alu64-imm whistler/bpf:+bpf-neg+ (cadr dst-loc) 0)))
      (:stack
       (ectx-emit ctx (whistler/bpf:emit-mov64-reg whistler/bpf:+bpf-reg-1+ src-reg))
       (ectx-emit ctx (whistler/bpf:emit-alu64-imm whistler/bpf:+bpf-neg+ whistler/bpf:+bpf-reg-1+ 0))
       (ectx-emit ctx (whistler/bpf:emit-stx-mem
                       whistler/bpf:+bpf-dw+
                       whistler/bpf:+bpf-reg-10+ whistler/bpf:+bpf-reg-1+ (cadr dst-loc)))))))

;;; ========== ALU emission ==========

(defun ir-type-is-32bit-p (type)
  "Return T if TYPE is a 32-bit or narrower type (u8, u16, u32)."
  (when type
    (let ((name (string-upcase (string type))))
      (or (string= name "U8")  (string= name "I8")
          (string= name "U16") (string= name "I16")
          (string= name "U32") (string= name "I32")))))

(defun emit-alu-insn (ctx op dst args &optional type)
  (let* ((bpf-op (ir-alu-to-bpf op))
         (rhs (second args))
         (dst-loc (allocate-vreg ctx dst))
         (work-reg (if (eq (car dst-loc) :reg) (cadr dst-loc) whistler/bpf:+bpf-reg-1+))
         (use-alu32 (ir-type-is-32bit-p type))
         (emit-alu (if use-alu32 #'whistler/bpf:emit-alu32-reg #'whistler/bpf:emit-alu64-reg))
         (emit-alu-i (if use-alu32 #'whistler/bpf:emit-alu32-imm #'whistler/bpf:emit-alu64-imm)))
    (if (integerp rhs)
        ;; vreg operand — check physical locations BEFORE emitting loads
        ;; to avoid clobbering one operand while loading the other
        (let* ((lhs-loc (allocate-vreg ctx (first args)))
               (rhs-loc (allocate-vreg ctx rhs))
               (lhs-phys (if (eq (car lhs-loc) :reg) (cadr lhs-loc) nil))
               (rhs-phys (if (eq (car rhs-loc) :reg) (cadr rhs-loc) nil)))
          (cond
            ;; Case 1: lhs already in work-reg — just load rhs
            ((and lhs-phys (= lhs-phys work-reg))
             (let ((rhs-reg (vreg-to-physical ctx rhs whistler/bpf:+bpf-reg-2+)))
               (ectx-emit ctx (funcall emit-alu bpf-op work-reg rhs-reg))))
            ;; Case 2: rhs NOT in work-reg — safe to load lhs first
            ((not (and rhs-phys (= rhs-phys work-reg)))
             (let ((lhs-reg (vreg-to-physical ctx (first args) work-reg)))
               (unless (= lhs-reg work-reg)
                 (ectx-emit ctx (whistler/bpf:emit-mov64-reg work-reg lhs-reg)))
               (let ((rhs-reg (vreg-to-physical ctx rhs whistler/bpf:+bpf-reg-2+)))
                 (ectx-emit ctx (funcall emit-alu bpf-op work-reg rhs-reg)))))
            ;; Case 3: rhs IS in work-reg — evacuate rhs before loading lhs
            (t
             (if (commutative-alu-op-p op)
                 ;; For commutative ops, keep rhs in work-reg and apply lhs.
                 (let* ((lhs-tmp (if (= work-reg whistler/bpf:+bpf-reg-2+)
                                     whistler/bpf:+bpf-reg-3+
                                     whistler/bpf:+bpf-reg-2+))
                        (lhs-reg (vreg-to-physical ctx (first args) lhs-tmp)))
                   (ectx-emit ctx (funcall emit-alu bpf-op work-reg lhs-reg)))
                 (let ((scratch (if (and lhs-phys (= lhs-phys whistler/bpf:+bpf-reg-2+))
                                    whistler/bpf:+bpf-reg-3+
                                    whistler/bpf:+bpf-reg-2+)))
                   (ectx-emit ctx (whistler/bpf:emit-mov64-reg scratch work-reg))
                   (let ((lhs-reg (vreg-to-physical ctx (first args) work-reg)))
                     (unless (= lhs-reg work-reg)
                       (ectx-emit ctx (whistler/bpf:emit-mov64-reg work-reg lhs-reg))))
                   (ectx-emit ctx (funcall emit-alu bpf-op work-reg scratch)))))))
        ;; Immediate or non-integer rhs
        (let ((lhs-reg (vreg-to-physical ctx (first args) whistler/bpf:+bpf-reg-1+))
              (imm (imm-arg-value rhs)))
          (unless (= lhs-reg work-reg)
            (ectx-emit ctx (whistler/bpf:emit-mov64-reg work-reg lhs-reg)))
          (if (and imm (typep imm '(signed-byte 32)))
              (ectx-emit ctx (funcall emit-alu-i bpf-op work-reg imm))
              ;; Must be a vreg in a non-standard form
              (let ((rhs-reg (vreg-to-physical ctx rhs whistler/bpf:+bpf-reg-2+)))
                (ectx-emit ctx (funcall emit-alu bpf-op work-reg rhs-reg))))))
    ;; Store result if on stack
    (when (eq (car dst-loc) :stack)
      (ectx-emit ctx (whistler/bpf:emit-stx-mem
                       whistler/bpf:+bpf-dw+
                       whistler/bpf:+bpf-reg-10+ work-reg (cadr dst-loc))))))

;;; ========== Comparison emission ==========

(defun emit-cmp-insn (ctx dst args)
  (let* ((cmp-op (cmp-arg-op (first args)))
         (bpf-jmp (ir-cmp-to-bpf-jmp cmp-op))
         (lhs (second args))
         (rhs (third args))
         (dst-loc (allocate-vreg ctx dst))
         (dst-reg (if (eq (car dst-loc) :reg) (cadr dst-loc) whistler/bpf:+bpf-reg-1+)))
    ;; Load lhs
    (let ((lhs-reg (if (integerp lhs)
                       (vreg-to-physical ctx lhs whistler/bpf:+bpf-reg-2+)
                       whistler/bpf:+bpf-reg-2+)))
      ;; Set result = 1
      (ectx-emit ctx (whistler/bpf:emit-mov64-imm dst-reg 1))
      ;; Compare
      (let ((imm (imm-arg-value rhs)))
        (if (and imm (typep imm '(signed-byte 32)))
            (ectx-emit ctx (whistler/bpf:emit-jmp-imm bpf-jmp lhs-reg imm 1))
            (let ((rhs-reg (if (integerp rhs)
                               (vreg-to-physical ctx rhs whistler/bpf:+bpf-reg-3+)
                               whistler/bpf:+bpf-reg-3+)))
              (ectx-emit ctx (whistler/bpf:emit-jmp-reg bpf-jmp lhs-reg rhs-reg 1)))))
      ;; Set result = 0 (fallthrough)
      (ectx-emit ctx (whistler/bpf:emit-mov64-imm dst-reg 0)))
    ;; Store if needed
    (when (eq (car dst-loc) :stack)
      (ectx-emit ctx (whistler/bpf:emit-stx-mem
                       whistler/bpf:+bpf-dw+
                       whistler/bpf:+bpf-reg-10+ dst-reg (cadr dst-loc))))))

;;; ========== Load/Store emission ==========

(defun emit-load-insn (ctx dst args)
  (let* ((ptr-vreg (first args))
         (struct-base (and (integerp ptr-vreg)
                           (gethash ptr-vreg (emit-ctx-struct-offsets ctx))))
         (off (imm-arg-value (second args)))
         (type-kw (type-arg-name (third args)))
         (bpf-size (ir-type-to-bpf-size type-kw))
         (dst-loc (allocate-vreg ctx dst))
         (dst-reg (if (eq (car dst-loc) :reg) (cadr dst-loc) whistler/bpf:+bpf-reg-1+))
         (core-info (core-arg-info args))
         load-insn)
    (if struct-base
        ;; Direct R10-relative load — skip loading the struct pointer
        (let ((insns (whistler/bpf:emit-ldx-mem bpf-size dst-reg
                       whistler/bpf:+bpf-reg-10+ (+ struct-base off))))
          (setf load-insn (first insns))
          (ectx-emit ctx insns))
        ;; Normal pointer-based load
        (let ((ptr-reg (vreg-to-physical ctx ptr-vreg whistler/bpf:+bpf-reg-1+)))
          (let ((insns (whistler/bpf:emit-ldx-mem bpf-size dst-reg ptr-reg off)))
            (setf load-insn (first insns))
            (ectx-emit ctx insns))))
    ;; Record CO-RE relocation if annotated
    (when core-info
      (push (list load-insn (first core-info) (second core-info))
            (emit-ctx-core-relocs ctx)))
    (when (eq (car dst-loc) :stack)
      (ectx-emit ctx (whistler/bpf:emit-stx-mem
                       whistler/bpf:+bpf-dw+
                       whistler/bpf:+bpf-reg-10+ dst-reg (cadr dst-loc))))))

(defun emit-ctx-load-insn (ctx dst args)
  ;; When ctx was saved to R6 (not early), use R6 directly instead of
  ;; looking up the ctx vreg's allocation — which may be a stack spill
  ;; that hasn't been initialized.
  (let* ((ctx-early (ctx-loads-early-p (emit-ctx-ir-prog ctx)))
         (ctx-reg (if ctx-early
                      (vreg-to-physical ctx (first args) whistler/bpf:+bpf-reg-1+)
                      whistler/bpf:+bpf-reg-6+))
         (off (imm-arg-value (second args)))
         (type-kw (type-arg-name (third args)))
         (bpf-size (ir-type-to-bpf-size type-kw))
         (dst-loc (allocate-vreg ctx dst))
         (dst-reg (if (eq (car dst-loc) :reg) (cadr dst-loc) whistler/bpf:+bpf-reg-1+))
         (core-info (core-arg-info args)))
    (let ((insns (whistler/bpf:emit-ldx-mem bpf-size dst-reg ctx-reg off)))
      (when core-info
        (push (list (first insns) (first core-info) (second core-info))
              (emit-ctx-core-relocs ctx)))
      (ectx-emit ctx insns))
    (when (eq (car dst-loc) :stack)
      (ectx-emit ctx (whistler/bpf:emit-stx-mem
                       whistler/bpf:+bpf-dw+
                       whistler/bpf:+bpf-reg-10+ dst-reg (cadr dst-loc))))))

(defun emit-store-insn (ctx args)
  (let* ((ptr-vreg (first args))
         (struct-base (and (integerp ptr-vreg)
                           (gethash ptr-vreg (emit-ctx-struct-offsets ctx))))
         (off (imm-arg-value (second args)))
         (val-arg (third args))
         (val-imm (or (imm-arg-value val-arg)
                      ;; Also check const-values for vregs holding constants
                      (and (integerp val-arg)
                           (gethash val-arg (emit-ctx-const-values ctx)))))
         (type-kw (type-arg-name (fourth args)))
         (bpf-size (ir-type-to-bpf-size type-kw))
         (core-info (core-arg-info args))
         store-insn)
    (cond
      ;; Immediate value + struct base → direct st-mem to R10-relative
      ((and struct-base val-imm)
       (let ((insns (whistler/bpf:emit-st-mem bpf-size
                      whistler/bpf:+bpf-reg-10+ (+ struct-base off) val-imm)))
         (setf store-insn (first insns))
         (ectx-emit ctx insns)))
      ;; Immediate value + normal pointer → st-mem through pointer reg
      (val-imm
       (let ((ptr-reg (vreg-to-physical ctx ptr-vreg whistler/bpf:+bpf-reg-1+)))
         (let ((insns (whistler/bpf:emit-st-mem bpf-size ptr-reg off val-imm)))
           (setf store-insn (first insns))
           (ectx-emit ctx insns))))
      ;; Vreg value + struct base → stx-mem to R10-relative
      (struct-base
       (let ((val-reg (vreg-to-physical ctx val-arg whistler/bpf:+bpf-reg-2+)))
         (let ((insns (whistler/bpf:emit-stx-mem bpf-size
                        whistler/bpf:+bpf-reg-10+ val-reg (+ struct-base off))))
           (setf store-insn (first insns))
           (ectx-emit ctx insns))))
      ;; Normal pointer-based store
      (t
       (let ((ptr-reg (vreg-to-physical ctx ptr-vreg whistler/bpf:+bpf-reg-1+))
             (val-reg (vreg-to-physical ctx val-arg whistler/bpf:+bpf-reg-2+)))
         (let ((insns (whistler/bpf:emit-stx-mem bpf-size ptr-reg val-reg off)))
           (setf store-insn (first insns))
           (ectx-emit ctx insns)))))
    ;; Record CO-RE relocation if annotated
    (when core-info
      (push (list store-insn (first core-info) (second core-info))
            (emit-ctx-core-relocs ctx)))))

(defun emit-atomic-add-insn (ctx args)
  (let* ((ptr-vreg (first args))
         (struct-base (and (integerp ptr-vreg)
                           (gethash ptr-vreg (emit-ctx-struct-offsets ctx))))
         (off (imm-arg-value (second args)))
         (val-reg (vreg-to-physical ctx (third args) whistler/bpf:+bpf-reg-2+))
         (type-kw (if (fourth args) (type-arg-name (fourth args)) 'u64))
         (bpf-size (ir-type-to-bpf-size type-kw)))
    (if struct-base
        (ectx-emit ctx (whistler/bpf:emit-stx-atomic
                         bpf-size whistler/bpf:+bpf-reg-10+
                         val-reg (+ struct-base off) whistler/bpf:+bpf-add+))
        (let ((ptr-reg (vreg-to-physical ctx ptr-vreg whistler/bpf:+bpf-reg-1+)))
          (ectx-emit ctx (whistler/bpf:emit-stx-atomic
                           bpf-size ptr-reg
                           val-reg off whistler/bpf:+bpf-add+))))))

;;; ========== Stack-addr emission ==========

(defun emit-stack-addr-insn (ctx dst args)
  "Emit stack-addr: store vreg to stack, return pointer to that slot."
  (let* ((src-vreg (first args))
         (stack-offset (emit-key-to-stack ctx src-vreg))
         (dst-loc (allocate-vreg ctx dst))
         (dst-reg (if (eq (car dst-loc) :reg) (cadr dst-loc) whistler/bpf:+bpf-reg-1+)))
    (emit-stack-ptr ctx stack-offset dst-reg)
    (when (eq (car dst-loc) :stack)
      (ectx-emit ctx (whistler/bpf:emit-stx-mem
                       whistler/bpf:+bpf-dw+
                       whistler/bpf:+bpf-reg-10+ dst-reg (cadr dst-loc))))))

;;; ========== Map operations emission ==========

(defun emit-map-fd (ctx map-name dst-reg)
  "Emit map fd load with relocation.  Caches the fd in a free callee-saved
   register when available, replacing subsequent ld_pseudo (2 insns) with
   mov (1 insn).  Uses dominator analysis to ensure the cached register is
   only reused when the caching block dominates the current block."
  (let ((cached-reg (gethash map-name (emit-ctx-map-fd-cache ctx)))
        (cached-block (gethash map-name (emit-ctx-map-fd-cache-block ctx)))
        (cur-block (emit-ctx-current-block-label ctx))
        (dom-map (emit-ctx-dom-map ctx)))
    (if (and cached-reg cached-block dom-map
             (dominates-p dom-map cached-block cur-block))
        ;; Cache hit — the block where we cached dominates here,
        ;; so the register is guaranteed to be initialized.
        (ectx-emit ctx (whistler/bpf:emit-mov64-reg dst-reg cached-reg))
        ;; Cache miss or not dominated — emit fresh ld_pseudo
        (let* ((name-str (symbol-name map-name))
               (map (find name-str (ir-program-maps (emit-ctx-ir-prog ctx))
                          :key (lambda (m) (symbol-name (whistler/compiler:bpf-map-name m)))
                          :test #'string=)))
          (unless map (error "Unknown map: ~a" map-name))
          (let ((byte-offset (* (ectx-current-idx ctx) 8)))
            (push (list byte-offset (whistler/compiler:bpf-map-index map))
                  (emit-ctx-map-relocs ctx)))
          (ectx-emit ctx (whistler/bpf:emit-ld-map-fd dst-reg 0))
          ;; Cache in a free callee-saved register when profitable (3+ refs)
          (when (and (not cached-reg)
                     (emit-ctx-free-callee-regs ctx)
                     (>= (gethash map-name (emit-ctx-map-ref-counts ctx) 0) 3))
            (let ((cache-reg (pop (emit-ctx-free-callee-regs ctx))))
              (ectx-emit ctx (whistler/bpf:emit-mov64-reg cache-reg dst-reg))
              (setf (gethash map-name (emit-ctx-map-fd-cache ctx)) cache-reg)
              (setf (gethash map-name (emit-ctx-map-fd-cache-block ctx))
                    cur-block)))))))

(defun key-cache-key (ctx key-arg byte-size)
  "Build a stable cache key for stack-stored map keys.
   Constant keys are canonicalized by size+value so repeated (:imm N)
   objects and distinct constant-valued vregs can reuse the same slot."
  (let ((imm-val (imm-arg-value key-arg)))
    (if imm-val
        (list :const byte-size imm-val)
        (let ((const-val (gethash key-arg (emit-ctx-const-values ctx))))
          (if const-val
              (list :const byte-size const-val)
              key-arg)))))

(defun emit-key-to-stack (ctx key-arg)
  "Store a key value on the stack and return the stack offset.
   KEY-ARG may be a vreg (integer) or (:imm N) from constant propagation.
   Reuses existing stack slot if the same key was previously stored.
   Uses st-mem for constant keys (saves 1 insn vs mov+stx-mem)."
  (let* ((imm-val (imm-arg-value key-arg))
         (vreg-type (if imm-val nil (gethash key-arg (emit-ctx-vreg-types ctx))))
         (byte-size (if imm-val 4 (ir-type-to-byte-size vreg-type)))
         (cache-key (key-cache-key ctx key-arg byte-size))
         (cached (gethash cache-key (emit-ctx-key-cache ctx))))
    (if cached
        cached
        (let* ((bpf-size (if imm-val whistler/bpf:+bpf-w+
                             (ir-type-to-bpf-size (or vreg-type 'u64))))
               (const-val (or imm-val
                              (gethash key-arg (emit-ctx-const-values ctx))))
               (offset (ectx-alloc-stack ctx byte-size "map key temporaries")))
          (if (and const-val (typep const-val '(signed-byte 32)))
              ;; Constant key: use st-mem (1 insn)
              (ectx-emit ctx (whistler/bpf:emit-st-mem
                              bpf-size
                              whistler/bpf:+bpf-reg-10+ offset const-val))
              ;; Variable key: load to register then store
              (let ((src-reg (vreg-to-physical ctx key-arg whistler/bpf:+bpf-reg-3+)))
                (ectx-emit ctx (whistler/bpf:emit-stx-mem
                                bpf-size
                                whistler/bpf:+bpf-reg-10+ src-reg offset))))
          (setf (gethash cache-key (emit-ctx-key-cache ctx)) offset)
          offset))))

(defun emit-stack-ptr (ctx offset dst-reg)
  "Emit instructions to compute R10 + offset into dst-reg.
   If this offset has a cached pointer (from a previous call that stored it),
   reload in 1 instruction instead of recomputing in 2."
  (let ((cached-slot (gethash offset (emit-ctx-ptr-cache ctx))))
    (if cached-slot
        ;; Cache hit: reload in 1 instruction
        (ectx-emit ctx (whistler/bpf:emit-ldx-mem
                         whistler/bpf:+bpf-dw+ dst-reg
                         whistler/bpf:+bpf-reg-10+ cached-slot))
        ;; No cache: compute normally
        (progn
          (ectx-emit ctx (whistler/bpf:emit-mov64-reg dst-reg whistler/bpf:+bpf-reg-10+))
          (ectx-emit ctx (whistler/bpf:emit-alu64-imm whistler/bpf:+bpf-add+ dst-reg offset))))))

;;; ========== Struct allocation ==========

(defun emit-struct-alloc-insn (ctx dst args)
  "Allocate a contiguous region on the stack (no zeroing — lowering emits
   explicit zero stores, and DSE removes dead ones).
   Returns a pointer (R10 + offset) in DST."
  (let* ((size (imm-arg-value (first args)))
         (offset (ectx-alloc-stack ctx size "struct-alloc"))
         (dst-loc (allocate-vreg ctx dst))
         (dst-reg (if (eq (car dst-loc) :reg) (cadr dst-loc)
                      whistler/bpf:+bpf-reg-1+))
         (ptr-uses (gethash dst (emit-ctx-struct-ptr-uses ctx) 0))
         (stack-home (and (eq (car dst-loc) :stack) (cadr dst-loc))))
    ;; Record struct base offset for direct R10-relative access optimization
    (setf (gethash dst (emit-ctx-struct-offsets ctx)) offset)
    ;; Compute pointer: dst = R10 + offset
    (ectx-emit ctx (whistler/bpf:emit-mov64-reg dst-reg whistler/bpf:+bpf-reg-10+))
    (ectx-emit ctx (whistler/bpf:emit-alu64-imm whistler/bpf:+bpf-add+ dst-reg offset))
    ;; If this struct is used as a map-ptr key 3+ times, cache the pointer
    ;; on the stack for 1-insn reload (saves 1 insn per subsequent use).
    ;; Reuse the vreg's stack home when possible to avoid a duplicate store.
    (when (>= ptr-uses 3)
      (let ((cache-slot (or stack-home (ectx-alloc-stack ctx 8 "pointer cache"))))
        (unless stack-home
          (ectx-emit ctx (whistler/bpf:emit-stx-mem
                           whistler/bpf:+bpf-dw+
                           whistler/bpf:+bpf-reg-10+ dst-reg cache-slot)))
        (setf (gethash offset (emit-ctx-ptr-cache ctx)) cache-slot)))
    (when stack-home
      (ectx-emit ctx (whistler/bpf:emit-stx-mem
                       whistler/bpf:+bpf-dw+
                       whistler/bpf:+bpf-reg-10+ dst-reg stack-home)))))

(defun emit-map-lookup-ptr-insn (ctx dst args)
  "Emit map_lookup_elem where the key is already a pointer to stack data."
  (let* ((map-name (map-arg-name (first args)))
         (ptr-vreg (second args))
         ;; If the key pointer is a struct-alloc with a known stack offset,
         ;; compute R2 = R10 + offset directly (avoids an extra mov)
         (struct-off (and (integerp ptr-vreg)
                          (gethash ptr-vreg (emit-ctx-struct-offsets ctx)))))
    (if struct-off
        ;; Direct: compute R2 from R10 + struct offset
        (progn
          (emit-stack-ptr ctx struct-off whistler/bpf:+bpf-reg-2+)
          (emit-map-fd ctx map-name whistler/bpf:+bpf-reg-1+))
        ;; General: load ptr vreg then set up R1
        (let ((ptr-reg (vreg-to-physical ctx ptr-vreg whistler/bpf:+bpf-reg-2+)))
          (unless (= ptr-reg whistler/bpf:+bpf-reg-2+)
            (ectx-emit ctx (whistler/bpf:emit-mov64-reg
                             whistler/bpf:+bpf-reg-2+ ptr-reg)))
          (emit-map-fd ctx map-name whistler/bpf:+bpf-reg-1+)))
    ;; call bpf_map_lookup_elem
    (ectx-emit ctx (whistler/bpf:emit-call whistler/bpf:+bpf-func-map-lookup-elem+))
    (store-to-vreg ctx dst whistler/bpf:+bpf-reg-0+)))

(defun emit-map-lookup-insn (ctx dst args)
  (let* ((map-name (map-arg-name (first args)))
         (key-vreg (second args))
         (key-offset (emit-key-to-stack ctx key-vreg)))
    ;; R1 = map fd
    (emit-map-fd ctx map-name whistler/bpf:+bpf-reg-1+)
    ;; R2 = &key
    (emit-stack-ptr ctx key-offset whistler/bpf:+bpf-reg-2+)
    ;; call map_lookup_elem
    (ectx-emit ctx (whistler/bpf:emit-call whistler/bpf:+bpf-func-map-lookup-elem+))
    ;; Result in R0
    (store-to-vreg ctx dst whistler/bpf:+bpf-reg-0+)))

(defun emit-map-update-insn (ctx dst args)
  (let* ((map-name (map-arg-name (first args)))
         (key-vreg (second args))
         (val-vreg (third args))
         (flags-arg (fourth args))
         ;; Store key and val to stack first
         (key-offset (emit-key-to-stack ctx key-vreg))
         (val-offset (emit-key-to-stack ctx val-vreg)))
    ;; Load flags into R4 BEFORE r1-r3 setup clobbers caller-saved registers
    (let ((flags-imm (imm-arg-value flags-arg)))
      (if flags-imm
          ;; Immediate flags value
          (ectx-emit ctx (whistler/bpf:emit-mov64-imm whistler/bpf:+bpf-reg-4+ flags-imm))
          ;; Vreg flags value
          (let ((flags-reg (vreg-to-physical ctx flags-arg whistler/bpf:+bpf-reg-4+)))
            (unless (= flags-reg whistler/bpf:+bpf-reg-4+)
              (ectx-emit ctx (whistler/bpf:emit-mov64-reg whistler/bpf:+bpf-reg-4+ flags-reg))))))
    ;; Now setup r1-r3 (clobbers r1, r2, r3)
    (emit-map-fd ctx map-name whistler/bpf:+bpf-reg-1+)
    (emit-stack-ptr ctx key-offset whistler/bpf:+bpf-reg-2+)
    (emit-stack-ptr ctx val-offset whistler/bpf:+bpf-reg-3+)
    (ectx-emit ctx (whistler/bpf:emit-call whistler/bpf:+bpf-func-map-update-elem+))
    (when dst (store-to-vreg ctx dst whistler/bpf:+bpf-reg-0+))))

(defun emit-map-update-ptr-insn (ctx dst args)
  "Emit map_update_elem where key AND value are already pointers to stack data."
  (let* ((map-name (map-arg-name (first args)))
         (key-vreg (second args))
         (val-vreg (third args))
         (flags-arg (fourth args)))
    ;; Load flags into R4 BEFORE r1-r3 setup
    (let ((flags-imm (imm-arg-value flags-arg)))
      (if flags-imm
          (ectx-emit ctx (whistler/bpf:emit-mov64-imm whistler/bpf:+bpf-reg-4+ flags-imm))
          (let ((flags-reg (vreg-to-physical ctx flags-arg whistler/bpf:+bpf-reg-4+)))
            (unless (= flags-reg whistler/bpf:+bpf-reg-4+)
              (ectx-emit ctx (whistler/bpf:emit-mov64-reg whistler/bpf:+bpf-reg-4+ flags-reg))))))
    ;; Move key/val pointers to R2/R3 FIRST (before ld_pseudo clobbers R1)
    (let ((key-off (and (integerp key-vreg)
                        (gethash key-vreg (emit-ctx-struct-offsets ctx))))
          (val-off (and (integerp val-vreg)
                        (gethash val-vreg (emit-ctx-struct-offsets ctx)))))
      (if key-off
          (emit-stack-ptr ctx key-off whistler/bpf:+bpf-reg-2+)
          (let ((key-reg (vreg-to-physical ctx key-vreg whistler/bpf:+bpf-reg-2+)))
            (unless (= key-reg whistler/bpf:+bpf-reg-2+)
              (ectx-emit ctx (whistler/bpf:emit-mov64-reg whistler/bpf:+bpf-reg-2+ key-reg)))))
      (if val-off
          (emit-stack-ptr ctx val-off whistler/bpf:+bpf-reg-3+)
          (let ((val-reg (vreg-to-physical ctx val-vreg whistler/bpf:+bpf-reg-3+)))
            (unless (= val-reg whistler/bpf:+bpf-reg-3+)
              (ectx-emit ctx (whistler/bpf:emit-mov64-reg whistler/bpf:+bpf-reg-3+ val-reg)))))
      ;; R1 = map fd (after key/val are safe in R2/R3)
      (emit-map-fd ctx map-name whistler/bpf:+bpf-reg-1+))
    (ectx-emit ctx (whistler/bpf:emit-call whistler/bpf:+bpf-func-map-update-elem+))
    (when dst (store-to-vreg ctx dst whistler/bpf:+bpf-reg-0+))))

(defun emit-map-delete-ptr-insn (ctx dst args)
  "Emit map_delete_elem where the key is already a pointer to stack data."
  (let* ((map-name (map-arg-name (first args)))
         (ptr-vreg (second args))
         (struct-off (and (integerp ptr-vreg)
                          (gethash ptr-vreg (emit-ctx-struct-offsets ctx)))))
    (if struct-off
        (progn
          (emit-stack-ptr ctx struct-off whistler/bpf:+bpf-reg-2+)
          (emit-map-fd ctx map-name whistler/bpf:+bpf-reg-1+))
        (let ((ptr-reg (vreg-to-physical ctx ptr-vreg whistler/bpf:+bpf-reg-2+)))
          (unless (= ptr-reg whistler/bpf:+bpf-reg-2+)
            (ectx-emit ctx (whistler/bpf:emit-mov64-reg whistler/bpf:+bpf-reg-2+ ptr-reg)))
          (emit-map-fd ctx map-name whistler/bpf:+bpf-reg-1+)))
    (ectx-emit ctx (whistler/bpf:emit-call whistler/bpf:+bpf-func-map-delete-elem+))
    (when dst (store-to-vreg ctx dst whistler/bpf:+bpf-reg-0+))))

(defun emit-map-delete-insn (ctx dst args)
  (let* ((map-name (map-arg-name (first args)))
         (key-vreg (second args))
         (key-offset (emit-key-to-stack ctx key-vreg)))
    (emit-map-fd ctx map-name whistler/bpf:+bpf-reg-1+)
    (emit-stack-ptr ctx key-offset whistler/bpf:+bpf-reg-2+)
    (ectx-emit ctx (whistler/bpf:emit-call whistler/bpf:+bpf-func-map-delete-elem+))
    (when dst (store-to-vreg ctx dst whistler/bpf:+bpf-reg-0+))))

(defun emit-map-lookup-delete-insn (ctx dst args)
  "Emit bpf_map_lookup_and_delete_elem — fused lookup + delete in one call."
  (let* ((map-name (map-arg-name (first args)))
         (key-vreg (second args))
         (key-offset (emit-key-to-stack ctx key-vreg)))
    (emit-map-fd ctx map-name whistler/bpf:+bpf-reg-1+)
    (emit-stack-ptr ctx key-offset whistler/bpf:+bpf-reg-2+)
    (ectx-emit ctx (whistler/bpf:emit-call whistler/bpf:+bpf-func-map-lookup-and-delete-elem+))
    (when dst (store-to-vreg ctx dst whistler/bpf:+bpf-reg-0+))))

;;; ========== Ring buffer emission ==========

(defun vreg-imm-or-const (ctx vreg)
  "Return the immediate value for VREG if it's (:imm N) or a const-propagated vreg."
  (or (imm-arg-value vreg)
      (and (integerp vreg) (gethash vreg (emit-ctx-const-values ctx)))))

(defun emit-vreg-to-reg (ctx vreg dst-reg)
  "Emit code to move VREG's value into DST-REG, handling immediates and const vregs."
  (let ((imm (vreg-imm-or-const ctx vreg)))
    (if imm
        (ectx-emit ctx (whistler/bpf:emit-mov64-imm dst-reg imm))
        (let ((r (vreg-to-physical ctx vreg dst-reg)))
          (unless (= r dst-reg)
            (ectx-emit ctx (whistler/bpf:emit-mov64-reg dst-reg r)))))))

(defun emit-ringbuf-reserve-insn (ctx dst args)
  "Emit bpf_ringbuf_reserve(map, size, flags) — returns pointer or NULL.
   IMPORTANT: Set up R3 and R2 BEFORE R1. The ld_imm64 for the map fd
   writes to R1, clobbering any value the register allocator placed there."
  (let* ((map-name (map-arg-name (first args)))
         (size-vreg (second args))
         (flags-vreg (third args)))
    ;; R3 = flags (first — safe from clobber)
    (emit-vreg-to-reg ctx flags-vreg whistler/bpf:+bpf-reg-3+)
    ;; R2 = size (before R1 clobber)
    (emit-vreg-to-reg ctx size-vreg whistler/bpf:+bpf-reg-2+)
    ;; R1 = map fd (last — ld_imm64 clobbers R1)
    (emit-map-fd ctx map-name whistler/bpf:+bpf-reg-1+)
    (ectx-emit ctx (whistler/bpf:emit-call 131))  ; bpf_ringbuf_reserve
    (when dst (store-to-vreg ctx dst whistler/bpf:+bpf-reg-0+))))

(defun emit-ringbuf-submit-insn (ctx dst args)
  "Emit bpf_ringbuf_submit(data, flags).
   After submit, the ringbuf pointer is consumed. We emit mov r0, 0
   to ensure a valid return value since submit returns void and
   the peephole may eliminate a later mov r0, 0."
  (let ((data-vreg (first args))
        (flags-vreg (second args)))
    ;; R2 = flags (before R1 in case data is in R2)
    (emit-vreg-to-reg ctx flags-vreg whistler/bpf:+bpf-reg-2+)
    ;; R1 = data pointer
    (let ((r (vreg-to-physical ctx data-vreg whistler/bpf:+bpf-reg-1+)))
      (unless (= r whistler/bpf:+bpf-reg-1+)
        (ectx-emit ctx (whistler/bpf:emit-mov64-reg whistler/bpf:+bpf-reg-1+ r))))
    (ectx-emit ctx (whistler/bpf:emit-call 132))  ; bpf_ringbuf_submit
    ;; Emit mov r0, 0 — submit is void and clobbers R0.
    ;; Without this, the verifier sees R0 as uninitialized on exit.
    (ectx-emit ctx (whistler/bpf:emit-mov64-imm whistler/bpf:+bpf-reg-0+ 0))
    (when dst (store-to-vreg ctx dst whistler/bpf:+bpf-reg-0+))))

(defun emit-ringbuf-discard-insn (ctx dst args)
  "Emit bpf_ringbuf_discard(data, flags)."
  (let ((data-vreg (first args))
        (flags-vreg (second args)))
    (let ((r (vreg-to-physical ctx data-vreg whistler/bpf:+bpf-reg-1+)))
      (unless (= r whistler/bpf:+bpf-reg-1+)
        (ectx-emit ctx (whistler/bpf:emit-mov64-reg whistler/bpf:+bpf-reg-1+ r))))
    (let ((flags-imm (imm-arg-value flags-vreg)))
      (if flags-imm
          (ectx-emit ctx (whistler/bpf:emit-mov64-imm whistler/bpf:+bpf-reg-2+ flags-imm))
          (let ((r (vreg-to-physical ctx flags-vreg whistler/bpf:+bpf-reg-2+)))
            (unless (= r whistler/bpf:+bpf-reg-2+)
              (ectx-emit ctx (whistler/bpf:emit-mov64-reg whistler/bpf:+bpf-reg-2+ r))))))
    (ectx-emit ctx (whistler/bpf:emit-call 133))  ; bpf_ringbuf_discard
    (when dst (store-to-vreg ctx dst whistler/bpf:+bpf-reg-0+))))

;;; ========== Tail call emission ==========

(defun emit-tail-call-insn (ctx dst args)
  "Emit bpf_tail_call(ctx, prog_array, index).
   Args: ((:map MAP-NAME) ctx-vreg index-vreg).
   Register setup: R1=ctx, R2=prog_array map FD, R3=index."
  (let ((map-name (map-arg-name (first args)))
        (ctx-vreg (second args))
        (idx-vreg (third args)))
    ;; Load index into R3 first (safe from map FD clobber)
    (emit-vreg-to-reg ctx idx-vreg whistler/bpf:+bpf-reg-3+)
    ;; Load map FD into R2 (ld_imm64 is 2 insns, doesn't touch R3)
    (emit-map-fd ctx map-name whistler/bpf:+bpf-reg-2+)
    ;; Load ctx into R1
    (let ((ctx-reg (vreg-to-physical ctx ctx-vreg whistler/bpf:+bpf-reg-1+)))
      (unless (= ctx-reg whistler/bpf:+bpf-reg-1+)
        (ectx-emit ctx (whistler/bpf:emit-mov64-reg
                         whistler/bpf:+bpf-reg-1+ ctx-reg))))
    ;; call bpf_tail_call (helper 12)
    (ectx-emit ctx (whistler/bpf:emit-call 12))
    ;; If tail call fails, R0 is undefined — set to 0 for safety
    (ectx-emit ctx (whistler/bpf:emit-mov64-imm whistler/bpf:+bpf-reg-0+ 0))
    (when dst (store-to-vreg ctx dst whistler/bpf:+bpf-reg-0+))))

;;; ========== Helper call emission ==========

(defun resolve-parallel-moves (ctx moves)
  "Resolve a set of parallel register moves, emitting them in an order that
   avoids clobbering.  Each move is (dst-reg . src), where src is one of:
     (:imm value)    - immediate constant
     (:reg phys-reg) - value in a physical register
     (:stack offset) - value spilled to stack at [R10+offset]
   Uses R0 as scratch to break cycles (safe: the upcoming CALL clobbers R0)."
  (let ((pending (copy-list moves))
        (tmp whistler/bpf:+bpf-reg-0+))
    ;; A move is "safe" if its source won't be clobbered by other pending moves.
    ;; Immediates and stack loads are always safe (no register conflict).
    ;; A register source is safe if no pending move targets that register.
    (loop
      (let ((safe (find-if
                   (lambda (m)
                     (let ((src (cdr m)))
                       (or (eq (car src) :imm)
                           (eq (car src) :stack)
                           (not (find (cadr src) pending :key #'car)))))
                   pending)))
        (cond
          (safe
           (setf pending (remove safe pending :test #'eq))
           (destructuring-bind (dst . src) safe
             (ecase (car src)
               (:imm (ectx-emit ctx (whistler/bpf:emit-mov64-imm dst (cadr src))))
               (:stack (ectx-emit ctx (whistler/bpf:emit-ldx-mem
                                       whistler/bpf:+bpf-dw+ dst
                                       whistler/bpf:+bpf-reg-10+ (cadr src))))
               (:reg (unless (= dst (cadr src))
                       (ectx-emit ctx (whistler/bpf:emit-mov64-reg dst (cadr src))))))))
          ;; No safe move — must be a register cycle. Break via R0 temp.
          (pending
           (let* ((m (first pending))
                  (src-reg (cadr (cdr m))))
             ;; Save one source to R0, redirect all reads from that register
             (ectx-emit ctx (whistler/bpf:emit-mov64-reg tmp src-reg))
             (dolist (p pending)
               (when (and (eq (car (cdr p)) :reg)
                          (= (cadr (cdr p)) src-reg))
                 (setf (cdr p) (list :reg tmp))))))
          (t (return)))))))

(defun emit-call-insn (ctx dst args)
  "Emit a BPF helper call. Load arguments into R1-R5 using parallel-move
   resolution to avoid clobbering when argument registers overlap."
  (let ((func-id (helper-arg-id (first args)))
        (call-args (rest args)))
    ;; Build move list: (target-reg . (:imm val) or (:reg src-reg))
    ;; For stack-spilled vregs, load them first without using any target
    ;; register — use allocate-vreg to find the source location.
    (let ((moves (loop for vreg in call-args
                       for reg from whistler/bpf:+bpf-reg-1+
                       collect (let ((imm (vreg-imm-or-const ctx vreg)))
                                 (if imm
                                     (cons reg (list :imm imm))
                                     (let ((loc (allocate-vreg ctx vreg)))
                                       (ecase (car loc)
                                         (:reg (cons reg (list :reg (cadr loc))))
                                         (:stack
                                          ;; Stack spill: encode as (:stack offset)
                                          ;; for resolve-parallel-moves to handle
                                          (cons reg (list :stack (cadr loc)))))))))))
      (resolve-parallel-moves ctx moves))
    (ectx-emit ctx (whistler/bpf:emit-call func-id))
    (when dst (store-to-vreg ctx dst whistler/bpf:+bpf-reg-0+))))

;;; ========== Log2 emission ==========

(defun emit-log2-insn (ctx dst args)
  (let* ((val-reg (vreg-to-physical ctx (first args) whistler/bpf:+bpf-reg-1+))
         (dst-loc (allocate-vreg ctx dst))
         (dst-reg (if (eq (car dst-loc) :reg) (cadr dst-loc) whistler/bpf:+bpf-reg-2+))
         ;; work-reg holds the value being shifted during binary search.
         ;; It MUST differ from dst-reg to avoid clobbering on init.
         (work-reg (cond
                     ((/= val-reg dst-reg) val-reg)
                     ;; val-reg == dst-reg: pick a scratch register
                     ((/= dst-reg whistler/bpf:+bpf-reg-1+) whistler/bpf:+bpf-reg-1+)
                     (t whistler/bpf:+bpf-reg-2+))))
    ;; Copy val to work register if needed
    (unless (= val-reg work-reg)
      (ectx-emit ctx (whistler/bpf:emit-mov64-reg work-reg val-reg)))
    ;; Initialize result to 0
    (ectx-emit ctx (whistler/bpf:emit-mov64-imm dst-reg 0))
    ;; Unrolled binary search
    (dolist (step '((65536 16) (256 8) (16 4) (4 2)))
      (destructuring-bind (threshold shift) step
        (ectx-emit ctx (whistler/bpf:emit-jmp-imm whistler/bpf:+bpf-jlt+ work-reg threshold 2))
        (ectx-emit ctx (whistler/bpf:emit-alu64-imm whistler/bpf:+bpf-rsh+ work-reg shift))
        (ectx-emit ctx (whistler/bpf:emit-alu64-imm whistler/bpf:+bpf-add+ dst-reg shift))))
    (ectx-emit ctx (whistler/bpf:emit-jmp-imm whistler/bpf:+bpf-jlt+ work-reg 2 1))
    (ectx-emit ctx (whistler/bpf:emit-alu64-imm whistler/bpf:+bpf-add+ dst-reg 1))
    ;; Store if on stack
    (when (eq (car dst-loc) :stack)
      (ectx-emit ctx (whistler/bpf:emit-stx-mem
                       whistler/bpf:+bpf-dw+
                       whistler/bpf:+bpf-reg-10+ dst-reg (cadr dst-loc))))))

;;; ========== Cast emission ==========

(defun emit-cast-insn (ctx dst args)
  (let* ((src-reg (vreg-to-physical ctx (first args) whistler/bpf:+bpf-reg-1+))
         (type-kw (type-arg-name (second args)))
         (dst-loc (allocate-vreg ctx dst))
         (dst-reg (if (eq (car dst-loc) :reg) (cadr dst-loc) whistler/bpf:+bpf-reg-1+)))
    (unless (= src-reg dst-reg)
      (ectx-emit ctx (whistler/bpf:emit-mov64-reg dst-reg src-reg)))
    (let ((name (string-upcase (string type-kw))))
      (cond
        ((or (string= name "U8")  (string= name "I8"))
         (ectx-emit ctx (whistler/bpf:emit-alu64-imm whistler/bpf:+bpf-and+ dst-reg #xff)))
        ((or (string= name "U16") (string= name "I16"))
         (ectx-emit ctx (whistler/bpf:emit-alu64-imm whistler/bpf:+bpf-and+ dst-reg #xffff)))
        ((or (string= name "U32") (string= name "I32"))
         ;; mov32 dst, dst — register-to-register 32-bit move zero-extends
         (ectx-emit ctx (whistler/bpf:emit-alu32-reg whistler/bpf:+bpf-mov+ dst-reg dst-reg)))))
    (when (eq (car dst-loc) :stack)
      (ectx-emit ctx (whistler/bpf:emit-stx-mem
                       whistler/bpf:+bpf-dw+
                       whistler/bpf:+bpf-reg-10+ dst-reg (cadr dst-loc))))))

;;; ========== Byte swap emission ==========

(defun emit-bswap-insn (ctx op dst args)
  (let* ((src-reg (vreg-to-physical ctx (first args) whistler/bpf:+bpf-reg-1+))
         (dst-loc (allocate-vreg ctx dst))
         (dst-reg (if (eq (car dst-loc) :reg) (cadr dst-loc) whistler/bpf:+bpf-reg-1+)))
    (unless (= src-reg dst-reg)
      (ectx-emit ctx (whistler/bpf:emit-mov64-reg dst-reg src-reg)))
    (ecase op
      (:bswap16 (ectx-emit ctx (whistler/bpf:emit-bswap16 dst-reg)))
      (:bswap32 (ectx-emit ctx (whistler/bpf:emit-bswap32 dst-reg)))
      (:bswap64 (ectx-emit ctx (whistler/bpf:emit-bswap64 dst-reg))))
    (when (eq (car dst-loc) :stack)
      (ectx-emit ctx (whistler/bpf:emit-stx-mem
                       whistler/bpf:+bpf-dw+
                       whistler/bpf:+bpf-reg-10+ dst-reg (cadr dst-loc))))))

;;; ========== Branch condition emission ==========

(defun emit-br-cond-insn (ctx args)
  (let* ((cmp-op (cmp-arg-op (first args)))
         (bpf-jmp (ir-cmp-to-bpf-jmp cmp-op))
         (lhs (second args))
         (rhs (third args))
         (then-label (label-arg-name (fourth args)))
         (else-label (label-arg-name (fifth args)))
         (lhs-reg (if (integerp lhs)
                      (vreg-to-physical ctx lhs whistler/bpf:+bpf-reg-1+)
                      whistler/bpf:+bpf-reg-1+)))
    ;; Emit: if cond goto then; goto else
    (let ((imm (imm-arg-value rhs)))
      (if (and imm (typep imm '(signed-byte 32)))
          (progn
            (push (list (ectx-current-idx ctx) then-label) (emit-ctx-fixups ctx))
            (ectx-emit ctx (whistler/bpf:emit-jmp-imm bpf-jmp lhs-reg imm 0)))
          (let ((rhs-reg (if (integerp rhs)
                             (vreg-to-physical ctx rhs whistler/bpf:+bpf-reg-2+)
                             whistler/bpf:+bpf-reg-2+)))
            (push (list (ectx-current-idx ctx) then-label) (emit-ctx-fixups ctx))
            (ectx-emit ctx (whistler/bpf:emit-jmp-reg bpf-jmp lhs-reg rhs-reg 0)))))
    ;; Unconditional jump to else
    (push (list (ectx-current-idx ctx) else-label) (emit-ctx-fixups ctx))
    (ectx-emit ctx (whistler/bpf:emit-jmp-a 0))))
