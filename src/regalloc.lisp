;;; -*- Mode: Lisp -*-
;;;
;;; Copyright (c) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; SPDX-License-Identifier: MIT

;;; regalloc.lisp — Linear-scan register allocator for SSA IR
;;;
;;; Computes liveness intervals for each vreg, then allocates physical
;;; registers using linear scan with two pools:
;;;   - Callee-saved (R6-R9): for vregs live across helper calls
;;;   - Caller-saved (R1-R5): for vregs NOT live across calls
;;;
;;; R0 is reserved for helper return values and program exit.
;;; R6 is reserved for ctx if needed.
;;; R10 is the frame pointer (immutable).

(in-package #:whistler/ir)

;;; ========== Liveness intervals ==========

(defstruct live-interval
  vreg              ; virtual register number
  start             ; first definition (instruction position)
  end               ; last use (instruction position)
  spans-call-p      ; t if interval contains a helper call
  (phys nil)        ; allocated physical location: (:reg N) or (:stack OFF)
  (value-class :temporary)  ; :packet-ptr, :hot-scalar, :recomputable,
                            ; :temporary, :helper-setup
  (rematerializable-p nil)  ; t if cheaper to recreate than preserve
  (remat-recipe nil)        ; original ir-insn for rematerialization
  (def-insn nil))            ; defining IR instruction (for operand-aware alloc)

(defun classify-vreg (insn)
  "Classify a vreg based on its defining instruction.
   Returns (values value-class rematerializable-p remat-recipe)."
  (let ((op (ir-insn-op insn)))
    (case op
      ;; Context/packet pointers — expensive, protect
      (:ctx-load (values :packet-ptr nil nil))
      ;; Constants — cheap to recreate
      (:mov
       (let ((args (ir-insn-args insn)))
         (if (and (= (length args) 1)
                  (consp (first args))
                  (eq (car (first args)) :imm))
             (values :recomputable t insn)
             (values :temporary nil nil))))
      ;; Map fd loads — helper setup, can be redone
      (:map-fd (values :helper-setup nil nil))
      ;; Map operations produce important results
      ((:map-lookup :map-lookup-ptr :map-lookup-delete :ringbuf-reserve)
       (values :hot-scalar nil nil))
      ;; Add with immediate — recomputable if base is still live
      (:add
       (let ((args (ir-insn-args insn)))
         (if (and (= (length args) 2)
                  (integerp (first args))
                  (consp (second args))
                  (eq (car (second args)) :imm))
             (values :recomputable t insn)
             (values :temporary nil nil))))
      ;; Struct-alloc — always recomputable (R10 + known offset)
      (:struct-alloc (values :recomputable t insn))
      ;; Stack-addr — always recomputable (R10 + compile-time offset)
      (:stack-addr (values :recomputable t insn))
      ;; Loads from memory — result of actual work
      (:load (values :hot-scalar nil nil))
      ;; Everything else
      (otherwise (values :temporary nil nil)))))

(defun compute-liveness (prog)
  "Compute liveness intervals for all vregs in PROG.
   Returns a list of live-interval structs, sorted by start position.
   Truncates liveness for vregs whose only uses are stack-addr (buffer variables)
   since emit-key-to-stack caches the value on first access."
  (let ((def-pos (make-hash-table))    ; vreg → first definition position
        (last-use (make-hash-table))   ; vreg → last use position
        (call-positions '())            ; list of positions where calls happen
        (first-stack-addr (make-hash-table))  ; vreg → first stack-addr use position
        (has-non-stack-use (make-hash-table)) ; vreg → t if used outside stack-addr
        (def-insn (make-hash-table))   ; vreg → defining instruction
        (pos 0))

    ;; Walk all instructions in block order, assigning positions
    (dolist (block (ir-program-blocks prog))
      (dolist (insn (basic-block-insns block))
        ;; Record definitions
        (when (ir-insn-dst insn)
          (unless (gethash (ir-insn-dst insn) def-pos)
            (setf (gethash (ir-insn-dst insn) def-pos) pos)
            (setf (gethash (ir-insn-dst insn) def-insn) insn)))

        ;; Record uses, tracking stack-addr vs other uses
        (dolist (vreg (ir-insn-all-vreg-uses insn))
          (setf (gethash vreg last-use) pos)
          (if (eq (ir-insn-op insn) :stack-addr)
              ;; Track first stack-addr use
              (unless (gethash vreg first-stack-addr)
                (setf (gethash vreg first-stack-addr) pos))
              ;; Non-stack-addr use
              (setf (gethash vreg has-non-stack-use) t)))

        ;; Record call positions
        (when (call-like-op-p (ir-insn-op insn))
          (push pos call-positions))

        (incf pos)))

    (setf call-positions (nreverse call-positions))

    ;; Build intervals with value classification
    (let ((intervals '()))
      (maphash (lambda (vreg def)
                 (let* ((raw-end (or (gethash vreg last-use) def))
                        ;; Truncate liveness for buffer vregs: if only used
                        ;; by stack-addr, end at first stack-addr (register
                        ;; value is stored to stack and cached after that)
                        (end (if (and (gethash vreg first-stack-addr)
                                      (not (gethash vreg has-non-stack-use)))
                                 (gethash vreg first-stack-addr)
                                 raw-end))
                        (spans (some (lambda (cp) (and (> cp def) (< cp end)))
                                     call-positions))
                        (insn (gethash vreg def-insn)))
                   (multiple-value-bind (vclass remat-p recipe)
                       (if insn (classify-vreg insn) (values :temporary nil nil))
                     (push (make-live-interval :vreg vreg :start def :end end
                                               :spans-call-p spans
                                               :value-class vclass
                                               :rematerializable-p remat-p
                                               :remat-recipe recipe
                                               :def-insn insn)
                           intervals))))
               def-pos)

      ;; Sort by start position
      (sort intervals #'< :key #'live-interval-start))))

;;; ========== Operand-aware register preference ==========

(defun binary-alu-op-p (op)
  "Is OP a binary ALU operation?"
  (member op '(:add :sub :mul :div :mod :and :or :xor :lsh :rsh :arsh)))

(defun preferred-register (interval result)
  "If INTERVAL's vreg is defined by a binary ALU op, return the physical
   register of its LHS operand (or either operand for commutative ops),
   or NIL if no preference can be determined."
  (let ((insn (live-interval-def-insn interval)))
    (when (and insn (binary-alu-op-p (ir-insn-op insn)))
      (let ((args (ir-insn-args insn)))
        (when (and (= (length args) 2) (integerp (first args)))
          ;; Check LHS operand location
          (let ((lhs-loc (gethash (first args) result)))
            (when (and lhs-loc (eq (car lhs-loc) :reg))
              (return-from preferred-register (cadr lhs-loc))))
          ;; For commutative ops, also check RHS
          (when (and (member (ir-insn-op insn) '(:add :mul :and :or :xor))
                     (integerp (second args)))
            (let ((rhs-loc (gethash (second args) result)))
              (when (and rhs-loc (eq (car rhs-loc) :reg))
                (cadr rhs-loc)))))))))

(defun avoided-register (interval result)
  "For non-commutative ALU ops, return the RHS operand's register.
   Allocating the destination to that register forces an evacuate in
   the emitter (Case 3: rhs in work-reg).  Skipping it saves 1 insn."
  (let ((insn (live-interval-def-insn interval)))
    (when (and insn (binary-alu-op-p (ir-insn-op insn))
               (not (member (ir-insn-op insn) '(:add :mul :and :or :xor))))
      (let ((args (ir-insn-args insn)))
        (when (and (= (length args) 2) (integerp (second args)))
          (let ((rhs-loc (gethash (second args) result)))
            (when (and rhs-loc (eq (car rhs-loc) :reg))
              (cadr rhs-loc))))))))

(defun pick-register (preferred avoid free-list)
  "Pick a register from FREE-LIST.  Prefer PREFERRED; avoid AVOID
   (to prevent emitter Case 3 evacuate on non-commutative ops).
   Returns (values reg new-free-list)."
  (cond
    ;; Preferred register available — use it
    ((and preferred (member preferred free-list))
     (values preferred (remove preferred free-list :count 1)))
    ;; Avoid a register — skip it if it would be picked first
    ((and avoid (eql avoid (car free-list)) (cdr free-list))
     (values (cadr free-list)
             (cons (car free-list) (cddr free-list))))
    ;; Default: first available
    (t (values (car free-list) (cdr free-list)))))

;;; ========== Linear-scan allocator ==========

(defun map-fd-cache-savings (prog)
  "Estimate instruction savings from map-fd caching.
   Returns the savings for the most-referenced map (each cached use
   saves 1 instruction vs ld_pseudo).  Requires >= 3 references
   to be profitable (1st use = ld_pseudo + mov-to-cache, subsequent = mov)."
  (let ((max-refs 0))
    (dolist (block (ir-program-blocks prog))
      (dolist (insn (basic-block-insns block))
        (when (member (ir-insn-op insn)
                      '(:map-lookup :map-lookup-ptr :map-lookup-delete
                        :map-update :map-update-ptr :map-delete :map-delete-ptr))
          (let ((map-arg (first (ir-insn-args insn))))
            (declare (ignore map-arg))
            (incf max-refs)))))
    ;; Each map ref uses ld_pseudo (2 insns).  Caching: first = 2+1, rest = 1 each.
    ;; But we need per-map counts.  Simple estimate: total refs across all maps.
    ;; Savings = (total_refs - num_distinct_maps) since each map's first use isn't cached.
    ;; Actually, just use the approach from emit.lisp: count per map.
    (let ((counts (make-hash-table)))
      (dolist (block (ir-program-blocks prog))
        (dolist (insn (basic-block-insns block))
          (when (member (ir-insn-op insn)
                        '(:map-lookup :map-lookup-ptr :map-lookup-delete
                          :map-update :map-update-ptr :map-delete :map-delete-ptr))
            (let ((map-arg (first (ir-insn-args insn))))
              (when (and (consp map-arg) (eq (car map-arg) :map))
                (incf (gethash (cadr map-arg) counts 0)))))))
      (setf max-refs 0)
      (maphash (lambda (name count)
                 (declare (ignore name))
                 (when (>= count 3)
                   (setf max-refs (max max-refs (1- count)))))
               counts))
    max-refs))

(defun linear-scan-alloc (prog &key ctx-early reserve-callee-count auto-reserve-helper-setup)
  "Allocate physical registers for all vregs in PROG.
   CTX-EARLY means ctx-loads happen before any calls, so R1 can be used
   directly and R6 is free for general allocation.
   RESERVE-CALLEE-COUNT hard-reserves that many callee-saved registers for
   helper setup/caching. When NIL, AUTO-RESERVE-HELPER-SETUP controls the
   existing heuristic that may preserve one call-safe register opportunistically.
   Returns a hash table: vreg → (:reg N) or (:stack OFF)."
  (let* ((intervals (compute-liveness prog))
         (ctx-vreg (find-ctx-vreg prog))
         (ctx-used (and ctx-vreg (vreg-used-p prog ctx-vreg)))
         (ctx-needs-save (and ctx-used (not ctx-early)))
         ;; Register pools — R6 free when ctx doesn't need saving
         (all-callee (if ctx-needs-save '(7 8 9) '(6 7 8 9)))
         (reserved-callee-count (or reserve-callee-count 0))
         (callee-free (subseq all-callee 0
                              (max 0 (- (length all-callee) reserved-callee-count))))
         ;; R0 is reserved for return values — never allocate it.
         ;; When ctx-early, R1 holds the live ctx pointer — exclude it too.
         (caller-free (if (and ctx-vreg ctx-used ctx-early)
                          '(2 3 4 5)
                          '(1 2 3 4 5)))
         ;; Reserve a callee-saved register for map-fd caching when
         ;; the savings outweigh the cost of spilling one recomputable value.
         ;; Cost of spill: ~2 insns (recompute at each use, typically 1-2 uses).
         ;; Savings from caching: (refs - 1) insns for the most-used map.
         (cache-savings (map-fd-cache-savings prog))
         (reserve-for-cache (and (null reserve-callee-count)
                                 auto-reserve-helper-setup
                                 (> cache-savings 2)))
         (callee-reserved reserved-callee-count)
         ;; Active intervals (sorted by end position)
         (callee-active '())
         (caller-active '())
         ;; Stack for spills
         (stack-offset 0)
         ;; Result
         (result (make-hash-table)))

    ;; Pre-assign ctx vreg: R6 if needs save, R1 if early (stays in entry reg)
    (when (and ctx-vreg ctx-used)
      (if ctx-early
          (setf (gethash ctx-vreg result) '(:reg 1))
          (setf (gethash ctx-vreg result) '(:reg 6))))

    ;; Add the ctx interval to the appropriate active set so it blocks
    ;; other intervals from being assigned the same register.
    ;; When ctx is saved to R6, extend the interval to cover the entire
    ;; program so R6 is never freed — the emitter uses R6 for all ctx-loads.
    (when (and ctx-vreg ctx-used)
      (let ((ctx-interval (find ctx-vreg intervals :key #'live-interval-vreg)))
        (when ctx-interval
          (when ctx-needs-save
            (setf (live-interval-end ctx-interval) most-positive-fixnum))
          (setf (live-interval-phys ctx-interval)
                (if ctx-early '(:reg 1) '(:reg 6)))
          (if (or ctx-needs-save (live-interval-spans-call-p ctx-interval))
              (setf callee-active (insert-by-end ctx-interval callee-active))
              (setf caller-active (insert-by-end ctx-interval caller-active))))))

    (dolist (interval intervals)
      (let ((vreg (live-interval-vreg interval)))
        ;; Skip ctx vreg (already assigned)
        (when (and ctx-vreg (= vreg ctx-vreg))
          (setf (live-interval-phys interval)
                (if ctx-early '(:reg 1) '(:reg 6))))

        (unless (and ctx-vreg (= vreg ctx-vreg))
          ;; Expire old intervals to free registers
          (multiple-value-setq (callee-active callee-free)
            (expire-intervals callee-active callee-free (live-interval-start interval)))
          (multiple-value-setq (caller-active caller-free)
            (expire-intervals caller-active caller-free (live-interval-start interval)))

          (let ((pref (preferred-register interval result))
                (avoid (avoided-register interval result)))
          (cond
            ;; Needs callee-saved (spans a call)
            ((live-interval-spans-call-p interval)
             (if callee-free
                 ;; Check: should we spill this recomputable interval to
                 ;; preserve a callee-saved register for map-fd caching?
                 (if (and reserve-for-cache
                          (< callee-reserved 1)
                          (live-interval-rematerializable-p interval))
                     ;; Spill this recomputable interval; map-fd caching
                     ;; will save more instructions than the spill costs
                     (progn
                       (incf callee-reserved)
                       (let ((off (alloc-spill-slot stack-offset)))
                         (setf stack-offset off)
                         (setf (live-interval-phys interval) (list :stack off))
                         (setf (gethash vreg result) (list :stack off))))
                 (multiple-value-bind (reg new-free)
                     (pick-register pref avoid callee-free)
                   (setf callee-free new-free)
                   (setf (live-interval-phys interval) (list :reg reg))
                   (setf (gethash vreg result) (list :reg reg))
                   (setf callee-active
                         (insert-by-end interval callee-active))))
                 ;; Spill: pick the cheapest-to-spill interval from active
                 (let ((spill-target (spill-candidate callee-active interval)))
                   (if (and spill-target
                            (or (< (spill-cost spill-target) (spill-cost interval))
                                (> (live-interval-end spill-target)
                                   (live-interval-end interval))))
                       ;; Spill the existing one, give its register to us
                       (let ((reg (cadr (live-interval-phys spill-target))))
                         (setf callee-active (remove spill-target callee-active))
                         (let ((off (alloc-spill-slot stack-offset)))
                           (setf stack-offset off)
                           (setf (live-interval-phys spill-target) (list :stack off))
                           (setf (gethash (live-interval-vreg spill-target) result)
                                 (list :stack off)))
                         (setf (live-interval-phys interval) (list :reg reg))
                         (setf (gethash vreg result) (list :reg reg))
                         (setf callee-active
                               (insert-by-end interval callee-active)))
                       ;; Spill the new interval
                       (let ((off (alloc-spill-slot stack-offset)))
                         (setf stack-offset off)
                         (setf (live-interval-phys interval) (list :stack off))
                         (setf (gethash vreg result) (list :stack off)))))))

            ;; Can use caller-saved (doesn't span a call)
            (t
             (if caller-free
                 (multiple-value-bind (reg new-free)
                     (pick-register pref avoid caller-free)
                   (setf caller-free new-free)
                   (setf (live-interval-phys interval) (list :reg reg))
                   (setf (gethash vreg result) (list :reg reg))
                   (setf caller-active
                         (insert-by-end interval caller-active)))
                 ;; Try callee-saved as overflow
                 (if callee-free
                     (multiple-value-bind (reg new-free)
                         (pick-register pref avoid callee-free)
                       (setf callee-free new-free)
                       (setf (live-interval-phys interval) (list :reg reg))
                       (setf (gethash vreg result) (list :reg reg))
                       (setf callee-active
                             (insert-by-end interval callee-active)))
                     ;; Spill
                     (let ((off (alloc-spill-slot stack-offset)))
                       (setf stack-offset off)
                       (setf (live-interval-phys interval) (list :stack off))
                       (setf (gethash vreg result) (list :stack off)))))))))))

    (values result stack-offset)))

(defun expire-intervals (active free-list current-pos)
  "Remove intervals from ACTIVE that end at or before CURRENT-POS.
   Uses <= because in SSA, when an interval's last use is at position P,
   and a new interval starts at P (defined by the instruction that uses
   the old value), they can safely share a register.
   Returns (values new-active new-free-list)."
  (let ((new-active '())
        (new-free free-list))
    (dolist (interval active)
      (if (<= (live-interval-end interval) current-pos)
          ;; Expired — return register to pool in sorted order
          ;; to maintain deterministic allocation regardless of expiry timing
          (let ((phys (live-interval-phys interval)))
            (when (and phys (eq (car phys) :reg))
              (setf new-free (insert-sorted (cadr phys) new-free))))
          ;; Still active
          (push interval new-active)))
    (values (nreverse new-active) new-free)))

(defun insert-sorted (reg free-list)
  "Insert REG into FREE-LIST maintaining ascending order."
  (if (or (null free-list) (< reg (car free-list)))
      (cons reg free-list)
      (cons (car free-list) (insert-sorted reg (cdr free-list)))))

(defun insert-by-end (interval active)
  "Insert INTERVAL into ACTIVE list sorted by end position."
  (merge 'list (list interval) active #'<
         :key #'live-interval-end))

(defun spill-cost (interval)
  "Return a numeric spill cost for INTERVAL.  Lower = prefer to spill.
   Rematerializable values are cheapest (recreate instead of reload).
   Packet pointers and hot scalars are most expensive."
  (if (live-interval-rematerializable-p interval)
      0
      (ecase (live-interval-value-class interval)
        (:recomputable  1)   ; cheap even without full remat
        (:helper-setup  2)   ; map-fd etc, can redo
        (:temporary     3)
        (:hot-scalar    4)
        (:packet-ptr    5))))

(defun spill-candidate (active new-interval)
  "Find the best interval to spill from ACTIVE.
   Prefer spilling cheap values (rematerializable, helper-setup) over
   expensive ones (packet pointers, hot scalars).  Among equal cost,
   pick the one whose end is farthest away.
   Never spill intervals with infinite end (ctx saved to R6)."
  (declare (ignore new-interval))
  ;; Filter out non-spillable intervals (ctx with infinite lifetime)
  (let ((candidates (remove-if (lambda (i)
                                 (= (live-interval-end i) most-positive-fixnum))
                               active)))
    (when candidates
      (reduce (lambda (a b)
                (let ((ca (spill-cost a))
                      (cb (spill-cost b)))
                  (cond ((< ca cb) a)       ; a is cheaper to spill
                        ((> ca cb) b)       ; b is cheaper to spill
                        (t                  ; same cost — farthest end
                         (if (> (live-interval-end a) (live-interval-end b))
                             a b)))))
              candidates))))

(defun alloc-spill-slot (current-offset)
  "Allocate 8 bytes on the stack. CURRENT-OFFSET is a negative offset (or 0).
   Returns the new negative offset from R10."
  (let ((off (- current-offset 8)))
    (when (< off -512)
      (whistler/compiler:whistler-error
       :what (format nil "stack frame exceeds BPF 512-byte limit during register allocation ~
                          (~d bytes in ~d spill slots)"
                     (- off) (/ (- off) 8))
       :expected "total stack usage <= 512 bytes"
       :hint "reduce struct sizes, reuse buffers, or split logic across tail-called programs"))

    off))
