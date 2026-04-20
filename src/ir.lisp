;;; -*- Mode: Lisp -*-
;;;
;;; Copyright (c) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; SPDX-License-Identifier: MIT

;;; ir.lisp — SSA intermediate representation for Whistler
;;;
;;; Virtual registers are non-negative integers. Basic blocks have labels.
;;; Instructions are in SSA form: each vreg is defined exactly once.

(in-package #:whistler/ir)

;;; IR instruction

(defstruct ir-insn
  (op nil)        ; keyword: :mov, :add, :sub, :mul, :div, :mod,
                  ;   :and, :or, :xor, :lsh, :rsh, :arsh, :neg,
                  ;   :load, :store, :call, :atomic-add,
                  ;   :bswap16, :bswap32, :bswap64, :cast,
                  ;   :phi, :br, :br-cond, :ret,
                  ;   :map-fd, :ctx-load, :map-lookup, :map-update, :map-delete,
                  ;   :log2, :stack-store, :stack-addr
  (dst nil)       ; destination vreg (integer) or nil
  (args '())      ; list of operands: vreg integers, immediates (:imm N),
                  ;   labels (:label sym), map names (:map sym),
                  ;   types (:type sym), helper ids (:helper N)
  (type nil)      ; result type keyword: u8 u16 u32 u64
  (id 0))         ; unique ID for ordering within block

;;; Basic block

(defstruct basic-block
  (label nil)     ; symbol
  (insns '())     ; list of ir-insn (in order)
  (succs '())     ; successor block labels
  (preds '()))    ; predecessor block labels

;;; IR program (output of lowering, input to optimization + regalloc)

(defstruct ir-program
  (blocks '())       ; list of basic-block
  (entry nil)        ; label of entry block
  (next-vreg 0)      ; next virtual register number
  (maps '())         ; list of bpf-map structs (from compilation-unit)
  (map-relocs '())   ; accumulated during emission
  (section "xdp")
  (license "GPL"))

;;; Helpers

(defun ir-fresh-vreg (prog)
  "Allocate a fresh virtual register."
  (prog1 (ir-program-next-vreg prog)
    (incf (ir-program-next-vreg prog))))

(defun ir-fresh-label (prog &optional (prefix "bb"))
  "Generate a unique block label."
  (let ((n (ir-program-next-vreg prog)))
    (incf (ir-program-next-vreg prog))
    (intern (format nil "~a_~d" prefix n) (find-package '#:whistler/ir))))

(defun ir-find-block (prog label)
  "Find block by label."
  (find label (ir-program-blocks prog) :key #'basic-block-label))

(defun ir-add-block (prog block)
  "Add a block to the program."
  (setf (ir-program-blocks prog)
        (nconc (ir-program-blocks prog) (list block))))

(defun bb-emit (block insn)
  "Append an instruction to a basic block."
  (setf (basic-block-insns block)
        (nconc (basic-block-insns block) (list insn))))

(defun bb-terminator-p (block)
  "Does this block have a terminator instruction?"
  (let ((last (car (last (basic-block-insns block)))))
    (and last (member (ir-insn-op last) '(:br :br-cond :ret)))))

(defun ir-insn-vreg-uses (insn)
  "Return list of vreg numbers used by this instruction."
  (loop for arg in (ir-insn-args insn)
        when (integerp arg) collect arg))

(defun ir-insn-side-effect-p (insn)
  "Does this instruction have side effects?"
  (member (ir-insn-op insn)
          '(:call :tail-call :store :ctx-store :stack-store :atomic-add
            :map-update :map-update-ptr :map-delete :map-delete-ptr
            :struct-alloc :br :br-cond :ret
            :ringbuf-reserve :ringbuf-submit :ringbuf-discard
            :ringbuf-output)))

;;; ========== Call-like operations and helper-effect classification ==========
;;;
;;; Shared by ssa-opt.lisp (splitting, hoisting, DSE) and regalloc.lisp.
;;; Each call-like op clobbers caller-saved registers (R0-R5).  Beyond that,
;;; individual BPF helpers have additional effects on pointer validity.
;;;
;;; Effect flags (a list of keywords):
;;;   :clobbers-caller-saved  — always present for call-like ops
;;;   :invalidates-packet-ptrs — packet data/data_end pointers become stale
;;;   :invalidates-map-value-ptrs — map value pointers become stale
;;;   :invalidates-stack-addrs — stack-derived addresses become stale
;;;                              (currently no BPF helper does this)

(defun call-like-op-p (op)
  "Is OP a call-like operation that clobbers caller-saved registers?"
  (member op '(:call :tail-call :map-lookup
               :map-update :map-update-ptr
               :map-delete :map-delete-ptr
               :map-lookup-ptr
               :ringbuf-reserve :ringbuf-submit :ringbuf-discard
            :ringbuf-output)))

(defun helper-effects (insn)
  "Return a list of effect keywords for a call-like instruction.
   Returns NIL for non-call-like instructions.
   For :call ops, classifies by helper ID.  For map-* ops, returns
   the standard map-helper effects (clobbers caller-saved only;
   map value pointers from prior lookups become invalid)."
  (let ((op (ir-insn-op insn)))
    (cond
      ;; Direct :call — classify by helper ID
      ((eq op :call)
       (let ((helper-id (let ((first-arg (first (ir-insn-args insn))))
                          (if (and (consp first-arg) (eq (car first-arg) :helper))
                              (cadr first-arg)
                              first-arg))))
         (case helper-id
           ;; Map helpers (1, 2, 3): clobber caller-saved,
           ;; invalidate map value pointers (lookup returns new ptr)
           ((1 2 3)
            '(:clobbers-caller-saved :invalidates-map-value-ptrs))
           ;; Packet-modifying helpers: also invalidate packet pointers
           ;; 44=xdp_adjust_head, 56=xdp_adjust_tail,
           ;; 65=xdp_adjust_meta, 50=skb_change_head, 51=skb_change_tail
           ((44 56 65 50 51)
            '(:clobbers-caller-saved :invalidates-packet-ptrs
              :invalidates-map-value-ptrs))
           ;; Safe helpers (ktime, prandom, smp_processor_id, trace_printk):
           ;; only clobber caller-saved regs, preserve all pointers
           ((5 6 7 8)
            '(:clobbers-caller-saved))
           ;; redirect (23): preserves pointers but clobbers regs
           ((23)
            '(:clobbers-caller-saved))
           ;; Unknown helper: assume worst case
           (otherwise
            '(:clobbers-caller-saved :invalidates-packet-ptrs
              :invalidates-map-value-ptrs)))))
      ;; Map-* IR ops: these lower to helper calls that clobber regs
      ;; and invalidate prior map value pointers
      ((member op '(:map-lookup
                    :map-update :map-update-ptr
                    :map-delete :map-delete-ptr
                    :map-lookup-ptr))
       '(:clobbers-caller-saved :invalidates-map-value-ptrs))
      ;; Not a call-like op
      (t nil))))

(defun helper-invalidates-p (insn effect)
  "Does call-like INSN have the given EFFECT (a keyword)?
   Convenience predicate for checking a single effect."
  (member effect (helper-effects insn)))

;;; ========== Debugging and Inspection ==========

(defun format-ir-arg (arg)
  "Format a single IR operand for printing."
  (cond
    ((integerp arg) (format nil "%~d" arg))
    ((and (consp arg) (eq (car arg) :imm))
     (let ((val (second arg)))
       (if (integerp val)
           (if (or (> val 1000) (< val -1000))
               (format nil "0x~x" val)
               (format nil "~d" val))
           (format nil "~a" val))))
    ((and (consp arg) (eq (car arg) :label)) (format nil "@~a" (second arg)))
    ((and (consp arg) (eq (car arg) :map)) (format nil "[~a]" (second arg)))
    ((and (consp arg) (eq (car arg) :type)) (format nil "<~a>" (second arg)))
    ((and (consp arg) (eq (car arg) :helper)) (format nil "helper:~d" (second arg)))
    ((and (consp arg) (integerp (first arg)))
     ;; Phi operand: (vreg (:label L))
     (format nil "(%~d from @~a)" (first arg) (second (second arg))))
    (t (format nil "~s" arg))))

(defmethod print-object ((insn ir-insn) stream)
  (print-unreadable-object (insn stream :type nil :identity nil)
    (format stream "IR: ")
    (when (ir-insn-dst insn)
      (format stream "%~d = " (ir-insn-dst insn)))
    (format stream "~a" (ir-insn-op insn))
    (dolist (arg (ir-insn-args insn))
      (format stream " ~a" (format-ir-arg arg)))
    (when (ir-insn-type insn)
      (format stream " :~a" (ir-insn-type insn)))))

(defun ir-dump (prog &optional (stream *standard-output*))
  "Print a human-readable dump of the SSA IR program."
  (format stream "~&; IR Program (~a, ~a)~%"
          (ir-program-section prog) (ir-program-license prog))
  (dolist (block (ir-program-blocks prog))
    (format stream "~%~a:~%" (basic-block-label block))
    (when (basic-block-preds block)
      (format stream "  ; preds: ~{~a~^, ~}~%" (basic-block-preds block)))
    (dolist (insn (basic-block-insns block))
      (format stream "    ")
      (when (ir-insn-dst insn)
        (format stream "%~-3d = " (ir-insn-dst insn)))
      (format stream "~-10a" (ir-insn-op insn))
      (let ((args (mapcar #'format-ir-arg (ir-insn-args insn))))
        (format stream "~{~a~^, ~}" args))
      (when (ir-insn-type insn)
        (format stream "  (~a)" (ir-insn-type insn)))
      (terpri stream))
    (when (basic-block-succs block)
      (format stream "  ; succs: ~{~a~^, ~}~%" (basic-block-succs block)))))
