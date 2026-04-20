;;; -*- Mode: Lisp -*-
;;;
;;; Copyright (c) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; SPDX-License-Identifier: MIT

(in-package #:whistler/compiler)

;;; Whistler compiler: shared definitions and macro expansion
;;;
;;; This file contains the canonical tables (helpers, constants, builtins),
;;; data structures (bpf-map, compilation-unit), and macro expansion logic
;;; used by the SSA pipeline (lower.lisp → ssa-opt.lisp → emit.lisp).

;;; Helper function table

(defparameter *builtin-helpers*
  '(("MAP-LOOKUP-ELEM"      . 1)
    ("MAP-UPDATE-ELEM"      . 2)
    ("MAP-DELETE-ELEM"      . 3)
    ("PROBE-READ"           . 4)
    ("KTIME-GET-NS"         . 5)
    ("TRACE-PRINTK"         . 6)
    ("GET-PRANDOM-U32"      . 7)
    ("GET-SMP-PROCESSOR-ID" . 8)
    ("TAIL-CALL"            . 12)
    ("GET-CURRENT-PID-TGID" . 14)
    ("GET-CURRENT-UID-GID"  . 15)
    ("GET-CURRENT-COMM"     . 16)
    ("REDIRECT"             . 23)
    ("PERF-EVENT-OUTPUT"    . 25)
    ("SKB-LOAD-BYTES"       . 26)
    ("PROBE-READ-STR"       . 45)
    ("GET-CURRENT-TASK"     . 35)
    ("GET-CURRENT-CGROUP-ID" . 80)
    ("PROBE-READ-KERNEL"    . 113)
    ("PROBE-READ-USER"      . 112)
    ("PROBE-READ-USER-STR"  . 114)
    ("RINGBUF-OUTPUT"       . 130)
    ("RINGBUF-RESERVE"      . 131)
    ("RINGBUF-SUBMIT"       . 132)
    ("RINGBUF-DISCARD"      . 133)
    ("GET-SOCKET-COOKIE"    . 46)
    ("GET-CURRENT-TASK-BTF" . 159)
    ("KTIME-GET-COARSE-NS"  . 161))
  "BPF helper functions: string name → helper ID.
   Single source of truth — referenced by the SSA pipeline via lower.lisp.")

(defparameter *helper-arg-counts*
  '(("PROBE-READ" . 3) ("PROBE-READ-USER" . 3) ("PROBE-READ-KERNEL" . 3)
    ("PROBE-READ-STR" . 3) ("PROBE-READ-USER-STR" . 3)
    ("KTIME-GET-NS" . 0) ("GET-PRANDOM-U32" . 0) ("GET-CURRENT-TASK" . 0)
    ("GET-SMP-PROCESSOR-ID" . 0) ("GET-CURRENT-CGROUP-ID" . 0)
    ("GET-CURRENT-PID-TGID" . 0) ("GET-CURRENT-UID-GID" . 0)
    ("GET-CURRENT-COMM" . 2)
    ("REDIRECT" . 2) ("PERF-EVENT-OUTPUT" . 3) ("SKB-LOAD-BYTES" . 4)
    ("TRACE-PRINTK" . 3)
    ("RINGBUF-RESERVE" . 3) ("RINGBUF-SUBMIT" . 2) ("RINGBUF-DISCARD" . 2)
    ("RINGBUF-OUTPUT" . 4)
    ("GET-SOCKET-COOKIE" . 1) ("GET-CURRENT-TASK-BTF" . 0)
    ("KTIME-GET-COARSE-NS" . 0))
  "Expected argument counts for BPF helpers that users call directly.
   BPF allows max 5 args (R1-R5). Helpers not listed here are not checked.")

;;; Known constants

(defparameter *builtin-constants*
  '(("XDP_ABORTED"  . 0)
    ("XDP_DROP"     . 1)
    ("XDP_PASS"     . 2)
    ("XDP_TX"       . 3)
    ("XDP_REDIRECT" . 4)
    ("BPF_ANY"      . 0)
    ("BPF_NOEXIST"  . 1)
    ("BPF_EXIST"    . 2)
    ("NULL"         . 0)
    ;; TC action codes
    ("TC_ACT_OK"       . 0)
    ("TC_ACT_SHOT"     . 2)
    ("TC_ACT_STOLEN"   . 4)
    ("TC_ACT_REDIRECT" . 7))
  "BPF constants: string name → integer value.")

;;; Map type name resolution

(defun resolve-map-type (type-kw)
  (ecase type-kw
    (:hash          +bpf-map-type-hash+)
    (:lru-hash      +bpf-map-type-lru-hash+)
    (:array         +bpf-map-type-array+)
    (:prog-array    +bpf-map-type-prog-array+)
    (:percpu-hash   +bpf-map-type-percpu-hash+)
    (:lpm-trie      +bpf-map-type-lpm-trie+)
    (:percpu-array  +bpf-map-type-percpu-array+)
    (:ringbuf       +bpf-map-type-ringbuf+)))

;;; Data structures

(defstruct bpf-map
  name type key-size value-size max-entries (flags 0) index)

(defstruct (compilation-unit (:conc-name cu-))
  (insns '())           ; list of bpf-insn
  (maps '())            ; list of bpf-map structs
  (map-relocs '())      ; list of (insn-index map-index) for relocation
  (core-relocs '())     ; list of (byte-offset struct-name field-name) for CO-RE
  (section "xdp")       ; ELF section name
  (name nil)            ; defprog name (symbol or string) for FUNC symbol
  (license "GPL"))      ; license string

;;; Compiler error reporting

(defun whistler-error (&key what where expected hint)
  "Signal a structured compiler error with context."
  (error "~&~%  error: ~a~@[~%  in: ~a~]~@[~%  expected: ~a~]~@[~%  hint: ~a~]~%"
         what where expected hint))

;;; Shared utility functions

(defun sym= (a b)
  "Compare symbols by name, ignoring package."
  (and (symbolp a) (symbolp b)
       (string= (symbol-name a) (symbol-name b))))

(defun bpf-type-p (sym)
  "Return T if SYM names a BPF type (u8, u16, u32, u64, i8, i16, i32, i64)."
  (and (symbolp sym)
       (member (symbol-name sym)
               '("U8" "U16" "U32" "U64" "I8" "I16" "I32" "I64")
               :test #'string=)))

(defun bpf-type-size (type-kw)
  "Return the size in bytes of a BPF type keyword (u8=1, u16=2, u32=4, u64=8)."
  (ecase (intern (string type-kw) :keyword)
    ((:u8 :i8) 1)
    ((:u16 :i16) 2)
    ((:u32 :i32) 4)
    ((:u64 :i64) 8)))

;;; ========== Context struct layouts ==========

(defvar *ctx-btf-resolver* nil
  "When non-nil, a function (lambda (struct-name) ...) that looks up a context
   struct in the kernel's BTF and returns fields in *ctx-struct-fields* format:
   ((field-name type offset) ...). Set by vmlinux.lisp at load time.")

(defparameter *prog-type-to-ctx-struct*
  '((:xdp              . "xdp_md")
    (:cgroup-skb        . "__sk_buff")
    (:cgroup-sock-addr  . "bpf_sock_addr")
    (:cgroup-sock       . "bpf_sock_ops")
    (:tc                . "__sk_buff")))

(defparameter *ctx-struct-fields*
  '(("xdp_md" .
     ((data          u32 0)
      (data-end      u32 4)
      (data-meta     u32 8)
      (ingress-ifindex u32 12)
      (rx-queue-index u32 16)
      (egress-ifindex u32 20)))
    ("bpf_sock_addr" .
     ((user-family   u32 0)
      (user-ip4      u32 4)
      (user-ip6      (:array u32 4) 8)
      (user-port     u32 24)
      (family        u32 28)
      (type          u32 32)
      (protocol      u32 36)
      (msg-src-ip4   u32 40)
      (msg-src-ip6   (:array u32 4) 44)
      (sk            :ptr 60)))
    ("bpf_sock_ops" .
     ((op            u32 0)
      (args          (:array u32 4) 4)
      (family        u32 20)
      (remote-ip4    u32 24)
      (local-ip4     u32 28)
      (remote-ip6    (:array u32 4) 32)
      (local-ip6     (:array u32 4) 48)
      (remote-port   u32 64)
      (local-port    u32 68)
      (is-fullsock   u32 72)
      (snd-cwnd      u32 76)
      (srtt-us       u32 80)))
    ("__sk_buff" .
     ((len           u32 0)
      (pkt-type      u32 4)
      (mark          u32 8)
      (queue-mapping u32 12)
      (protocol      u32 16)
      (vlan-present  u32 20)
      (vlan-tci      u32 24)
      (vlan-proto    u32 28)
      (priority      u32 32)
      (ingress-ifindex u32 36)
      (ifindex       u32 40)
      (tc-index      u32 44)
      (cb            (:array u32 5) 48)
      (hash          u32 68)
      (tc-classid    u32 72)
      (data          u32 76)
      (data-end      u32 80)
      (napi-id       u32 84)
      (family        u32 88)
      (remote-ip4    u32 92)
      (local-ip4     u32 96)
      (remote-ip6    (:array u32 4) 100)
      (local-ip6     (:array u32 4) 116)
      (remote-port   u32 132)
      (local-port    u32 136)
      (data-meta     u32 140)))))

(defun ctx-resolve-field (prog-type field-name &optional index)
  "Resolve a context field name to (values type offset) for a program type.
   For array fields, INDEX must be a compile-time constant integer.
   Tries BTF resolution first (when available), falls back to static table."
  (let* ((struct-name (cdr (assoc prog-type *prog-type-to-ctx-struct*)))
         (btf-fields (when (and struct-name *ctx-btf-resolver*)
                       (funcall *ctx-btf-resolver* struct-name)))
         (struct (or btf-fields
                     (when struct-name
                       (cdr (assoc struct-name *ctx-struct-fields* :test #'string=)))))
         (field (when struct
                  (find (symbol-name field-name) struct
                        :key (lambda (f) (symbol-name (first f)))
                        :test #'string=))))
    (unless field
      (whistler-error
       :what (format nil "unknown context field: ~a" field-name)
       :expected (if struct
                     (format nil "a field of ~a: ~{~a~^, ~}" struct-name
                             (mapcar #'first struct))
                     (format nil "program type ~a has no known context struct"
                             (or prog-type :unknown)))))
    (destructuring-bind (name ftype foffset) field
      (declare (ignore name))
      (cond
        ;; Array field
        ((and (consp ftype) (eq (first ftype) :array))
         (unless index
           (whistler-error
            :what (format nil "~a is an array field — index required" field-name)
            :expected (format nil "(ctx ~a INDEX)" field-name)))
         (unless (integerp index)
           (whistler-error
            :what (format nil "array index must be a compile-time constant, got ~s" index)))
         (let ((elem-type (second ftype))
               (count (third ftype)))
           (when (or (< index 0) (>= index count))
             (whistler-error
              :what (format nil "index ~d out of bounds for ~a[~d]" index field-name count)))
           (values elem-type (+ foffset (* index (bpf-type-size elem-type))))))
        ;; Pointer field
        ((eq ftype :ptr)
         (when index
           (whistler-error
            :what (format nil "~a is a pointer field — no index allowed" field-name)))
         (values 'u64 foffset))
        ;; Scalar field
        (t
         (when index
           (whistler-error
            :what (format nil "~a is a scalar field — no index allowed" field-name)))
         (values ftype foffset))))))

(defun builtin-helper-p (sym)
  "Return the helper ID if SYM names a known BPF helper, or NIL."
  (and (symbolp sym)
       (cdr (assoc (symbol-name sym) *builtin-helpers*
                   :test #'string=))))

;;; Builtin form recognition

(defparameter *whistler-builtins*
  '("PROGN" "LET" "LET*" "IF" "RETURN" "LOAD" "STORE" "ATOMIC-ADD"
    "MAP-LOOKUP" "MAP-UPDATE" "MAP-DELETE" "CTX-LOAD"
    "CORE-LOAD" "CORE-STORE" "CORE-CTX-LOAD"
    "MAP-UPDATE-PTR" "MAP-DELETE-PTR"
    "RINGBUF-RESERVE" "RINGBUF-SUBMIT" "RINGBUF-DISCARD"
    "STACK-ADDR" "CAST" "NOT" "WHEN" "UNLESS" "COND" "AND" "OR" "LOG2"
    "SETF" "DOTIMES" "NTOHS" "HTONS" "NTOHL" "HTONL" "NTOHLL" "HTONLL"
    "TAIL-CALL" "ASM" "DECLARE")
  "Form names handled by Whistler. Do not macroexpand these.")

;; ALU and comparison operator names (used by whistler-builtin-p to prevent
;; macro expansion of forms like (+ a b) and (= a b))
(defparameter *alu-op-names*
  '("+" "-" "*" "/" "MOD" "LOGIOR" "LOGAND" "LOGXOR"
    "BIT-OR" "BIT-AND" "BIT-XOR" "ASH" "ASH-LEFT" "ASH-RIGHT" "ASH-RIGHT-SIGNED"
    "<<" ">>" ">>>"))

(defparameter *jmp-op-names*
  '("=" "/=" ">" ">=" "<" "<=" "S>" "S>=" "S<" "S<="))

(defun whistler-builtin-p (sym)
  "Return T if SYM names a Whistler built-in form or a known BPF helper."
  (and (symbolp sym)
       (let ((name (symbol-name sym)))
         (or (member name *whistler-builtins* :test #'string=)
             (member name *alu-op-names* :test #'string=)
             (member name *jmp-op-names* :test #'string=)
             (builtin-helper-p sym)))))

;;; Macro expansion
;;;
;;; Before compilation, we walk the form tree and expand any CL macros.
;;; This is what makes Whistler a real Lisp: users define macros with
;;; defmacro in their source files, and the compiler expands them into
;;; primitive forms. Full Common Lisp is available at compile time.

(defun whistler-macroexpand (form)
  "Recursively expand macros in FORM. Does not descend into quoted data.
   Only expands macros that are NOT Whistler built-in forms."
  (cond
    ((atom form) form)
    ;; Don't expand inside quote
    ((sym= (car form) 'quote) form)
    (t
     (let ((head (car form)))
       (if (whistler-builtin-p head)
           ;; Known Whistler form — don't macroexpand it, just recurse into subforms
           (let ((head (car form)))
             (cond
               ;; (let/let* ((var [type] init) ...) body...) — expand inits and body
               ((or (sym= head 'let) (sym= head 'let*))
                (let ((bindings (mapcar (lambda (b)
                                         (cond
                                           ;; 3-element: (var type init) — typed
                                           ((and (consp b) (cddr b))
                                            (list (first b) (second b)
                                                  (whistler-macroexpand (third b))))
                                           ;; 2-element: (var init-or-type)
                                           ((and (consp b) (cdr b))
                                            (if (bpf-type-p (second b))
                                                ;; (var type) — typed, no init
                                                b
                                                ;; (var init) — untyped
                                                (list (first b)
                                                      (whistler-macroexpand (second b)))))
                                           ;; 1-element or atom
                                           (t b)))
                                       (second form)))
                      (body (mapcar (lambda (f)
                                     ;; Don't expand declare forms
                                     (if (and (consp f) (sym= (car f) 'declare))
                                         f
                                         (whistler-macroexpand f)))
                                   (cddr form))))
                  (list* (car form) bindings body)))
               ;; (setf ...) — handle multi-pair and accessor expansion
               ((sym= head 'setf)
                (let ((args (cdr form)))
                  (cond
                    ;; Multi-pair: (setf a 1 b 2 ...) → (progn (setf a 1) (setf b 2) ...)
                    ((> (length args) 2)
                     (let ((pairs '()))
                       (loop while args do
                         (push `(setf ,(first args) ,(second args)) pairs)
                         (setf args (cddr args)))
                       (whistler-macroexpand `(progn ,@(nreverse pairs)))))
                    ;; Accessor place: (setf (accessor ...) val) — try CL setf expansion
                    ((consp (first args))
                     (let ((expanded (macroexpand-1 form)))
                       (if (not (eq expanded form))
                           (whistler-macroexpand expanded)
                           (cons (car form) (mapcar #'whistler-macroexpand (cdr form))))))
                    ;; Simple: (setf var val) — recurse normally
                    (t (cons (car form) (mapcar #'whistler-macroexpand (cdr form)))))))
               ;; Everything else — expand all arguments
               (t
                (cons (car form) (mapcar #'whistler-macroexpand (cdr form))))))
           ;; Not a builtin — try macroexpanding
           (let ((expanded (macroexpand-1 form)))
             (if (not (eq expanded form))
                 ;; Got expansion — recurse on the result
                 (whistler-macroexpand expanded)
                 ;; No expansion — recurse on arguments
                 (cons (car form) (mapcar #'whistler-macroexpand (cdr form))))))))))

;;; Constant folding on s-expressions (pre-compilation pass)

(defun constant-fold-sexpr (form)
  "Walk FORM, replacing defconstant symbols with their integer values
   and folding arithmetic on constant arguments."
  (cond
    ((null form) form)
    ;; Resolve defconstant symbols to their values
    ((and (symbolp form)
          (not (keywordp form))
          (boundp form)
          (constantp form))
     (let ((val (symbol-value form)))
       (if (integerp val) val form)))
    ((atom form) form)
    (t
     (let* ((folded (mapcar #'constant-fold-sexpr form))
            (head (car folded))
            (args (cdr folded)))
       ;; Try to fold if head is an arithmetic op and all args are integers
       (if (and (symbolp head)
                args
                (every #'integerp args))
           (let ((name (symbol-name head)))
             (cond
               ((string= name "+") (reduce #'+ args))
               ((and (string= name "-") (= (length args) 1))
                (- (first args)))
               ((and (string= name "-") (>= (length args) 2))
                (reduce #'- args))
               ((string= name "*") (reduce #'* args))
               ((and (string= name "/") (>= (length args) 2)
                     (every (lambda (x) (/= x 0)) (rest args)))
                (reduce #'truncate args))
               ((and (string= name "<<") (= (length args) 2))
                (ash (first args) (second args)))
               ((and (string= name ">>") (= (length args) 2))
                (ash (first args) (- (second args))))
               ((and (string= name "&") (= (length args) 2))
                (logand (first args) (second args)))
               ((and (string= name "|") (= (length args) 2))
                (logior (first args) (second args)))
               (t folded)))
           folded)))))
