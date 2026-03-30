;;; vmlinux.lisp — Import kernel struct definitions from BTF
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Reads /sys/kernel/btf/vmlinux at macroexpand time and generates
;;; whistler:defstruct equivalents for kernel types.

(in-package #:whistler)

;;; ========== BTF binary reader ==========

(defconstant +btf-magic+ #xEB9F)
(defconstant +btf-kind-int+    1)
(defconstant +btf-kind-ptr+    2)
(defconstant +btf-kind-array+  3)
(defconstant +btf-kind-struct+ 4)
(defconstant +btf-kind-union+  5)
(defconstant +btf-kind-enum+   6)
(defconstant +btf-kind-fwd+    7)
(defconstant +btf-kind-typedef+ 8)
(defconstant +btf-kind-volatile+ 9)
(defconstant +btf-kind-const+  10)
(defconstant +btf-kind-restrict+ 11)
(defconstant +btf-kind-func+   12)
(defconstant +btf-kind-func-proto+ 13)
(defconstant +btf-kind-var+    14)
(defconstant +btf-kind-datasec+ 15)
(defconstant +btf-kind-float+  16)
(defconstant +btf-kind-enum64+ 19)

(cl:defstruct vmlinux-btf
  strtab types)

(cl:defstruct btf-type-info
  name-off info size/type)

(defun btf-u16 (bytes offset)
  (logior (aref bytes offset) (ash (aref bytes (1+ offset)) 8)))

(defun btf-u32 (bytes offset)
  (logior (aref bytes offset) (ash (aref bytes (+ offset 1)) 8)
          (ash (aref bytes (+ offset 2)) 16) (ash (aref bytes (+ offset 3)) 24)))

(defun btf-string (strtab offset)
  (let ((end (position 0 strtab :start offset)))
    (map 'string #'code-char (subseq strtab offset (or end (length strtab))))))

(defun btf-kind (info) (logand (ash info -24) #x1f))
(defun btf-vlen (info) (logand info #xffff))

(defun read-vmlinux-btf (&optional (path "/sys/kernel/btf/vmlinux"))
  "Read and parse the vmlinux BTF blob. Returns a vmlinux-btf structure."
  (let ((bytes (with-open-file (f path :element-type '(unsigned-byte 8))
                 (let ((buf (make-array (file-length f)
                                        :element-type '(unsigned-byte 8))))
                   (read-sequence buf f)
                   buf))))
    ;; Parse header
    (let* ((magic (btf-u16 bytes 0))
           (hdr-len (btf-u32 bytes 4))
           (type-off (btf-u32 bytes 8))
           (type-len (btf-u32 bytes 12))
           (str-off (btf-u32 bytes 16))
           (str-len (btf-u32 bytes 20)))
      (unless (= magic +btf-magic+)
        (error "Not a BTF file: magic=~x" magic))
      (let ((strtab (subseq bytes (+ hdr-len str-off)
                            (+ hdr-len str-off str-len)))
            (type-data (subseq bytes (+ hdr-len type-off)
                               (+ hdr-len type-off type-len)))
            (types (make-array 1 :adjustable t :fill-pointer 1
                                 :initial-element nil)))  ; type 0 = void
        ;; Parse type records
        (let ((pos 0))
          (loop while (< pos (length type-data)) do
            (let* ((name-off (btf-u32 type-data pos))
                   (info (btf-u32 type-data (+ pos 4)))
                   (size/type (btf-u32 type-data (+ pos 8)))
                   (kind (btf-kind info))
                   (vlen (btf-vlen info)))
              (vector-push-extend
               (list :name-off name-off :info info :size size/type
                     :kind kind :vlen vlen :data-off (+ pos 12))
               types)
              ;; Advance past this record
              (cl:incf pos 12)
              ;; Skip variable-length data
              (cl:incf pos
                       (cl:case kind
                         (#.+btf-kind-int+ 4)
                         (#.+btf-kind-array+ 12)
                         ((#.+btf-kind-struct+ #.+btf-kind-union+) (* vlen 12))
                         (#.+btf-kind-enum+ (* vlen 8))
                         (#.+btf-kind-func-proto+ (* vlen 8))
                         (#.+btf-kind-var+ 4)
                         (#.+btf-kind-datasec+ (* vlen 12))
                         (#.+btf-kind-enum64+ (* vlen 12))
                         (t 0))))))
        (make-vmlinux-btf :strtab strtab :types types)))))

;;; ========== Struct lookup ==========

(defun btf-find-struct (vmbtf name)
  "Find a BTF struct by name. Returns (type-id type-record) or nil."
  (let ((strtab (vmlinux-btf-strtab vmbtf))
        (types (vmlinux-btf-types vmbtf)))
    (loop for id from 1 below (length types)
          for rec = (aref types id)
          when (and rec
                    (= (getf rec :kind) +btf-kind-struct+)
                    (string= (btf-string strtab (getf rec :name-off)) name))
          return (values id rec))))

(defun btf-resolve-type (vmbtf type-id)
  "Resolve a BTF type through typedefs, const, volatile, etc.
   Returns the underlying kind, size, and name."
  (let ((types (vmlinux-btf-types vmbtf))
        (strtab (vmlinux-btf-strtab vmbtf)))
    (loop for id = type-id then (getf rec :size)
          for rec = (when (and id (< id (length types))) (aref types id))
          while rec
          for kind = (getf rec :kind)
          do (cl:case kind
               ((#.+btf-kind-typedef+ #.+btf-kind-volatile+
                 #.+btf-kind-const+ #.+btf-kind-restrict+)
                nil)  ; follow the chain
               (#.+btf-kind-ptr+
                (return (values 'u64 8 "ptr")))
               (#.+btf-kind-int+
                (let ((size (getf rec :size))
                      (name (btf-string strtab (getf rec :name-off))))
                  (return (values
                           (cl:case size (1 'u8) (2 'u16) (4 'u32) (8 'u64) (t 'u64))
                           size name))))
               (#.+btf-kind-enum+
                (let ((size (getf rec :size)))
                  (return (values
                           (cl:case size (1 'u8) (2 'u16) (4 'u32) (8 'u64) (t 'u32))
                           size "enum"))))
               (#.+btf-kind-array+
                ;; For now, treat as opaque bytes
                (return (values nil (getf rec :size) "array")))
               (#.+btf-kind-struct+ #.+btf-kind-union+
                (let ((name (btf-string strtab (getf rec :name-off))))
                  (return (values nil (getf rec :size) name))))
               (t (return (values 'u64 8 "unknown")))))))

(defun btf-struct-fields (vmbtf struct-type-id)
  "Extract fields from a BTF struct, recursively flattening anonymous
   struct/union members. Returns list of (name type offset size)."
  (let* ((types (vmlinux-btf-types vmbtf))
         (strtab (vmlinux-btf-strtab vmbtf))
         (type-data (with-open-file (f "/sys/kernel/btf/vmlinux"
                                       :element-type '(unsigned-byte 8))
                      (let ((buf (make-array (file-length f)
                                             :element-type '(unsigned-byte 8))))
                        (read-sequence buf f)
                        (let* ((hdr-len (btf-u32 buf 4))
                               (type-off (btf-u32 buf 8))
                               (type-len (btf-u32 buf 12)))
                          (subseq buf (+ hdr-len type-off)
                                  (+ hdr-len type-off type-len)))))))
    (labels ((collect-fields (tid base-offset)
               "Collect fields from struct/union at TID, adding BASE-OFFSET
                to each field's byte offset. Recurses into anonymous members."
               (let* ((rec (aref types tid))
                      (data-off (getf rec :data-off))
                      (vlen (getf rec :vlen))
                      (fields '()))
                 (dotimes (i vlen)
                   (let* ((moff (+ data-off (* i 12)))
                          (name-off (btf-u32 type-data moff))
                          (member-type-id (btf-u32 type-data (+ moff 4)))
                          (bit-offset (btf-u32 type-data (+ moff 8)))
                          (byte-offset (+ base-offset (ash bit-offset -3)))
                          (fname (btf-string strtab name-off)))
                     (if (plusp (length fname))
                         ;; Named field: resolve type and collect
                         (multiple-value-bind (bpf-type size resolved-name)
                             (btf-resolve-type vmbtf member-type-id)
                           (push (list fname bpf-type byte-offset size resolved-name)
                                 fields))
                         ;; Anonymous member: recurse into it if struct/union
                         (let ((member-rec (when (< member-type-id (length types))
                                             (aref types member-type-id))))
                           (when (and member-rec
                                      (member (getf member-rec :kind)
                                              (list +btf-kind-struct+ +btf-kind-union+)))
                             (setf fields
                                   (nconc (collect-fields member-type-id byte-offset)
                                          fields)))))))
                 (nreverse fields))))
      (collect-fields struct-type-id 0))))

;;; ========== Typed pointer support ==========

(defmacro typed-ptr (struct-type expr)
  "Compile-time struct pointer tag. Erased before lowering — zero cost.
   Accessor macros check this tag and propagate it for embedded structs."
  (declare (ignore struct-type))
  expr)

(defun strip-typed-ptr (form)
  "If FORM is (typed-ptr TYPE EXPR), return EXPR. Otherwise return FORM."
  (if (and (consp form) (eq (car form) 'typed-ptr))
      (third form)
      form))

(defun check-struct-ptr-type (expected-struct ptr-form accessor-name)
  "At macroexpand time, verify a typed-ptr tag matches the expected struct.
   Bare (untagged) pointers pass through unchecked for backward compatibility."
  (when (and (consp ptr-form) (eq (car ptr-form) 'typed-ptr))
    (let ((actual-struct (second ptr-form)))
      (unless (eq actual-struct expected-struct)
        (whistler-error
         :what (format nil "~a expects a ~a pointer, got ~a"
                       accessor-name expected-struct actual-struct)
         :hint (format nil "use (as-~(~a~) ptr) to cast if intentional"
                       expected-struct))))))

;;; ========== The macro ==========

(defvar *vmlinux-btf-cache* nil
  "Cached vmlinux BTF parse, shared across macro expansions.")

(defun ensure-vmlinux-btf ()
  (or *vmlinux-btf-cache*
      (setf *vmlinux-btf-cache*
            (read-vmlinux-btf))))

(defmacro import-kernel-struct (struct-name &rest field-names)
  "Import a kernel struct from vmlinux BTF at macroexpand time.
   For scalar/pointer fields, generates kernel-load accessors.
   For all fields (including embedded structs), generates offset constants.
   FIELD-NAMES optionally restricts which fields to import.

   Example:
     (import-kernel-struct msghdr msg_name msg_iter)

   Generates: (msghdr-msg-name ptr)  → (kernel-load u64 ptr OFFSET)  ; pointer field
              (msghdr-msg-iter ptr)  → (+ ptr OFFSET)                ; embedded struct"
  (let* ((vmbtf (ensure-vmlinux-btf))
         (c-name (substitute #\_ #\- (string-downcase (symbol-name struct-name)))))
    (multiple-value-bind (type-id rec) (btf-find-struct vmbtf c-name)
      (unless type-id
        (whistler-error
         :what (format nil "kernel struct not found in vmlinux BTF: ~a" c-name)
         :expected "a struct defined in /sys/kernel/btf/vmlinux"))
      (let* ((all-fields (btf-struct-fields vmbtf type-id))
             (fields (if field-names
                         (loop for fname in field-names
                               for c-fname = (substitute #\_ #\-
                                               (string-downcase (symbol-name fname)))
                               for field = (find c-fname all-fields
                                                 :key #'first :test #'string=)
                               when field collect field
                               else do (whistler-error
                                        :what (format nil "field ~a not found in ~a"
                                                      fname c-name)
                                        :expected (format nil "known fields: ~{~a~^, ~}"
                                                          (mapcar #'first
                                                                  (subseq all-fields 0
                                                                          (min 20 (length all-fields)))))))
                         all-fields))
             (forms '())
             (lisp-struct-name (intern (string-upcase
                                        (substitute #\- #\_ c-name))
                                       (symbol-package struct-name))))
        ;; Generate as-STRUCT cast macro
        (let ((cast-name (intern (format nil "AS-~a" (symbol-name lisp-struct-name))
                                 (symbol-package struct-name))))
          (push `(defmacro ,cast-name (ptr)
                   (list 'typed-ptr ',lisp-struct-name ptr))
                forms))
        ;; Generate accessors with type checking
        (dolist (field fields)
          (destructuring-bind (c-fname bpf-type byte-offset size resolved-name) field
            (declare (ignore size))
            (let* ((lisp-fname (substitute #\- #\_ c-fname))
                   (accessor (intern (format nil "~a-~a"
                                            (symbol-name lisp-struct-name)
                                            (string-upcase lisp-fname))
                                     (symbol-package struct-name))))
              (if bpf-type
                  ;; Scalar/pointer: check type, strip tag, kernel-load
                  (push `(defmacro ,accessor (ptr)
                           (check-struct-ptr-type ',lisp-struct-name ptr ',accessor)
                           (list 'kernel-load ',bpf-type (strip-typed-ptr ptr)
                                 ,byte-offset))
                        forms)
                  ;; Embedded struct: check type, strip tag, return typed address
                  (let ((embedded-name
                          (when (and resolved-name (plusp (length resolved-name)))
                            (intern (string-upcase (substitute #\- #\_ resolved-name))
                                    (symbol-package struct-name)))))
                    (if embedded-name
                        (push `(defmacro ,accessor (ptr)
                                 (check-struct-ptr-type ',lisp-struct-name ptr ',accessor)
                                 (list 'typed-ptr ',embedded-name
                                       (list '+ (strip-typed-ptr ptr) ,byte-offset)))
                              forms)
                        (push `(defmacro ,accessor (ptr)
                                 (check-struct-ptr-type ',lisp-struct-name ptr ',accessor)
                                 (list '+ (strip-typed-ptr ptr) ,byte-offset))
                              forms)))))))
        ;; Generate sizeof constant
        (let ((sizeof-name (intern (format nil "+~a-SIZE+"
                                          (symbol-name lisp-struct-name))
                                   (symbol-package struct-name))))
          (push `(cl:defconstant ,sizeof-name ,(getf rec :size)) forms))
        `(progn ,@(nreverse forms))))))
