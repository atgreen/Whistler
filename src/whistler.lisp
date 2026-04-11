;;; -*- Mode: Lisp -*-
;;;
;;; Copyright (c) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; SPDX-License-Identifier: MIT

(in-package #:whistler)

;;; Whistler: top-level interface
;;; Compile Lisp forms to eBPF ELF object files.

(defun whistler-version ()
  "Return the Whistler version string from the ASDF system definition."
  (let ((sys (asdf:find-system "whistler" nil)))
    (if sys
        (format nil "v~a" (asdf:component-version sys))
        "unknown")))

(defvar *version* (whistler-version))

(defvar *user-constants* '()
  "Constants defined by user code in the current compilation. Set by codegen.")

(defvar *maps* '()
  "Map definitions for the current compilation.")

(defvar *programs* '()
  "Program definitions for the current compilation.")

;;; Byte encoding helpers for struct decode/encode (no external deps)

(defun bpf-bytes-u32 (bytes offset)
  (logior (aref bytes offset) (ash (aref bytes (+ offset 1)) 8)
          (ash (aref bytes (+ offset 2)) 16) (ash (aref bytes (+ offset 3)) 24)))

(defun bpf-bytes-u64 (bytes offset)
  (logior (bpf-bytes-u32 bytes offset) (ash (bpf-bytes-u32 bytes (+ offset 4)) 32)))

(defun bpf-put-u32 (bytes offset val)
  (setf (aref bytes offset) (logand val #xff))
  (setf (aref bytes (+ offset 1)) (logand (ash val -8) #xff))
  (setf (aref bytes (+ offset 2)) (logand (ash val -16) #xff))
  (setf (aref bytes (+ offset 3)) (logand (ash val -24) #xff)))

(defun bpf-put-u64 (bytes offset val)
  (bpf-put-u32 bytes offset (logand val #xffffffff))
  (bpf-put-u32 bytes (+ offset 4) (logand (ash val -32) #xffffffff)))

;;; Struct definitions

(defvar *struct-defs* (make-hash-table :test 'equal)
  "Struct definitions: name-string -> (total-size . field-alist).
   Each field entry is (field-name type offset size).")

(defun struct-type-byte-size (type)
  "Return byte size for a struct field type."
  (let ((name (string-upcase (string type))))
    (cond ((string= name "U8")  1)
          ((string= name "U16") 2)
          ((string= name "U32") 4)
          ((string= name "U64") 8)
          (t (whistler-error
             :what (format nil "unknown struct field type: ~a" type)
             :expected "one of: u8, u16, u32, u64, or (array TYPE COUNT)"
             :hint (cond
                     ((member (symbol-name type) '("INT" "CHAR" "UINT32_T" "UINT8_T"
                               "UINT16_T" "UINT64_T" "SIZE_T") :test #'string=)
                      (format nil "use BPF types: u8, u16, u32, u64 (not C types)"))
                     (t nil)))))))

(defun struct-type-to-store-type (type)
  "Convert a struct field type symbol to the surface-language store type."
  (let ((name (string-upcase (string type))))
    (cond ((string= name "U8")  'u8)
          ((string= name "U16") 'u16)
          ((string= name "U32") 'u32)
          ((string= name "U64") 'u64)
          (t (whistler-error
             :what (format nil "unknown struct field type: ~a" type)
             :expected "one of: u8, u16, u32, u64, or (array TYPE COUNT)"
             :hint (cond
                     ((member (symbol-name type) '("INT" "CHAR" "UINT32_T" "UINT8_T"
                               "UINT16_T" "UINT64_T" "SIZE_T") :test #'string=)
                      (format nil "use BPF types: u8, u16, u32, u64 (not C types)"))
                     (t nil)))))))

(defun parse-field-type (ftype)
  "Parse a field type spec. Returns (values elem-type count is-array).
   For scalar types like U32: (values U32 1 nil).
   For array types like (ARRAY U8 16): (values U8 16 t)."
  (if (and (consp ftype)
           (string= (string (car ftype)) "ARRAY"))
      (values (second ftype) (third ftype) t)
      (values ftype 1 nil)))

(defmacro defstruct (name &body fields)
  "Define a BPF struct with C-compatible layout.
   Generates:
   - (make-NAME) constructor macro
   - (NAME-FIELD ptr) accessor macros for each scalar field
   - (NAME-FIELD ptr idx) indexed accessor macros for each array field
   - (setf ...) writer expanders for each field

   Field syntax:
     (field-name type)             — scalar field (u8, u16, u32, u64)
     (field-name (array type n))   — array of n elements"
  (let ((field-list '())
        (offset 0)
        (max-align 1))
    (dolist (field-spec fields)
      (cl:destructuring-bind (fname ftype) field-spec
        (multiple-value-bind (elem-type count is-array) (parse-field-type ftype)
          (let* ((elem-size (struct-type-byte-size elem-type))
                 (align elem-size)
                 (field-size (if is-array (* count elem-size) elem-size))
                 (aligned-off (logand (+ offset (1- align)) (- align)))
                 (stored-type (if is-array
                                  (list :array elem-type count)
                                  ftype)))
            (push (list fname stored-type aligned-off field-size) field-list)
            (setf offset (+ aligned-off field-size))
            (setf max-align (max max-align align))))))
    (let* ((total (logand (+ offset (1- max-align)) (- max-align)))
           (fields-rev (nreverse field-list))
           (make-name (intern (format nil "MAKE-~a" (symbol-name name))
                              (symbol-package name)))
           (accessor-forms '()))
      ;; Generate accessor and setf macros for each field
      (dolist (field fields-rev)
        (cl:destructuring-bind (fname ftype foffset fsize) field
          (declare (ignore fsize))
          (let ((accessor-name (intern (format nil "~a-~a" (symbol-name name)
                                               (symbol-name fname))
                                       (symbol-package name))))
            (if (and (consp ftype) (eq (car ftype) :array))
                ;; Array field: generate indexed accessor and writer
                (let* ((elem-type (second ftype))
                       (elem-size (struct-type-byte-size elem-type))
                       (store-type (struct-type-to-store-type elem-type))
                       (writer-name (intern (format nil "SET-~a-~a!" (symbol-name name)
                                                    (symbol-name fname))
                                            (symbol-package name))))
                  ;; Reader: (name-field ptr idx)
                  ;; Constant idx → fixed offset; runtime idx → computed offset
                  (push `(cl:defmacro ,accessor-name (ptr idx)
                           (if (integerp idx)
                               (list 'load ',store-type ptr
                                     (+ ,foffset (* idx ,elem-size)))
                               (list 'load ',store-type
                                     (list '+ ptr
                                           ,(if (= elem-size 1)
                                                `(list '+ ,foffset idx)
                                                `(list '+ ,foffset
                                                       (list '* idx ,elem-size))))
                                     0)))
                        accessor-forms)
                  ;; Writer: (set-name-field! ptr idx val)
                  (push `(cl:defmacro ,writer-name (ptr idx val)
                           (if (integerp idx)
                               (list 'store ',store-type ptr
                                     (+ ,foffset (* idx ,elem-size)) val)
                               (list 'store ',store-type
                                     (list '+ ptr
                                           ,(if (= elem-size 1)
                                                `(list '+ ,foffset idx)
                                                `(list '+ ,foffset
                                                       (list '* idx ,elem-size))))
                                     0 val)))
                        accessor-forms)
                  (push `(cl:defsetf ,accessor-name ,writer-name)
                        accessor-forms)
                  ;; Pointer accessor: (name-field-ptr ptr) → (+ ptr offset)
                  ;; For passing array field addresses to helpers
                  (let ((ptr-name (intern (format nil "~a-~a-PTR" (symbol-name name)
                                                  (symbol-name fname))
                                          (symbol-package name))))
                    (push `(cl:defmacro ,ptr-name (ptr)
                             (list '+ ptr ,foffset))
                          accessor-forms)))
                ;; Scalar field: direct load/store with fixed offsets
                (let ((store-type (struct-type-to-store-type ftype)))
                  ;; Reader: (name-field ptr) → (load TYPE ptr OFFSET)
                  (push `(cl:defmacro ,accessor-name (ptr)
                           (list 'load ',store-type ptr ,foffset))
                        accessor-forms)
                  ;; Writer macro: (set-name-field! ptr val) for setf expansion
                  (let ((writer-name (intern (format nil "SET-~a-~a!" (symbol-name name)
                                                     (symbol-name fname))
                                             (symbol-package name))))
                    (push `(cl:defmacro ,writer-name (ptr val)
                             (list 'store ',store-type ptr ,foffset val))
                          accessor-forms)
                    (push `(cl:defsetf ,accessor-name ,writer-name)
                          accessor-forms)))))))
      ;; Generate CL struct + decoder for userspace byte handling.
      ;; The CL struct uses the same name as the BPF struct — the CL
      ;; defstruct accessors (functions) replace the BPF accessors (macros)
      ;; on the same symbols, which is fine: BPF macros are only used inside
      ;; bpf:prog bodies compiled at macroexpand time.
      (let* ((cl-struct-name name)
             (cl-make-name (intern (format nil "MAKE-~a" (symbol-name name))
                                   (symbol-package name)))
             (decode-name (intern (format nil "DECODE-~a" (symbol-name name))
                                  (symbol-package name)))
             (encode-name (intern (format nil "ENCODE-~a" (symbol-name name))
                                  (symbol-package name)))
             (cl-slots (mapcar (lambda (f)
                                 (destructuring-bind (fname ftype foffset fsize) f
                                   (declare (ignore foffset fsize))
                                   (multiple-value-bind (elem-type count is-array)
                                       (parse-field-type ftype)
                                     (declare (ignore elem-type))
                                     (let ((slot-name fname))
                                       (if is-array
                                           `(,slot-name nil)
                                           `(,slot-name 0))))))
                               fields-rev))
             (decode-fields
              (mapcar (lambda (f)
                        (destructuring-bind (fname ftype foffset fsize) f
                          (declare (ignore fsize))
                          (multiple-value-bind (elem-type count is-array)
                              (parse-field-type ftype)
                            (let ((kw (intern (string fname) :keyword)))
                              (if is-array
                                  (let ((byte-len (* count (struct-type-byte-size elem-type))))
                                    `(,kw (subseq bytes ,foffset ,(+ foffset byte-len))))
                                  (cl:case (struct-type-byte-size ftype)
                                    (1 `(,kw (aref bytes ,foffset)))
                                    (2 `(,kw (logior (aref bytes ,foffset)
                                                     (ash (aref bytes ,(1+ foffset)) 8))))
                                    (4 `(,kw (bpf-bytes-u32 bytes ,foffset)))
                                    (8 `(,kw (bpf-bytes-u64 bytes ,foffset)))))))))
                      fields-rev))
             (encode-fields
              (mapcar (lambda (f)
                        (destructuring-bind (fname ftype foffset fsize) f
                          (declare (ignore fsize))
                          (multiple-value-bind (elem-type count is-array)
                              (parse-field-type ftype)
                            (declare (ignore elem-type))
                            (let ((accessor (intern (format nil "~a-~a"
                                                           (symbol-name cl-struct-name)
                                                           (symbol-name fname))
                                                   (symbol-package name))))
                              (if is-array
                                  (let ((byte-len (* count (struct-type-byte-size
                                                            (second ftype)))))
                                    `(replace bytes (,accessor rec)
                                              :start1 ,foffset
                                              :end1 ,(+ foffset byte-len)))
                                  (cl:case (struct-type-byte-size ftype)
                                    (1 `(setf (aref bytes ,foffset) (,accessor rec)))
                                    (2 `(let ((v (,accessor rec)))
                                          (setf (aref bytes ,foffset) (logand v #xff))
                                          (setf (aref bytes ,(1+ foffset)) (logand (ash v -8) #xff))))
                                    (4 `(bpf-put-u32 bytes ,foffset (,accessor rec)))
                                    (8 `(bpf-put-u64 bytes ,foffset (,accessor rec)))))))))
                      fields-rev)))
        `(progn
           (setf (gethash ,(string name) *struct-defs*)
                 (cons ,total ',fields-rev))
           (cl:defmacro ,make-name ()
             '(struct-alloc ,total))
           ,@(nreverse accessor-forms)
           ;; CL struct for userspace
           (cl:defstruct ,cl-struct-name ,@cl-slots)
           ;; Decoder: bytes → CL struct
           (cl:defun ,decode-name (bytes)
             (,cl-make-name ,@(mapcan #'identity decode-fields)))
           ;; Encoder: CL struct → bytes
           (cl:defun ,encode-name (rec)
             (let ((bytes (make-array ,total :element-type '(unsigned-byte 8)
                                             :initial-element 0)))
               ,@encode-fields
               bytes)))))))

(defun lookup-struct-field (struct-name field-name)
  "Look up a field in a struct definition. Returns (type offset size)."
  (let ((def (gethash (string struct-name) *struct-defs*)))
    (unless def
      (whistler-error
       :what (format nil "unknown struct: ~a" struct-name)
       :expected (format nil "(defstruct ~a ...) before this point" struct-name)
       :hint (let ((names (loop for k being the hash-keys of *struct-defs* collect k)))
               (if names (format nil "known structs: ~{~a~^, ~}" names) nil))))
    (let ((field (find (string field-name) (cdr def)
                       :key (lambda (f) (string (first f)))
                       :test #'string=)))
      (unless field
        (let ((fields (mapcar (lambda (f) (first f)) (cdr def))))
          (whistler-error
           :what (format nil "unknown field ~a in struct ~a" field-name struct-name)
           :expected (format nil "one of: ~{~a~^, ~}" fields))))
      (values (second field) (third field) (fourth field)))))

(defmacro struct-set (struct-name var field-name value)
  "Set a field in a struct. Expands to (store TYPE ptr OFFSET val)."
  (multiple-value-bind (ftype foffset) (lookup-struct-field struct-name field-name)
    `(store ,(struct-type-to-store-type ftype) ,var ,foffset ,value)))

(defmacro struct-ref (struct-name var field-name)
  "Read a field from a struct. Expands to (load TYPE ptr OFFSET)."
  (multiple-value-bind (ftype foffset) (lookup-struct-field struct-name field-name)
    `(load ,(struct-type-to-store-type ftype) ,var ,foffset)))

;;; Struct introspection

(defmacro sizeof (struct-name)
  "Return the byte size of a struct defined with defstruct.
   Expands to an integer constant at compile time."
  (let ((def (gethash (string struct-name) *struct-defs*)))
    (unless def
      (whistler-error
       :what (format nil "sizeof: unknown struct ~a" struct-name)
       :expected (format nil "(defstruct ~a ...) before sizeof" struct-name)))
    (car def)))

;;; Memory operations

(defun widen-byte-value (byte-val width)
  "Replicate an 8-bit value across WIDTH bytes. WIDTH must be 1, 2, 4, or 8.
   Returns a signed representation when it fits in s32, so the BPF emitter
   can use mov (1 insn) instead of ld_imm64 (2 insns)."
  (let* ((v (logand byte-val #xFF))
         (unsigned (ecase width
                     (1 v)
                     (2 (logior v (ash v 8)))
                     (4 (logior v (ash v 8) (ash v 16) (ash v 24)))
                     (8 (logior v (ash v 8) (ash v 16) (ash v 24)
                                (ash v 32) (ash v 40) (ash v 48) (ash v 56)))))
         (bits (* width 8)))
    ;; If the value has its sign bit set, convert to signed.
    ;; This lets the emitter use mov r,-1 instead of ld_imm64 for 0xFF fill.
    (if (logbitp (1- bits) unsigned)
        (let ((signed (- unsigned (ash 1 bits))))
          (if (<= -2147483648 signed 2147483647)
              signed
              unsigned))
        unsigned)))

(defmacro memset (ptr offset value nbytes)
  "Fill NBYTES bytes at PTR+OFFSET with VALUE (a byte).
   OFFSET and NBYTES must be compile-time constants.
   When VALUE is a compile-time integer, uses widened stores for efficiency."
  (check-type offset integer)
  (check-type nbytes (integer 0))
  (let ((forms '())
        (pos offset)
        (end (+ offset nbytes)))
    (if (integerp value)
        ;; Compile-time constant: widen and use the largest stores possible
        (let ((v64 (widen-byte-value value 8))
              (v32 (widen-byte-value value 4))
              (v16 (widen-byte-value value 2))
              (v8  (widen-byte-value value 1)))
          (loop while (<= (+ pos 8) end)
                do (push `(store u64 ,ptr ,pos ,v64) forms)
                   (cl:incf pos 8))
          (loop while (<= (+ pos 4) end)
                do (push `(store u32 ,ptr ,pos ,v32) forms)
                   (cl:incf pos 4))
          (loop while (<= (+ pos 2) end)
                do (push `(store u16 ,ptr ,pos ,v16) forms)
                   (cl:incf pos 2))
          (loop while (< pos end)
                do (push `(store u8 ,ptr ,pos ,v8) forms)
                   (cl:incf pos 1)))
        ;; Runtime value: use u8 stores
        (loop while (< pos end)
              do (push `(store u8 ,ptr ,pos ,value) forms)
                 (cl:incf pos 1)))
    `(progn ,@(nreverse forms))))

(defmacro memcpy (dst dst-offset src src-offset nbytes)
  "Copy NBYTES bytes from SRC+SRC-OFFSET to DST+DST-OFFSET.
   All offsets and NBYTES must be compile-time constants.
   Uses the widest possible loads/stores for efficiency."
  (check-type dst-offset integer)
  (check-type src-offset integer)
  (check-type nbytes (integer 0))
  (let ((forms '())
        (pos 0))
    (loop while (<= (+ pos 8) nbytes)
          do (push `(store u64 ,dst ,(+ dst-offset pos)
                          (load u64 ,src ,(+ src-offset pos)))
                   forms)
             (cl:incf pos 8))
    (loop while (<= (+ pos 4) nbytes)
          do (push `(store u32 ,dst ,(+ dst-offset pos)
                          (load u32 ,src ,(+ src-offset pos)))
                   forms)
             (cl:incf pos 4))
    (loop while (<= (+ pos 2) nbytes)
          do (push `(store u16 ,dst ,(+ dst-offset pos)
                          (load u16 ,src ,(+ src-offset pos)))
                   forms)
             (cl:incf pos 2))
    (loop while (< pos nbytes)
          do (push `(store u8 ,dst ,(+ dst-offset pos)
                          (load u8 ,src ,(+ src-offset pos)))
                   forms)
             (cl:incf pos 1))
    `(progn ,@(nreverse forms))))

;;; User-facing macros for defining maps and programs

(defmacro defmap (name &key type (key-size 0) (value-size 0) value-type
                           max-entries (map-flags 0))
  "Define a BPF map. KEY-SIZE and VALUE-SIZE default to 0 (appropriate for
   ringbuf maps which don't use traditional key/value pairs).
   VALUE-TYPE optionally names a struct defined with defstruct.  When provided,
   VALUE-SIZE is derived automatically from the struct definition, and getmap
   returns a map_value pointer instead of a dereferenced scalar."
  (let ((vs (if value-type
                (let ((def (gethash (string value-type) *struct-defs*)))
                  (unless def
                    (error "defmap ~a: :value-type ~a is not a known struct. ~
                            Define it with defstruct before defmap." name value-type))
                  (car def))
                value-size)))
    ;; Validate key/value sizes for non-ringbuf maps
    (when (and (not (eq type :ringbuf))
               (or (eql key-size 0) (eql vs 0)))
      (error "defmap ~a: non-ringbuf maps (~a) require non-zero :key-size and :value-size"
             name type))
    ;; Validate ringbuf maps don't have key/value sizes
    (when (and (eq type :ringbuf)
               (or (not (eql key-size 0)) (and (not value-type) (not (eql vs 0)))))
      (warn "defmap ~a: ringbuf maps don't use :key-size or :value-size (they will be ignored)"
            name))
    `(push (list ',name :type ,type :key-size ,key-size
                        :value-size ,vs
                        ,@(when value-type `(:value-type ',value-type))
                        :max-entries ,max-entries
                        :map-flags ,map-flags)
           *maps*)))

(defmacro defprog (name (&key (type :xdp) (section nil) (license "GPL"))
                   &body body)
  "Define a BPF program. The last expression is implicitly returned —
   no need for an explicit (return ...) at the end."
  (let ((sec (or section (string-downcase (symbol-name type))))
        (wrapped-body (wrap-implicit-return body)))
    `(push (list ',name :section ,sec :license ,license :body ',wrapped-body)
           *programs*)))

(defun wrap-implicit-return (body)
  "If the last form in BODY is not already a (return ...), wrap it."
  (if (null body)
      '((return 0))
      (let* ((last-form (car (last body)))
             (needs-wrap (not (and (consp last-form)
                                   (let ((head (car last-form)))
                                     (and (symbolp head)
                                          (string= (symbol-name head) "RETURN")))))))
        (if needs-wrap
            (append (butlast body) (list `(return ,last-form)))
            body))))

;;; Compilation

(defun compile-to-elf (output-path &key maps programs)
  "Compile maps and programs to an ELF object file.
   Supports multiple programs — each gets its own ELF section."
  (let* ((maps (or maps (reverse *maps*)))
         (progs (or programs (reverse *programs*))))
    (when (null progs)
      (whistler-error
       :what "no BPF programs defined"
       :expected "at least one (defprog name (:type ...) body...) form"
       :hint "add a program, e.g.: (defprog my-prog (:type :xdp :license \"GPL\") XDP_PASS)"))
    ;; Compile each program independently
    (let ((compiled-units
           (mapcar (lambda (prog-spec)
                     (destructuring-bind (name &key section license body) prog-spec
                       (let ((cu (compile-program section license maps body)))
                         (setf (cu-name cu)
                               (substitute #\_ #\-
                                           (string-downcase (symbol-name name))))
                         cu)))
                   progs)))
      ;; Verify all programs declare the same license
      (let ((licenses (mapcar #'cu-license compiled-units)))
        (unless (every (lambda (l) (string= l (first licenses))) (rest licenses))
          (error "Conflicting licenses across programs: ~{~S~^, ~}. ~
                  All programs in a single ELF must share the same license."
                 licenses)))
      ;; Maps are shared — take from first CU (all have the same map list)
      (let* ((first-cu (first compiled-units))
             (map-specs (loop for m in (cu-maps first-cu)
                              collect (list (bpf-map-name m)
                                            (bpf-map-type m)
                                            (bpf-map-key-size m)
                                            (bpf-map-value-size m)
                                            (bpf-map-max-entries m)
                                            (bpf-map-flags m))))
             ;; Build per-program data for ELF writer
             (prog-sections
              (mapcar (lambda (cu)
                        (list (cu-section cu)
                              (insn-bytes (cu-insns cu))
                              (reverse (cu-map-relocs cu))
                              (cu-core-relocs cu)
                              (cu-name cu)))
                      compiled-units))
             (section-names (mapcar #'first prog-sections))
             (prog-names (mapcar #'fifth prog-sections))
             (all-core-relocs (mapcar #'fourth prog-sections)))
        ;; Generate BTF and BTF.ext for all programs
        (multiple-value-bind (btf btf-ext)
            (generate-btf-and-ext *struct-defs* section-names all-core-relocs
                                  map-specs :prog-names prog-names)
          (write-bpf-elf output-path
                         :prog-sections prog-sections
                         :maps map-specs
                         :license (cu-license first-cu)
                         :btf-data btf
                         :btf-ext-data btf-ext))
        (let ((total-insns (reduce #'+ compiled-units :key (lambda (cu) (length (cu-insns cu))))))
          (format t "~&Compiled ~d program~:p (~d instructions total), ~d maps → ~a~%"
                  (length compiled-units) total-insns
                  (length map-specs) output-path))
        ;; Return first CU for backward compatibility
        first-cu))))

;;; SSA pipeline compilation

(defun backend-candidates ()
  "Return backend policy variants to try for SSA-based compilation."
  (list '(:name :baseline-auto
          :reserve-callee-count nil
          :force-save-ctx nil
          :auto-reserve-helper-setup t)
        '(:name :no-helper-reserve
          :reserve-callee-count 0
          :force-save-ctx nil
          :auto-reserve-helper-setup nil)
        '(:name :force-helper-reserve
          :reserve-callee-count 1
          :force-save-ctx nil
          :auto-reserve-helper-setup nil)
        '(:name :force-two-helper-reserves
          :reserve-callee-count 2
          :force-save-ctx nil
          :auto-reserve-helper-setup nil)
        '(:name :force-save-ctx-helper-reserve
          :reserve-callee-count 1
          :force-save-ctx t
          :auto-reserve-helper-setup nil)))

(defun better-cu-p (candidate best)
  "Return true when CANDIDATE should replace BEST."
  (let ((cand-insns (length (cu-insns candidate)))
        (best-insns (length (cu-insns best))))
    (or (< cand-insns best-insns)
        (and (= cand-insns best-insns)
             (< (length (cu-map-relocs candidate))
                (length (cu-map-relocs best)))))))

(defun compile-program (section license maps body)
  "Compile a program through the SSA IR pipeline.
   Returns a compilation-unit."
  ;; Build map structs
  (let ((map-structs
         (loop for map-spec in maps
               for idx from 0
               collect (destructuring-bind (name &key type key-size value-size value-type
                                                 max-entries (map-flags 0))
                           map-spec
                         (declare (ignore value-type))
                         (make-bpf-map
                          :name name
                          :type (whistler/compiler:resolve-map-type type)
                          :key-size key-size
                          :value-size value-size
                          :max-entries max-entries
                          :flags map-flags
                          :index idx)))))
    ;; Macro-expand and constant-fold body
    (let ((expanded (mapcar (lambda (form)
                              (whistler/compiler:constant-fold-sexpr
                               (whistler/compiler:whistler-macroexpand form)))
                            body)))
      ;; Lower + optimize per backend variant. Programs are small enough that
      ;; trying a few complete backend shapes is cheaper than overfitting one
      ;; allocator heuristic path.
      (let ((best-cu nil))
        (dolist (candidate (backend-candidates))
          (let ((ir (whistler/ir:lower-program section license map-structs expanded)))
            (let ((whistler/ir::*force-save-ctx* (getf candidate :force-save-ctx)))
              (whistler/ir:optimize-ir ir)
              (let ((cu (whistler/ir:emit-ir-to-bpf
                         ir
                         :reserve-callee-count (getf candidate :reserve-callee-count)
                         :auto-reserve-helper-setup (getf candidate :auto-reserve-helper-setup))))
                (when (or (null best-cu) (better-cu-p cu best-cu))
                  (setf best-cu cu))))))
        best-cu))))

(defun reset-compilation-state ()
  "Clear accumulated maps, programs, and struct definitions.
   Call this between separate compile-to-elf invocations in the same
   Lisp image when not using compile-file* or with-bpf-session
   (which isolate state automatically)."
  (setf *maps* '()
        *programs* '()
        *user-constants* '())
  (clrhash *struct-defs*)
  (values))

;;; File-based compilation

(defun compile-file* (input-path output-path)
  "Compile a .lisp file to a .bpf.o ELF object."
  (let ((*maps* '())
        (*programs* '())
        (*struct-defs* (make-hash-table :test 'equal)))
    ;; Load and evaluate the source file (it uses defmap/defprog)
    (load input-path)
    (compile-to-elf output-path)))

;;; Disassembly (for debugging)

(defun disassemble-cu (cu &optional (stream *standard-output*))
  "Print a human-readable disassembly of a compilation unit."
  (format stream "~&; Section: ~a~%" (cu-section cu))
  (format stream "; License: ~a~%" (cu-license cu))
  (format stream "; Maps:~%")
  (dolist (m (cu-maps cu))
    (format stream ";   ~a: type=~d key=~d val=~d max=~d~%"
            (bpf-map-name m) (bpf-map-type m)
            (bpf-map-key-size m) (bpf-map-value-size m)
            (bpf-map-max-entries m)))
  (format stream "; Instructions (~d):~%" (length (cu-insns cu)))
  (loop for insn in (cu-insns cu)
        for i from 0
        do (format stream "  ~3d: ~2,'0x ~d ~d ~4d ~8d~%"
                  i
                  (bpf-insn-code insn)
                  (bpf-insn-dst insn)
                  (bpf-insn-src insn)
                  (bpf-insn-off insn)
                  (bpf-insn-imm insn)))
  (when (cu-map-relocs cu)
    (format stream "; Relocations:~%")
    (dolist (r (cu-map-relocs cu))
      (format stream ";   insn-byte-offset=~d map-index=~d~%"
              (first r) (second r)))))

;;; CLI entry point

(defun main ()
  "CLI entry point for whistler."
  (let ((args (uiop:command-line-arguments)))
    (cond
      ((or (member "--version" args :test #'string=)
           (member "-V" args :test #'string=))
       (format t "whistler ~a~%" *version*))

      ((or (null args) (member "--help" args :test #'string=)
           (member "-h" args :test #'string=))
       (format t "whistler ~a - copyright (C) 2026 Anthony Green <green@moxielogic.com>~%"
               *version*)
       (format t "~%A Lisp that compiles to eBPF.~%")
       (format t "~%Usage: whistler [-h|--help] [-V|--version] command~%")
       (format t "~%Available options:~%")
       (format t "  -h, --help              show this help text~%")
       (format t "  -V, --version           show version information~%")
       (format t "~%Choose from the following whistler commands:~%")
       (format t "~%   compile INPUT [-o OUTPUT] [--gen LANG...]~%")
       (format t "                                  Compile .lisp to .bpf.o ELF object~%")
       (format t "   disasm INPUT                   Disassemble to stdout~%")
       (format t "   version                        Show version information~%")
       (format t "~%Compile options:~%")
       (format t "   -o FILE                        Output .bpf.o path~%")
       (format t "   --gen LANG                     Generate shared type header~%")
       (format t "                                  LANG: c, go, rust, python, lisp, all~%")
       (format t "                                  May be repeated: --gen c --gen python~%")
       (format t "~%Distributed under the terms of the MIT License~%"))

      ((string= (first args) "version")
       (format t "whistler ~a~%" *version*))

      ((string= (first args) "compile")
       (let* ((input (second args))
              (rest-args (cddr args))
              (output (or (let ((pos (position "-o" rest-args :test #'string=)))
                            (when pos (nth (1+ pos) rest-args)))
                          (concatenate 'string
                                       (if (search ".lisp" input)
                                           (subseq input 0 (search ".lisp" input))
                                           (if (search ".lisp" input)
                                               (subseq input 0 (search ".lisp" input))
                                               input))
                                       ".bpf.o")))
              (base (if (search ".bpf.o" output)
                        (subseq output 0 (search ".bpf.o" output))
                        output))
              ;; Collect --gen languages
              (gen-langs '()))
         (loop for i from 0 below (length rest-args)
               when (string= (nth i rest-args) "--gen")
               do (let ((lang (nth (1+ i) rest-args)))
                    (when lang (push (string-downcase lang) gen-langs))))
         (unless input
           (format *error-output* "Error: no input file~%")
           (uiop:quit 1))
         (if gen-langs
             ;; Compile + generate headers
             (let ((*maps* '())
                   (*programs* '())
                   (*struct-defs* (make-hash-table :test 'equal)))
               (load input)
               (let ((*user-constants* (collect-user-constants-from-file input)))
                   (compile-to-elf output)
                   (let ((all (member "all" gen-langs :test #'string=)))
                     (when (or all (member "c" gen-langs :test #'string=))
                       (generate-c-header (format nil "~a.h" base)))
                     (when (or all (member "go" gen-langs :test #'string=))
                       (generate-go-header (format nil "~a_types.go" base)))
                     (when (or all (member "rust" gen-langs :test #'string=))
                       (generate-rust-header (format nil "~a_types.rs" base)))
                     (when (or all (member "python" gen-langs :test #'string=))
                       (generate-python-header (format nil "~a_types.py" base)))
                     (when (or all (member "lisp" gen-langs :test #'string=))
                       (generate-cl-header (format nil "~a_types.lisp" base))))))
             ;; Just compile
             (compile-file* input output))))

      ((string= (first args) "disasm")
       (let ((input (second args)))
         (unless input
           (format *error-output* "Error: no input file~%")
           (uiop:quit 1))
         (let ((*maps* '())
               (*programs* '())
               (*struct-defs* (make-hash-table :test 'equal)))
           (load input)
           (let* ((maps (reverse *maps*))
                  (progs (reverse *programs*)))
             (destructuring-bind (name &key section license body) (first progs)
               (declare (ignore name))
               (let ((cu (compile-program section license maps body)))
                 (disassemble-cu cu)))))))

      (t
       (format *error-output* "Unknown command: ~a~%" (first args))
       (uiop:quit 1)))))
