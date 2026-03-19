;;; -*- Mode: Lisp -*-
;;;
;;; Copyright (c) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; SPDX-License-Identifier: MIT

(in-package #:whistler/btf)

;;; BTF (BPF Type Format) encoder
;;; Produces .BTF section bytes for BPF ELF objects.
;;; Reference: kernel Documentation/bpf/btf.rst

;;; BTF constants

(defconstant +btf-magic+ #xeB9F)
(defconstant +btf-version+ 1)
(defconstant +btf-header-size+ 24)

;; BTF type kinds (stored in bits 24-28 of info field)
(defconstant +btf-kind-int+        1)
(defconstant +btf-kind-ptr+        2)
(defconstant +btf-kind-array+      3)
(defconstant +btf-kind-struct+     4)
(defconstant +btf-kind-var+       14)
(defconstant +btf-kind-datasec+   15)
(defconstant +btf-kind-func-proto+ 13)
(defconstant +btf-kind-func+      12)

;; BTF_INT encoding bits
(defconstant +btf-int-signed+ (ash 1 0))

;;; BTF string table

(defstruct btf-strtab
  (data (let ((v (make-array 16 :element-type '(unsigned-byte 8)
                                :adjustable t :fill-pointer 0)))
          (vector-push-extend 0 v)  ; initial NUL byte
          v)))

(defun btf-strtab-add (strtab string)
  "Add a string to the BTF string table, return its offset."
  (let ((data (btf-strtab-data strtab))
        (offset (length (btf-strtab-data strtab))))
    (loop for ch across string
          do (vector-push-extend (char-code ch) data))
    (vector-push-extend 0 data)
    offset))

;;; BTF context

(defstruct btf-ctx
  (types (make-array 16 :element-type '(unsigned-byte 8)
                        :adjustable t :fill-pointer 0))
  (strtab (make-btf-strtab))
  (next-id 1)
  (type-cache (make-hash-table :test 'equal)))  ; name -> type-id

(defun btf-emit-u32 (vec val)
  "Append a little-endian u32 to an adjustable byte vector."
  (vector-push-extend (logand val #xff) vec)
  (vector-push-extend (logand (ash val -8) #xff) vec)
  (vector-push-extend (logand (ash val -16) #xff) vec)
  (vector-push-extend (logand (ash val -24) #xff) vec))

(defun btf-alloc-id (ctx)
  "Allocate and return the next type ID."
  (prog1 (btf-ctx-next-id ctx)
    (incf (btf-ctx-next-id ctx))))

;;; BTF type emitters

(defun btf-info-field (kind vlen)
  "Encode the BTF type info word: kind in bits 24-28, vlen in bits 0-15."
  (logior (ash kind 24) (logand vlen #xffff)))

(defun btf-add-int (ctx name bits)
  "Add a BTF_KIND_INT type. Returns the type ID."
  (let* ((id (btf-alloc-id ctx))
         (name-off (btf-strtab-add (btf-ctx-strtab ctx) name))
         (types (btf-ctx-types ctx)))
    ;; Type header: name_off(4), info(4), size(4) = 12 bytes
    (btf-emit-u32 types name-off)
    (btf-emit-u32 types (btf-info-field +btf-kind-int+ 0))
    (btf-emit-u32 types (/ bits 8))  ; size in bytes
    ;; INT data: encoding(8:8), offset(8:8), bits(8:8) packed in 4 bytes
    ;; encoding = 0 (unsigned), offset = 0, bits = actual bit width
    (btf-emit-u32 types (logior (ash 0 24)    ; encoding: unsigned
                                (ash 0 16)    ; offset: 0
                                bits))        ; nr_bits
    (setf (gethash name (btf-ctx-type-cache ctx)) id)
    id))

(defun btf-resolve-field-type (ctx ftype fname)
  "Resolve a field type to a BTF type ID. Handles both scalar types
   and (:array elem-type count) array types."
  (if (and (consp ftype) (eq (car ftype) :array))
      ;; Array field: create BTF array type on demand
      (let* ((elem-type (second ftype))
             (count (third ftype))
             (cache-key (format nil "~a[~d]" (string-downcase (string elem-type)) count))
             (cached (gethash cache-key (btf-ctx-type-cache ctx))))
        (or cached
            (let* ((elem-type-id (or (gethash (string-downcase (string elem-type))
                                              (btf-ctx-type-cache ctx))
                                     (error "Unknown BTF type for array element ~a in field ~a"
                                            elem-type fname)))
                   (index-type-id (or (gethash "u32" (btf-ctx-type-cache ctx))
                                      (error "BTF u32 type not found for array index")))
                   (arr-id (btf-add-array ctx elem-type-id index-type-id count)))
              (setf (gethash cache-key (btf-ctx-type-cache ctx)) arr-id)
              arr-id)))
      ;; Scalar field
      (let ((type-name (string-downcase (string ftype))))
        (or (gethash type-name (btf-ctx-type-cache ctx))
            (error "Unknown BTF type for field ~a: ~a" fname ftype)))))

(defun btf-add-struct (ctx name fields)
  "Add a BTF_KIND_STRUCT type.
   FIELDS is a list of (field-name type offset size) as from *struct-defs*.
   Type may be a symbol (scalar) or (:array elem-type count).
   Returns the type ID."
  ;; Resolve all field types FIRST — array fields append BTF_KIND_ARRAY
  ;; records to the types vector, so this must complete before we start
  ;; emitting the contiguous struct type + member entries.
  (let ((resolved (mapcar (lambda (field)
                            (destructuring-bind (fname ftype foffset fsize) field
                              (list fname ftype foffset fsize
                                    (btf-resolve-field-type ctx ftype fname))))
                          fields)))
    (let* ((id (btf-alloc-id ctx))
           (name-off (btf-strtab-add (btf-ctx-strtab ctx) name))
           (types (btf-ctx-types ctx))
           (total-size (loop for (nil nil off sz) in fields
                             maximize (+ off sz))))
      ;; Type header
      (btf-emit-u32 types name-off)
      (btf-emit-u32 types (btf-info-field +btf-kind-struct+ (length fields)))
      (btf-emit-u32 types total-size)
      ;; Member entries: name_off(4), type(4), offset(4) = 12 bytes each
      (dolist (field resolved)
        (destructuring-bind (fname ftype foffset fsize type-id) field
          (declare (ignore ftype fsize))
          (let ((fname-off (btf-strtab-add (btf-ctx-strtab ctx)
                                           (string-downcase (string fname)))))
            (btf-emit-u32 types fname-off)
            (btf-emit-u32 types type-id)
            ;; Offset in bits
            (btf-emit-u32 types (* foffset 8)))))
      (setf (gethash name (btf-ctx-type-cache ctx)) id)
      id)))

(defun btf-add-func-proto (ctx ret-type-id params)
  "Add a BTF_KIND_FUNC_PROTO type.
   PARAMS is a list of (name-string type-id).
   Returns the type ID."
  (let* ((id (btf-alloc-id ctx))
         (types (btf-ctx-types ctx)))
    ;; name_off = 0 for FUNC_PROTO
    (btf-emit-u32 types 0)
    (btf-emit-u32 types (btf-info-field +btf-kind-func-proto+ (length params)))
    (btf-emit-u32 types ret-type-id)
    ;; Param entries: name_off(4), type(4) = 8 bytes each
    (dolist (param params)
      (destructuring-bind (pname ptype-id) param
        (let ((pname-off (btf-strtab-add (btf-ctx-strtab ctx) pname)))
          (btf-emit-u32 types pname-off)
          (btf-emit-u32 types ptype-id))))
    id))

(defun btf-add-func (ctx name proto-type-id)
  "Add a BTF_KIND_FUNC type. Returns the type ID."
  (let* ((id (btf-alloc-id ctx))
         (name-off (btf-strtab-add (btf-ctx-strtab ctx) name))
         (types (btf-ctx-types ctx)))
    ;; FUNC: name_off(4), info(4), type(4) — type points to FUNC_PROTO
    (btf-emit-u32 types name-off)
    ;; vlen=0 for FUNC; BTF_FUNC_STATIC=0, BTF_FUNC_GLOBAL=1
    (btf-emit-u32 types (btf-info-field +btf-kind-func+ 0))
    (btf-emit-u32 types proto-type-id)
    id))

(defun btf-add-ptr (ctx target-type-id)
  "Add a BTF_KIND_PTR type. Returns the type ID."
  (let* ((id (btf-alloc-id ctx))
         (types (btf-ctx-types ctx)))
    (btf-emit-u32 types 0)  ; name_off = 0 (anonymous)
    (btf-emit-u32 types (btf-info-field +btf-kind-ptr+ 0))
    (btf-emit-u32 types target-type-id)
    id))

(defun btf-add-array (ctx elem-type-id index-type-id nelems)
  "Add a BTF_KIND_ARRAY type. Returns the type ID."
  (let* ((id (btf-alloc-id ctx))
         (types (btf-ctx-types ctx)))
    (btf-emit-u32 types 0)  ; name_off = 0
    (btf-emit-u32 types (btf-info-field +btf-kind-array+ 0))
    (btf-emit-u32 types 0)  ; size = 0
    ;; Array data: type(4) index_type(4) nelems(4)
    (btf-emit-u32 types elem-type-id)
    (btf-emit-u32 types index-type-id)
    (btf-emit-u32 types nelems)
    id))

(defun btf-add-var (ctx name type-id &optional (linkage 1))
  "Add a BTF_KIND_VAR type. LINKAGE: 0=static, 1=global. Returns the type ID."
  (let* ((id (btf-alloc-id ctx))
         (name-off (btf-strtab-add (btf-ctx-strtab ctx) name))
         (types (btf-ctx-types ctx)))
    (btf-emit-u32 types name-off)
    (btf-emit-u32 types (btf-info-field +btf-kind-var+ 0))
    (btf-emit-u32 types type-id)
    ;; Linkage
    (btf-emit-u32 types linkage)
    id))

(defun btf-add-datasec (ctx name vars)
  "Add a BTF_KIND_DATASEC type.
   VARS is a list of (var-type-id offset size). Returns the type ID."
  (let* ((id (btf-alloc-id ctx))
         (name-off (btf-strtab-add (btf-ctx-strtab ctx) name))
         (types (btf-ctx-types ctx)))
    (btf-emit-u32 types name-off)
    (btf-emit-u32 types (btf-info-field +btf-kind-datasec+ (length vars)))
    (btf-emit-u32 types 0)  ; size = 0 (resolved by loader)
    ;; Variable entries: type_id(4) offset(4) size(4)
    (dolist (var vars)
      (destructuring-bind (var-type-id offset size) var
        (btf-emit-u32 types var-type-id)
        (btf-emit-u32 types offset)
        (btf-emit-u32 types size)))
    id))

;;; Encoding

(defun btf-encode (ctx)
  "Serialize the BTF context into a complete .BTF section byte vector."
  (let* ((type-data (btf-ctx-types ctx))
         (str-data (btf-strtab-data (btf-ctx-strtab ctx)))
         (type-len (length type-data))
         (str-len (length str-data))
         (total (+ +btf-header-size+ type-len str-len))
         (out (make-array total :element-type '(unsigned-byte 8) :initial-element 0))
         (pos 0))
    (flet ((put-u8 (val)
             (setf (aref out pos) (logand val #xff))
             (incf pos))
           (put-u16 (val)
             (setf (aref out pos) (logand val #xff))
             (setf (aref out (+ pos 1)) (logand (ash val -8) #xff))
             (incf pos 2))
           (put-u32 (val)
             (setf (aref out pos) (logand val #xff))
             (setf (aref out (+ pos 1)) (logand (ash val -8) #xff))
             (setf (aref out (+ pos 2)) (logand (ash val -16) #xff))
             (setf (aref out (+ pos 3)) (logand (ash val -24) #xff))
             (incf pos 4)))
      ;; Header (24 bytes)
      (put-u16 +btf-magic+)                    ; magic
      (put-u8 +btf-version+)                   ; version
      (put-u8 0)                                ; flags
      (put-u32 +btf-header-size+)              ; hdr_len
      ;; Type section: immediately after header
      (put-u32 0)                               ; type_off
      (put-u32 type-len)                        ; type_len
      ;; String section: after types
      (put-u32 type-len)                        ; str_off
      (put-u32 str-len))                        ; str_len
    ;; Copy type data
    (replace out type-data :start1 +btf-header-size+)
    ;; Copy string data
    (replace out str-data :start1 (+ +btf-header-size+ type-len))
    out))

;;; Top-level entry points

(defun btf-add-map-def (ctx map-name map-type key-size value-size max-entries map-flags)
  "Add BTF types for a BTF-defined map.
   Creates: struct type with type/key_size/value_size/max_entries fields,
   and a VAR referencing it. Returns the VAR type ID."
  (let* ((int-id (gethash "u32" (btf-ctx-type-cache ctx)))
         ;; __uint(type, N) → int (*type)[N]  (ptr to array of N ints)
         (type-arr-id (btf-add-array ctx int-id int-id map-type))
         (type-ptr-id (btf-add-ptr ctx type-arr-id))
         ;; key_size and value_size as __uint
         (key-arr-id (btf-add-array ctx int-id int-id key-size))
         (key-ptr-id (btf-add-ptr ctx key-arr-id))
         (val-arr-id (btf-add-array ctx int-id int-id value-size))
         (val-ptr-id (btf-add-ptr ctx val-arr-id))
         (max-arr-id (btf-add-array ctx int-id int-id max-entries))
         (max-ptr-id (btf-add-ptr ctx max-arr-id))
         ;; Build the map struct: { type, key_size, value_size, max_entries [, map_flags] }
         (fields (list (list "type" type-ptr-id 0)
                       (list "key_size" key-ptr-id 64)
                       (list "value_size" val-ptr-id 128)
                       (list "max_entries" max-ptr-id 192))))
    ;; Add map_flags field if non-zero
    (when (and map-flags (> map-flags 0))
      (let* ((flags-arr-id (btf-add-array ctx int-id int-id map-flags))
             (flags-ptr-id (btf-add-ptr ctx flags-arr-id)))
        (setf fields (append fields
                             (list (list "map_flags" flags-ptr-id 256))))))
    ;; Create the struct type
    (let* ((struct-id (btf-alloc-id ctx))
           (types (btf-ctx-types ctx))
           (nfields (length fields))
           (struct-size (* 8 nfields)))  ; 8 bytes per ptr field
      ;; Type header
      (btf-emit-u32 types 0)  ; anonymous struct
      (btf-emit-u32 types (btf-info-field +btf-kind-struct+ nfields))
      (btf-emit-u32 types struct-size)
      ;; Members
      (dolist (field fields)
        (destructuring-bind (fname ftype-id fbits-offset) field
          (let ((fname-off (btf-strtab-add (btf-ctx-strtab ctx) fname)))
            (btf-emit-u32 types fname-off)
            (btf-emit-u32 types ftype-id)
            (btf-emit-u32 types fbits-offset))))
      ;; Create VAR for the map
      (let ((var-id (btf-add-var ctx (lisp-to-c-name map-name)
                                 struct-id 1)))  ; linkage=global
        (values var-id struct-size)))))

(defun build-btf-ctx (struct-defs section-names &optional map-specs)
  "Build a BTF context with base types, struct defs, map defs, and function info.
   SECTION-NAMES is a string or list of strings (one per program).
   MAP-SPECS is a list of (name type key-size value-size max-entries flags).
   Returns (values ctx func-type-ids) where func-type-ids is a list of FUNC type IDs."
  (let ((ctx (make-btf-ctx))
        (names (if (listp section-names) section-names (list section-names))))
    ;; 1. Add base integer types
    (btf-add-int ctx "u8"  8)
    (btf-add-int ctx "u16" 16)
    (btf-add-int ctx "u32" 32)
    (btf-add-int ctx "u64" 64)

    ;; 2. Add struct types from *struct-defs*
    (maphash (lambda (name def)
               (let ((fields (cdr def)))  ; skip total-size
                 (btf-add-struct ctx (lisp-to-c-name name) fields)))
             struct-defs)

    ;; 3. Add xdp_md if any section is XDP and not already defined
    (when (and (some (lambda (s) (search "xdp" (string-downcase s))) names)
               (not (gethash "xdp_md" (btf-ctx-type-cache ctx))))
      (btf-add-struct ctx "xdp_md"
                      '((data u32 0 4)
                        (data_end u32 4 4)
                        (data_meta u32 8 4)
                        (ingress_ifindex u32 12 4)
                        (rx_queue_index u32 16 4))))

    ;; 4. Add BTF-defined map types + .maps DATASEC
    (when map-specs
      (let ((map-vars '()))
        (loop for (name type key-size value-size max-entries flags) in map-specs
              for offset from 0 by 32  ; 32 bytes per map entry in .maps
              do (multiple-value-bind (var-id struct-size)
                     (btf-add-map-def ctx name type key-size value-size
                                      max-entries (or flags 0))
                   (push (list var-id offset struct-size) map-vars)))
        (btf-add-datasec ctx ".maps" (nreverse map-vars))))

    ;; 5. Add FUNC_PROTO (ret=u32, param ctx=u64) + FUNC for each program
    (let* ((u32-id (gethash "u32" (btf-ctx-type-cache ctx)))
           (u64-id (gethash "u64" (btf-ctx-type-cache ctx)))
           (proto-id (btf-add-func-proto ctx u32-id (list (list "ctx" u64-id))))
           (func-ids (mapcar (lambda (name)
                               ;; BTF FUNC names must be valid C identifiers.
                               ;; Section names like "tracepoint/sock/foo"
                               ;; need sanitizing — use last component.
                               (let ((func-name (let ((pos (position #\/ name :from-end t)))
                                                  (if pos (subseq name (1+ pos)) name))))
                                 (btf-add-func ctx func-name proto-id)))
                             names)))
      (values ctx func-ids))))

(defun generate-btf (struct-defs section-names)
  "Generate BTF section bytes.
   STRUCT-DEFS is a hash table of name -> (total-size . fields).
   SECTION-NAMES is a string or list of section names.
   Returns a byte vector suitable for a .BTF ELF section."
  (let ((ctx (build-btf-ctx struct-defs section-names)))
    (btf-encode ctx)))

;;; ========== BTF.ext encoding ==========

(defconstant +btf-ext-magic+ #xeB9F)
(defconstant +btf-ext-version+ 1)
(defconstant +btf-ext-header-size+ 32)

;; CO-RE relocation kinds
(defconstant +bpf-core-field-byte-offset+ 0)

(defun lisp-to-c-name (sym)
  "Convert a Lisp symbol name to C-style: lowercase, hyphens to underscores."
  (substitute #\_ #\- (string-downcase (string sym))))

;; Known kernel struct field lists for CO-RE (not in user *struct-defs*)
(defparameter *kernel-struct-fields*
  '(("xdp_md" . (data data_end data_meta ingress_ifindex rx_queue_index))))

(defun struct-field-index (struct-defs struct-name field-name)
  "Look up the field index for FIELD-NAME in STRUCT-NAME.
   Checks user struct-defs first, then kernel struct definitions.
   Returns the 0-based index in the field list."
  (let* ((c-struct (lisp-to-c-name struct-name))
         (c-field (lisp-to-c-name field-name))
         ;; Check user-defined structs
         (def (or (gethash (string struct-name) struct-defs)
                  (gethash (string-downcase (string struct-name)) struct-defs))))
    (if def
        (let ((fields (cdr def)))
          (loop for field in fields
                for idx from 0
                when (string-equal (string (first field)) (string field-name))
                return idx))
        ;; Check kernel structs
        (let ((kernel (assoc c-struct *kernel-struct-fields* :test #'string=)))
          (when kernel
            (loop for f in (cdr kernel)
                  for idx from 0
                  when (string-equal (string f) c-field)
                  return idx))))))

(defun btf-ext-encode (ctx section-names func-type-ids per-section-core-relocs struct-defs)
  "Encode .BTF.ext section bytes for one or more programs.
   CTX: the btf-ctx (shared string table).
   SECTION-NAMES: list of program section name strings.
   FUNC-TYPE-IDS: list of BTF FUNC type IDs (one per program).
   PER-SECTION-CORE-RELOCS: list of core-reloc lists (one list per program).
   STRUCT-DEFS: struct definitions hash table.
   Returns a byte vector."
  (let ((strtab (btf-ctx-strtab ctx)))

    ;; Build func_info subsection — one entry per program
    (let ((func-info (make-array 32 :element-type '(unsigned-byte 8)
                                    :adjustable t :fill-pointer 0)))
      ;; rec_size = 8
      (btf-emit-u32 func-info 8)
      ;; One section header + record per program
      (loop for sec-name in section-names
            for func-id in func-type-ids
            do (let ((sec-off (btf-strtab-add strtab sec-name)))
                 (btf-emit-u32 func-info sec-off)
                 (btf-emit-u32 func-info 1)          ; num_info = 1
                 (btf-emit-u32 func-info 0)          ; insn_off = 0
                 (btf-emit-u32 func-info func-id)))  ; type_id

      ;; Build line_info subsection — one minimal entry per program.
      ;; The kernel requires at least one bpf_line_info per function
      ;; when func_info is present.
      ;; bpf_line_info = { insn_off(u32), file_name_off(u32),
      ;;                   line_off(u32), line_col(u32) } = 16 bytes
      (let ((line-info (make-array 32 :element-type '(unsigned-byte 8)
                                      :adjustable t :fill-pointer 0))
            (synth-file-off (btf-strtab-add strtab "<whistler>"))
            (synth-line-off (btf-strtab-add strtab "; whistler-generated")))
        ;; rec_size = 16
        (btf-emit-u32 line-info 16)
        ;; One section header + one record per program
        (loop for sec-name in section-names
              do (let ((sec-off (btf-strtab-add strtab sec-name)))
                   ;; Section header: sec_name_off, num_info
                   (btf-emit-u32 line-info sec-off)
                   (btf-emit-u32 line-info 1)           ; num_info = 1
                   ;; bpf_line_info record
                   (btf-emit-u32 line-info 0)           ; insn_off = 0 (first insn)
                   (btf-emit-u32 line-info synth-file-off) ; file_name_off
                   (btf-emit-u32 line-info synth-line-off) ; line_off
                   (btf-emit-u32 line-info (ash 1 10)))) ; line_col = line 1, col 0

      ;; Build core_relo subsection
      (let ((core-relo (make-array 32 :element-type '(unsigned-byte 8)
                                      :adjustable t :fill-pointer 0))
            (has-any-relocs (some #'identity per-section-core-relocs)))
        (when has-any-relocs
          ;; rec_size = 16
          (btf-emit-u32 core-relo 16)
          ;; Per-section core relocs
          (loop for sec-name in section-names
                for core-relocs in per-section-core-relocs
                when core-relocs
                do (let ((sec-off (btf-strtab-add strtab sec-name)))
                     (btf-emit-u32 core-relo sec-off)
                     (btf-emit-u32 core-relo (length core-relocs))
                     (dolist (reloc core-relocs)
                       (destructuring-bind (byte-off struct-name field-name) reloc
                         (let* ((type-name (lisp-to-c-name struct-name))
                                (type-id (gethash type-name (btf-ctx-type-cache ctx)))
                                (field-idx (or (struct-field-index struct-defs struct-name field-name)
                                               0))
                                (access-str (format nil "0:~d" field-idx))
                                (access-off (btf-strtab-add strtab access-str)))
                           (btf-emit-u32 core-relo byte-off)
                           (btf-emit-u32 core-relo (or type-id 0))
                           (btf-emit-u32 core-relo access-off)
                           (btf-emit-u32 core-relo +bpf-core-field-byte-offset+)))))))

        ;; Assemble header + subsections
        (let* ((func-info-len (length func-info))
               (line-info-len (length line-info))
               (core-relo-len (length core-relo))
               (func-info-off 0)
               (line-info-off func-info-len)
               (core-relo-off (+ func-info-len line-info-len))
               (total (+ +btf-ext-header-size+ func-info-len line-info-len core-relo-len))
               (out (make-array total :element-type '(unsigned-byte 8) :initial-element 0))
               (pos 0))
          (flet ((put-u8 (val)
                   (setf (aref out pos) (logand val #xff))
                   (incf pos))
                 (put-u16 (val)
                   (setf (aref out pos) (logand val #xff))
                   (setf (aref out (+ pos 1)) (logand (ash val -8) #xff))
                   (incf pos 2))
                 (put-u32 (val)
                   (setf (aref out pos) (logand val #xff))
                   (setf (aref out (+ pos 1)) (logand (ash val -8) #xff))
                   (setf (aref out (+ pos 2)) (logand (ash val -16) #xff))
                   (setf (aref out (+ pos 3)) (logand (ash val -24) #xff))
                   (incf pos 4)))
            ;; Header (32 bytes)
            (put-u16 +btf-ext-magic+)
            (put-u8 +btf-ext-version+)
            (put-u8 0)  ; flags
            (put-u32 +btf-ext-header-size+)
            (put-u32 func-info-off)
            (put-u32 func-info-len)
            (put-u32 line-info-off)
            (put-u32 line-info-len)
            (put-u32 core-relo-off)
            (put-u32 core-relo-len))
          ;; Copy subsection data
          (replace out func-info :start1 +btf-ext-header-size+)
          (replace out line-info :start1 (+ +btf-ext-header-size+ line-info-off))
          (when (plusp core-relo-len)
            (replace out core-relo :start1 (+ +btf-ext-header-size+ core-relo-off)))
          out))))))

(defun generate-btf-and-ext (struct-defs section-names per-section-core-relocs
                             &optional map-specs)
  "Generate both .BTF and .BTF.ext section bytes for one or more programs.
   STRUCT-DEFS: hash table of name -> (total-size . fields).
   SECTION-NAMES: string or list of section name strings.
   PER-SECTION-CORE-RELOCS: list of core-reloc lists (one per program).
   MAP-SPECS: list of (name type key-size value-size max-entries flags).
   Returns (values btf-bytes btf-ext-bytes)."
  (let ((names (if (listp section-names) section-names (list section-names)))
        (relocs-per-section (if (and (listp section-names)
                                     (listp per-section-core-relocs))
                                per-section-core-relocs
                                (list per-section-core-relocs))))
    (multiple-value-bind (ctx func-ids) (build-btf-ctx struct-defs names map-specs)
      ;; Encode BTF.ext BEFORE btf-encode, so access strings get into the
      ;; shared string table before it's serialized.
      (let ((btf-ext (btf-ext-encode ctx names func-ids
                                     relocs-per-section struct-defs)))
        (values (btf-encode ctx) btf-ext)))))
