;;; -*- Mode: Lisp -*-
;;;
;;; Copyright (c) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; SPDX-License-Identifier: MIT

(in-package #:whistler)

;;; Shared header code generation
;;;
;;; Generates matching struct definitions and constants for userland code
;;; in C, Go, and Rust. These are "shared headers" — the types that both
;;; the BPF program and the userland loader need to agree on.

;;; ========== Name conversion ==========

(defun lisp-to-c-ident (name)
  "Convert a Lisp name to C identifier: lowercase, hyphens to underscores.
   Strips +earmuffs+ from constants."
  (let* ((s (string name))
         (s (if (and (> (length s) 2)
                     (char= (char s 0) #\+)
                     (char= (char s (1- (length s))) #\+))
                (subseq s 1 (1- (length s)))
                s)))
    (substitute #\_ #\- (string-downcase s))))

(defun lisp-to-pascal (name)
  "Convert a Lisp name to PascalCase: ct4-key → Ct4Key."
  (let* ((s (string name))
         (s (if (and (> (length s) 2)
                     (char= (char s 0) #\+)
                     (char= (char s (1- (length s))) #\+))
                (subseq s 1 (1- (length s)))
                s)))
    (let ((parts (uiop:split-string (string-downcase s) :separator "-")))
      (format nil "~{~:(~a~)~}" parts))))

(defun lisp-to-screaming-snake (name)
  "Convert a Lisp name to SCREAMING_SNAKE_CASE: +syn-threshold+ → SYN_THRESHOLD."
  (let* ((s (string name))
         (s (if (and (> (length s) 2)
                     (char= (char s 0) #\+)
                     (char= (char s (1- (length s))) #\+))
                (subseq s 1 (1- (length s)))
                s)))
    (substitute #\_ #\- (string-upcase s))))

;;; ========== Type mapping ==========

(defun c-type-for (whistler-type)
  (let ((n (string-upcase (string whistler-type))))
    (cond ((string= n "U8") "uint8_t") ((string= n "U16") "uint16_t")
          ((string= n "U32") "uint32_t") ((string= n "U64") "uint64_t")
          ((string= n "I8") "int8_t") ((string= n "I16") "int16_t")
          ((string= n "I32") "int32_t") ((string= n "I64") "int64_t")
          (t "uint64_t"))))

(defun go-type-for (whistler-type)
  (let ((n (string-upcase (string whistler-type))))
    (cond ((string= n "U8") "uint8") ((string= n "U16") "uint16")
          ((string= n "U32") "uint32") ((string= n "U64") "uint64")
          ((string= n "I8") "int8") ((string= n "I16") "int16")
          ((string= n "I32") "int32") ((string= n "I64") "int64")
          (t "uint64"))))

(defun rust-type-for (whistler-type)
  (let ((n (string-upcase (string whistler-type))))
    (cond ((string= n "U8") "u8") ((string= n "U16") "u16")
          ((string= n "U32") "u32") ((string= n "U64") "u64")
          ((string= n "I8") "i8") ((string= n "I16") "i16")
          ((string= n "I32") "i32") ((string= n "I64") "i64")
          (t "u64"))))

;;; ========== Constant collection ==========

(defvar *user-constants* '()
  "Constants defined by user code in the current compilation.")

(defun collect-package-constants (pkg)
  "Return an alist of (symbol-name . value) for all integer constants in PKG."
  (let ((result '()))
    (do-symbols (sym pkg)
      (when (and (boundp sym) (constantp sym)
                 (not (keywordp sym))
                 (integerp (symbol-value sym)))
        (push (cons (symbol-name sym) (symbol-value sym)) result)))
    result))

(defun find-new-constants (before after)
  "Find constants in AFTER that are new or changed vs BEFORE.
   Both are alists of (name . value). Returns a list of symbols."
  (let ((before-map (make-hash-table :test 'equal))
        (result '()))
    (dolist (entry before)
      (setf (gethash (car entry) before-map) (cdr entry)))
    (dolist (entry after)
      (let ((old-val (gethash (car entry) before-map :missing)))
        (when (or (eq old-val :missing)
                  (not (eql old-val (cdr entry))))
          (let ((sym (find-symbol (car entry) (find-package '#:whistler))))
            (when sym (push sym result))))))
    result))

(defun collect-user-constants-from-file (path)
  "Scan a .lisp file for (defconstant +NAME+ VALUE) forms and return
   a list of the corresponding interned symbols after loading."
  (let ((names '()))
    (with-open-file (in path)
      (loop for line = (read-line in nil)
            while line
            do (let ((trimmed (string-trim '(#\Space #\Tab) line)))
                 (when (and (>= (length trimmed) 13)
                            (string-equal (subseq trimmed 0 13) "(defconstant "))
                   (let* ((rest (subseq trimmed 13))
                          (end (position #\Space rest)))
                     (when end
                       (push (subseq rest 0 end) names)))))))
    ;; Resolve to interned symbols
    (let ((result '()))
      (dolist (name names)
        (let ((sym (find-symbol (string-upcase name) (find-package '#:whistler))))
          (when (and sym (boundp sym) (integerp (symbol-value sym)))
            (push sym result))))
      result)))

;;; ========== C header ==========

(defun generate-c-header (output-path)
  "Generate a C header with struct definitions and constants."
  (with-open-file (out output-path :direction :output :if-exists :supersede)
    (let ((guard (string-upcase
                  (substitute #\_ #\-
                    (substitute #\_ #\.
                      (pathname-name output-path))))))
      (format out "#ifndef ~a_H~%" guard)
      (format out "#define ~a_H~%~%" guard)
      (format out "#include <stdint.h>~%~%"))

    ;; Structs
    (maphash (lambda (name def)
               (let ((fields (cdr def)))
                 (format out "struct ~a {~%" (lisp-to-c-ident name))
                 (dolist (field fields)
                   (cl:destructuring-bind (fname ftype foffset fsize) field
                     (declare (ignore foffset fsize))
                     (format out "    ~a ~a;~%" (c-type-for ftype) (lisp-to-c-ident fname))))
                 (format out "};~%~%")))
             *struct-defs*)

    ;; Constants
    (when *user-constants*
      (dolist (sym (sort (copy-list *user-constants*) #'string< :key #'symbol-name))
        (format out "#define ~a ~d~%"
                (lisp-to-screaming-snake sym) (symbol-value sym)))
      (format out "~%"))

    (format out "#endif~%"))
  (format t "~&Generated C header → ~a~%" output-path))

;;; ========== Go types ==========

(defun generate-go-header (output-path &key (package "main"))
  "Generate a Go file with struct definitions and constants."
  (with-open-file (out output-path :direction :output :if-exists :supersede)
    (format out "package ~a~%~%" package)

    ;; Structs
    (maphash (lambda (name def)
               (let ((fields (cdr def)))
                 (format out "type ~a struct {~%" (lisp-to-pascal name))
                 (dolist (field fields)
                   (cl:destructuring-bind (fname ftype foffset fsize) field
                     (declare (ignore foffset fsize))
                     (format out "~a~a ~a~%" #\Tab (lisp-to-pascal fname) (go-type-for ftype))))
                 (format out "}~%~%")))
             *struct-defs*)

    ;; Constants
    (when *user-constants*
      (format out "const (~%")
      (dolist (sym (sort (copy-list *user-constants*) #'string< :key #'symbol-name))
        (format out "~a~a = ~d~%" #\Tab (lisp-to-pascal sym) (symbol-value sym)))
      (format out ")~%")))
  (format t "~&Generated Go types  → ~a~%" output-path))

;;; ========== Rust types ==========

(defun generate-rust-header (output-path)
  "Generate a Rust file with struct definitions and constants."
  (with-open-file (out output-path :direction :output :if-exists :supersede)
    (format out "// Generated by Whistler~%~%")

    ;; Structs
    (maphash (lambda (name def)
               (let ((fields (cdr def)))
                 (format out "#[repr(C)]~%")
                 (format out "#[derive(Clone, Copy, Debug, Default)]~%")
                 (format out "pub struct ~a {~%" (lisp-to-pascal name))
                 (dolist (field fields)
                   (cl:destructuring-bind (fname ftype foffset fsize) field
                     (declare (ignore foffset fsize))
                     (format out "    pub ~a: ~a,~%"
                             (lisp-to-c-ident fname) (rust-type-for ftype))))
                 (format out "}~%~%")
                 ;; Pod safety
                 (format out "unsafe impl aya::Pod for ~a {}~%~%"
                         (lisp-to-pascal name))))
             *struct-defs*)

    ;; Constants
    (when *user-constants*
      (dolist (sym (sort (copy-list *user-constants*) #'string< :key #'symbol-name))
        (format out "pub const ~a: u64 = ~d;~%"
                (lisp-to-screaming-snake sym) (symbol-value sym)))
      (format out "~%")))
  (format t "~&Generated Rust types → ~a~%" output-path))

;;; ========== Common Lisp types ==========

(defun cl-type-for (whistler-type)
  (let ((n (string-upcase (string whistler-type))))
    (cond ((string= n "U8")  "(unsigned-byte 8)")
          ((string= n "U16") "(unsigned-byte 16)")
          ((string= n "U32") "(unsigned-byte 32)")
          ((string= n "U64") "(unsigned-byte 64)")
          ((string= n "I8")  "(signed-byte 8)")
          ((string= n "I16") "(signed-byte 16)")
          ((string= n "I32") "(signed-byte 32)")
          ((string= n "I64") "(signed-byte 64)")
          (t "(unsigned-byte 64)"))))

(defun cl-byte-size (whistler-type)
  (let ((n (string-upcase (string whistler-type))))
    (cond ((or (string= n "U8") (string= n "I8"))   1)
          ((or (string= n "U16") (string= n "I16")) 2)
          ((or (string= n "U32") (string= n "I32")) 4)
          (t 8))))

(defun generate-cl-header (output-path)
  "Generate a Common Lisp file with struct definitions, byte-vector accessors,
   and constants. Structs use CL defstruct with typed slots and include
   read-from-bytes / write-to-bytes functions for BPF map interop."
  (with-open-file (out output-path :direction :output :if-exists :supersede)
    (format out ";;; Generated by Whistler — shared types for userland BPF interop~%")
    (format out ";;; Use with CFFI or raw bpf(2) syscalls to read/write map values.~%~%")

    ;; Structs
    (maphash
     (lambda (name def)
       (let ((fields (cdr def))
             (total-size (car def))
             (cl-name (lisp-to-c-ident name)))
         ;; defstruct
         (format out "(defstruct ~a~%" cl-name)
         (dolist (field fields)
           (cl:destructuring-bind (fname ftype foffset fsize) field
             (declare (ignore foffset fsize))
             (format out "  (~a 0 :type ~a)~%"
                     (lisp-to-c-ident fname) (cl-type-for ftype))))
         (format out ")~%~%")

         ;; read-from-bytes
         (format out "(defun ~a-from-bytes (buf &optional (offset 0))~%" cl-name)
         (format out "  \"Decode a ~a from a byte vector at OFFSET.\"~%" cl-name)
         (format out "  (make-~a~%" cl-name)
         (dolist (field fields)
           (cl:destructuring-bind (fname ftype foffset fsize) field
             (declare (ignore fsize))
             (let ((bsize (cl-byte-size ftype))
                   (fn (lisp-to-c-ident fname)))
               (format out "   :~a (logior~%" fn)
               (dotimes (i bsize)
                 (if (= i (1- bsize))
                     (format out "          (ash (aref buf (+ offset ~d)) ~d))~%"
                             (+ foffset i) (* i 8))
                     (format out "          (ash (aref buf (+ offset ~d)) ~d)~%"
                             (+ foffset i) (* i 8)))))))
         (format out "  ))~%~%")

         ;; write-to-bytes
         (format out "(defun ~a-to-bytes (obj &optional (buf (make-array ~d :element-type '(unsigned-byte 8))) (offset 0))~%"
                 cl-name total-size)
         (format out "  \"Encode a ~a into a byte vector at OFFSET. Returns BUF.\"~%" cl-name)
         (dolist (field fields)
           (cl:destructuring-bind (fname ftype foffset fsize) field
             (declare (ignore fsize))
             (let ((bsize (cl-byte-size ftype))
                   (fn (lisp-to-c-ident fname))
                   (accessor (format nil "~a-~a" cl-name (lisp-to-c-ident fname))))
               (format out "  (let ((v (~a obj)))~%" accessor)
               (dotimes (i bsize)
                 (format out "    (setf (aref buf (+ offset ~d)) (logand (ash v ~d) #xff))~%"
                         (+ foffset i) (- (* i 8))))
               (format out "  )~%"))))
         (format out "  buf)~%~%")))
     *struct-defs*)

    ;; Constants
    (when *user-constants*
      (dolist (sym (sort (copy-list *user-constants*) #'string< :key #'symbol-name))
        (format out "(defconstant +~a+ ~d)~%"
                (lisp-to-c-ident sym) (symbol-value sym)))
      (format out "~%")))
  (format t "~&Generated CL types  → ~a~%" output-path))

;;; ========== Python types ==========

(defun python-type-for (whistler-type)
  "Return a ctypes type string for a Whistler type."
  (let ((n (string-upcase (string whistler-type))))
    (cond ((string= n "U8")  "ctypes.c_uint8")
          ((string= n "U16") "ctypes.c_uint16")
          ((string= n "U32") "ctypes.c_uint32")
          ((string= n "U64") "ctypes.c_uint64")
          ((string= n "I8")  "ctypes.c_int8")
          ((string= n "I16") "ctypes.c_int16")
          ((string= n "I32") "ctypes.c_int32")
          ((string= n "I64") "ctypes.c_int64")
          (t "ctypes.c_uint64"))))

(defun generate-python-header (output-path)
  "Generate a Python file with ctypes struct definitions and constants."
  (with-open-file (out output-path :direction :output :if-exists :supersede)
    (format out "\"\"\"Generated by Whistler — shared types for userland BPF interop.\"\"\"~%~%")
    (format out "import ctypes~%~%")

    ;; Structs
    (maphash
     (lambda (name def)
       (let ((fields (cdr def)))
         (format out "class ~a(ctypes.LittleEndianStructure):~%" (lisp-to-pascal name))
         (format out "    _fields_ = [~%")
         (let ((field-list fields))
           (loop for field in field-list
                 for i from 0
                 do (cl:destructuring-bind (fname ftype foffset fsize) field
                      (declare (ignore foffset fsize))
                      (format out "        (~s, ~a)~a~%"
                              (lisp-to-c-ident fname)
                              (python-type-for ftype)
                              (if (< i (1- (length field-list))) "," "")))))
         (format out "    ]~%~%")
         (format out "    def __repr__(self):~%")
         (format out "        fields = {f[0]: getattr(self, f[0]) for f in self._fields_}~%")
         (format out "        return f\"~a({fields})\"~%~%" (lisp-to-pascal name))))
     *struct-defs*)

    ;; Constants
    (when *user-constants*
      (dolist (sym (sort (copy-list *user-constants*) #'string< :key #'symbol-name))
        (format out "~a = ~d~%" (lisp-to-screaming-snake sym) (symbol-value sym)))
      (format out "~%")))
  (format t "~&Generated Python   → ~a~%" output-path))

;;; ========== Top-level API ==========

(defun generate-headers (output-base)
  "Generate shared headers for C, Go, Rust, and Common Lisp.
   Produces OUTPUT-BASE.h, OUTPUT-BASE_types.go, OUTPUT-BASE_types.rs,
   OUTPUT-BASE_types.lisp."
  (generate-c-header (format nil "~a.h" output-base))
  (generate-go-header (format nil "~a_types.go" output-base))
  (generate-rust-header (format nil "~a_types.rs" output-base))
  (generate-cl-header (format nil "~a_types.lisp" output-base))
  (generate-python-header (format nil "~a_types.py" output-base)))

(defun compile-and-generate (input-path output-base)
  "Compile a Whistler program and generate .bpf.o + shared headers.
   Produces OUTPUT-BASE.bpf.o, OUTPUT-BASE.h, OUTPUT-BASE_types.go,
   OUTPUT-BASE_types.rs."
  (let ((*maps* '())
        (*programs* '())
        (*struct-defs* (make-hash-table :test 'equal)))
    (load input-path)
    (let ((*user-constants* (collect-user-constants-from-file input-path)))
      (compile-to-elf (format nil "~a.bpf.o" output-base))
      (generate-headers output-base))))
