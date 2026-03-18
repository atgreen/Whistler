;;; -*- Mode: Lisp -*-
;;;
;;; Copyright (c) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; SPDX-License-Identifier: MIT

(in-package #:whistler)

;;; Whistler: top-level interface
;;; Compile Lisp forms to eBPF ELF object files.

(version-string:define-version-parameter *version* "whistler")

(defvar *user-constants* '()
  "Constants defined by user code in the current compilation. Set by codegen.")

(defvar *maps* '()
  "Map definitions for the current compilation.")

(defvar *programs* '()
  "Program definitions for the current compilation.")

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
          (t (error "Unknown struct field type: ~a" type)))))

(defun struct-type-to-store-type (type)
  "Convert a struct field type symbol to the surface-language store type."
  (let ((name (string-upcase (string type))))
    (cond ((string= name "U8")  'u8)
          ((string= name "U16") 'u16)
          ((string= name "U32") 'u32)
          ((string= name "U64") 'u64)
          (t (error "Unknown struct field type: ~a" type)))))

(defmacro defstruct (name &body fields)
  "Define a BPF struct with C-compatible layout.
   Generates:
   - (make-NAME) constructor macro
   - (NAME-FIELD ptr) accessor macros for each field
   - (setf (NAME-FIELD ptr) val) writer expanders for each field"
  (let ((field-list '())
        (offset 0)
        (max-align 1))
    (dolist (field-spec fields)
      (cl:destructuring-bind (fname ftype) field-spec
        (let* ((size (struct-type-byte-size ftype))
               (align size)
               (aligned-off (logand (+ offset (1- align)) (- align))))
          (push (list fname ftype aligned-off size) field-list)
          (setf offset (+ aligned-off size))
          (setf max-align (max max-align align)))))
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
                                       (symbol-package name)))
                (store-type (struct-type-to-store-type ftype)))
            ;; Reader: (name-field ptr) → (core-load TYPE ptr OFFSET NAME FIELD)
            (push `(cl:defmacro ,accessor-name (ptr)
                     (list 'core-load ',store-type ptr ,foffset ',name ',fname))
                  accessor-forms)
            ;; Writer macro: (set-name-field! ptr val) for setf expansion
            (let ((writer-name (intern (format nil "SET-~a-~a!" (symbol-name name)
                                               (symbol-name fname))
                                       (symbol-package name))))
              (push `(cl:defmacro ,writer-name (ptr val)
                       (list 'core-store ',store-type ptr ,foffset val ',name ',fname))
                    accessor-forms)
              (push `(cl:defsetf ,accessor-name ,writer-name)
                    accessor-forms)))))
      `(progn
         (setf (gethash ,(string name) *struct-defs*)
               (cons ,total ',fields-rev))
         (cl:defmacro ,make-name ()
           '(struct-alloc ,total))
         ,@(nreverse accessor-forms)))))

(defun lookup-struct-field (struct-name field-name)
  "Look up a field in a struct definition. Returns (type offset size)."
  (let ((def (gethash (string struct-name) *struct-defs*)))
    (unless def (error "Unknown struct: ~a" struct-name))
    (let ((field (find (string field-name) (cdr def)
                       :key (lambda (f) (string (first f)))
                       :test #'string=)))
      (unless field (error "Unknown field ~a in struct ~a" field-name struct-name))
      (values (second field) (third field) (fourth field)))))

(defmacro struct-set (struct-name var field-name value)
  "Set a field in a struct. Expands to (core-store TYPE ptr OFFSET val STRUCT FIELD)."
  (multiple-value-bind (ftype foffset) (lookup-struct-field struct-name field-name)
    `(core-store ,(struct-type-to-store-type ftype) ,var ,foffset ,value
                 ,struct-name ,field-name)))

(defmacro struct-ref (struct-name var field-name)
  "Read a field from a struct. Expands to (core-load TYPE ptr OFFSET STRUCT FIELD)."
  (multiple-value-bind (ftype foffset) (lookup-struct-field struct-name field-name)
    `(core-load ,(struct-type-to-store-type ftype) ,var ,foffset
                ,struct-name ,field-name)))

;;; User-facing macros for defining maps and programs

(defmacro defmap (name &key type key-size value-size max-entries (map-flags 0))
  "Define a BPF map."
  `(push (list ',name :type ,type :key-size ,key-size
                      :value-size ,value-size :max-entries ,max-entries
                      :map-flags ,map-flags)
         *maps*))

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
      (error "No programs defined"))
    ;; Compile each program independently
    (let ((compiled-units
           (mapcar (lambda (prog-spec)
                     (destructuring-bind (name &key section license body) prog-spec
                       (declare (ignore name))
                       (compile-program section license maps body)))
                   progs)))
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
                              (cu-core-relocs cu)))
                      compiled-units))
             (section-names (mapcar #'first prog-sections))
             (all-core-relocs (mapcar #'fourth prog-sections)))
        ;; Generate BTF and BTF.ext for all programs
        (multiple-value-bind (btf btf-ext)
            (generate-btf-and-ext *struct-defs* section-names all-core-relocs map-specs)
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
               collect (destructuring-bind (name &key type key-size value-size max-entries
                                                 (map-flags 0))
                           map-spec
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
