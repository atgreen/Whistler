;;; session.lisp — with-bpf-session: inline BPF compilation + loading
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Compiles BPF code at macroexpand time and loads it at runtime.
;;; The bpf: prefix separates kernel-side forms from userspace CL code.

(in-package #:whistler/loader)

;;; ========== BPF session package ==========
;;; Provides bpf:map, bpf:prog, bpf:attach, bpf:map-ref

(defpackage #:bpf
  (:export #:map #:prog #:attach #:map-ref #:map-ref-int))

;;; ========== Symbol re-interning ==========
;;; When bpf:prog body is written in CL-USER, symbols like INCF and GETMAP
;;; resolve to CL:INCF and CL-USER::GETMAP instead of WHISTLER::INCF and
;;; WHISTLER::GETMAP. Re-intern them so the Whistler macros fire correctly.

(defun whistler-intern-form (form)
  "Walk FORM and re-intern symbols into the WHISTLER package where a
   same-named symbol already exists there."
  (cond
    ((null form) nil)
    ((keywordp form) form)
    ((symbolp form)
     (multiple-value-bind (sym status)
         (find-symbol (symbol-name form) :whistler)
       (if status sym form)))
    ((atom form) form)
    (t (cons (whistler-intern-form (car form))
             (whistler-intern-form (cdr form))))))

;;; ========== Compile-time BPF collection ==========

(defun compile-bpf-forms (map-forms prog-forms)
  "Compile BPF map and program definitions at macroexpand time.
   Returns (map-defs prog-defs) where each is a list of plists with
   the compiled bytecode and metadata embedded as literals."
  (let ((whistler::*maps* nil)
        (whistler::*programs* nil))
    ;; Evaluate map definitions
    (dolist (form map-forms)
      (eval form))
    ;; Evaluate prog definitions (and any structs they reference)
    (dolist (form prog-forms)
      (eval form))
    ;; Compile
    (let* ((maps (reverse whistler::*maps*))
           (progs (reverse whistler::*programs*)))
      (when (null progs)
        (error "with-bpf-session: no bpf:prog forms found"))
      ;; Compile each program
      (let ((compiled-units
             (mapcar (lambda (prog-spec)
                       (destructuring-bind (name &key section license body) prog-spec
                         (let ((cu (whistler::compile-program section license maps body)))
                           (setf (whistler/compiler:cu-name cu)
                                 (substitute #\_ #\-
                                             (string-downcase (symbol-name name))))
                           cu)))
                     progs))
            (map-specs
             (loop for (name . rest) in maps
                   collect (list :name (string-downcase
                                        (substitute #\_ #\- (symbol-name name)))
                                 :type (getf rest :type)
                                 :key-size (getf rest :key-size)
                                 :value-size (getf rest :value-size)
                                 :max-entries (getf rest :max-entries)
                                 :flags (or (getf rest :map-flags) 0)))))
        (values map-specs
                (mapcar (lambda (cu prog-spec)
                          (declare (ignore prog-spec))
                          (list :name (whistler/compiler:cu-name cu)
                                :section (whistler/compiler:cu-section cu)
                                :license (whistler/compiler:cu-license cu)
                                :insns (whistler::insn-bytes
                                        (whistler/compiler:cu-insns cu))
                                :relocs (reverse
                                         (whistler/compiler:cu-map-relocs cu))))
                        compiled-units progs))))))

;;; ========== Integer key/value encoding ==========

(defun encode-int-key (value size)
  "Encode an integer as a little-endian byte array of SIZE bytes."
  (let ((buf (make-array size :element-type '(unsigned-byte 8) :initial-element 0)))
    (loop for i below (min size 8)
          do (setf (aref buf i) (logand (ash value (* i -8)) #xff)))
    buf))

(defun decode-int-value (bytes)
  "Decode a little-endian byte array as an unsigned integer."
  (loop for i below (length bytes)
        sum (ash (aref bytes i) (* i 8))))

;;; ========== Session runtime ==========

(defvar *bpf-session* nil
  "Dynamically bound to the active inline BPF session.")

(defstruct bpf-session
  maps progs attachments)

(defun bpf-session-map (name &optional (session *bpf-session*))
  "Find a map by NAME in SESSION."
  (cdr (assoc (string-downcase
               (substitute #\_ #\- (string name)))
              (bpf-session-maps session)
              :test #'string=)))

(defun bpf-session-prog (name &optional (session *bpf-session*))
  "Find a program by NAME in SESSION."
  (cdr (assoc (string-downcase
               (substitute #\_ #\- (string name)))
              (bpf-session-progs session)
              :test #'string=)))

(defun session-create-maps (map-specs)
  "Create all maps from compiled specs. Returns name→map-info alist."
  (loop for spec in map-specs
        for info = (make-map-info
                    :name (getf spec :name)
                    :type (whistler/compiler:resolve-map-type (getf spec :type))
                    :key-size (getf spec :key-size)
                    :value-size (getf spec :value-size)
                    :max-entries (getf spec :max-entries)
                    :flags (getf spec :flags))
        do (create-map info)
        collect (cons (getf spec :name) info)))

(defun session-load-progs (prog-specs map-alist)
  "Load all programs with map FD relocations. Returns name→prog-info alist."
  (let ((map-fds (mapcar (lambda (e) (cons (car e) (map-info-fd (cdr e)))) map-alist)))
    (mapcar
     (lambda (spec)
       (let* ((insns (copy-seq (getf spec :insns)))
              (relocs (getf spec :relocs))
              (sec-name (getf spec :section))
              (name (getf spec :name))
              (license (getf spec :license))
              (prog-type (section-to-prog-type sec-name)))
         ;; Patch relocations: each reloc is (insn-byte-offset map-index)
         (dolist (rel relocs)
           (let* ((offset (first rel))
                  (map-idx (second rel))
                  (map-name (car (nth map-idx map-alist)))
                  (fd (cdr (assoc map-name map-fds :test #'string=))))
             (when fd
               (setf (aref insns (+ offset 1))
                     (logior (logand (aref insns (+ offset 1)) #x0f)
                             (ash +bpf-pseudo-map-fd+ 4)))
               (setf (aref insns (+ offset 4)) (logand fd #xff))
               (setf (aref insns (+ offset 5)) (logand (ash fd -8) #xff))
               (setf (aref insns (+ offset 6)) (logand (ash fd -16) #xff))
               (setf (aref insns (+ offset 7)) (logand (ash fd -24) #xff)))))
         (let* ((eat (section-to-expected-attach-type sec-name))
                (fd (load-program insns prog-type license
                                  :expected-attach-type eat)))
           (cons name (make-prog-info :name name :section-name sec-name
                                      :type prog-type :insns insns :fd fd)))))
     prog-specs)))

(defun session-close (session)
  "Close all session resources."
  (dolist (att (bpf-session-attachments session))
    (handler-case (detach att) (error () nil)))
  (dolist (entry (bpf-session-progs session))
    (let ((fd (prog-info-fd (cdr entry))))
      (when (plusp fd)
        (handler-case (sb-posix:close fd) (error () nil)))))
  (dolist (entry (bpf-session-maps session))
    (let ((fd (map-info-fd (cdr entry))))
      (when (plusp fd)
        (handler-case (sb-posix:close fd) (error () nil))))))

;;; ========== The macro ==========

(defmacro with-bpf-session (() &body body)
  "Compile BPF code inline and load it into the kernel.

   Use bpf:map and bpf:prog for kernel-side definitions (compiled at
   macroexpand time). Use bpf:attach for program attachment.
   Use bpf:map-ref to read map values.
   All other forms are normal CL code.

   Example:
     (with-bpf-session ()
       (bpf:map stats :type :hash :key-size 4 :value-size 8 :max-entries 1024)
       (bpf:prog counter (:type :kprobe :section \"kprobe/__x64_sys_execve\" :license \"GPL\")
         (incf (getmap stats 0)) 0)
       (bpf:attach counter \"__x64_sys_execve\")
       (loop (sleep 1)
             (format t \"count: ~d~%\" (bpf:map-ref stats 0))))"
  ;; Phase 1: Walk body, separate BPF forms from CL forms
  (let ((map-forms nil)
        (prog-forms nil)
        (map-key-sizes (make-hash-table :test 'equal))  ; name → key-size
        (map-value-sizes (make-hash-table :test 'equal))
        (runtime-body nil))
    ;; Classify each top-level form
    (dolist (form body)
      (cond
        ;; (bpf:map name &key type key-size value-size max-entries)
        ((and (consp form) (eq (car form) 'bpf:map))
         (let* ((name (second form))
                (args (cddr form))
                (ks (or (getf args :key-size) 0))
                (vs (or (getf args :value-size) 0)))
           (setf (gethash (string-downcase (substitute #\_ #\- (symbol-name name)))
                          map-key-sizes) ks)
           (setf (gethash (string-downcase (substitute #\_ #\- (symbol-name name)))
                          map-value-sizes) vs)
           (push `(whistler:defmap ,name ,@args) map-forms)))
        ;; (bpf:prog name (options...) body...)
        ((and (consp form) (eq (car form) 'bpf:prog))
         (let ((body (mapcar #'whistler-intern-form (cdddr form))))
           (push `(whistler:defprog ,(second form) ,(third form) ,@body)
                 prog-forms)))
        ;; Everything else is runtime CL code
        (t (push form runtime-body))))
    (setf map-forms (nreverse map-forms))
    (setf prog-forms (nreverse prog-forms))
    (setf runtime-body (nreverse runtime-body))

    ;; Phase 2: Compile BPF at macroexpand time
    (multiple-value-bind (map-specs prog-specs)
        (compile-bpf-forms map-forms prog-forms)

      ;; Phase 3: Emit runtime code
      ;; Build section-name lookup for attach type detection
      (let ((prog-section-names (make-hash-table :test 'equal)))
        (dolist (spec prog-specs)
          (setf (gethash (getf spec :name) prog-section-names)
                (getf spec :section)))

        `(let* ((*bpf-session*
                 (let* ((map-alist (session-create-maps ',map-specs))
                        (prog-alist (session-load-progs ',prog-specs map-alist)))
                   (make-bpf-session :maps map-alist :progs prog-alist))))
           (declare (special *bpf-session*))
           (unwind-protect
                (macrolet
                    ((bpf:attach (prog-name target &rest args)
                       ;; Detect kprobe vs uprobe vs tracepoint from section name
                       (let* ((pname (string-downcase
                                      (substitute #\_ #\-
                                                  (symbol-name prog-name))))
                              (sec-name (gethash pname ',prog-section-names))
                              (is-uprobe (and sec-name
                                              (>= (length sec-name) 7)
                                              (string= (subseq sec-name 0 7)
                                                       "uprobe/")))
                              (is-tracepoint (and sec-name
                                                  (>= (length sec-name) 11)
                                                  (string= (subseq sec-name 0 11)
                                                           "tracepoint/")))
                              (is-cgroup (and sec-name
                                              (>= (length sec-name) 6)
                                              (string= (subseq sec-name 0 6)
                                                       "cgroup")))
                              (cgroup-eat (and is-cgroup
                                               (section-to-expected-attach-type sec-name))))
                         (cond
                           (is-cgroup
                            ;; cgroup: (bpf:attach prog cgroup-path)
                            `(let* ((prog-entry (assoc ,pname
                                                       (bpf-session-progs *bpf-session*)
                                                       :test #'string=))
                                    (att (attach-cgroup (prog-info-fd (cdr prog-entry))
                                                        ,target ,cgroup-eat ,@args)))
                               (push att (bpf-session-attachments *bpf-session*))
                               att))
                           (is-uprobe
                            ;; uprobe: (bpf:attach prog binary-path symbol-name)
                            `(let* ((prog-entry (assoc ,pname
                                                       (bpf-session-progs *bpf-session*)
                                                       :test #'string=))
                                    (att (attach-uprobe (prog-info-fd (cdr prog-entry))
                                                        ,target ,@args)))
                               (push att (bpf-session-attachments *bpf-session*))
                               att))
                           (is-tracepoint
                            ;; tracepoint: (bpf:attach prog tracepoint-name)
                            `(let* ((prog-entry (assoc ,pname
                                                       (bpf-session-progs *bpf-session*)
                                                       :test #'string=))
                                    (att (attach-tracepoint (prog-info-fd (cdr prog-entry))
                                                            ,target)))
                               (push att (bpf-session-attachments *bpf-session*))
                               att))
                           (t
                            ;; kprobe: (bpf:attach prog function-name)
                            `(let* ((prog-entry (assoc ,pname
                                                       (bpf-session-progs *bpf-session*)
                                                       :test #'string=))
                                    (att (attach-kprobe (prog-info-fd (cdr prog-entry))
                                                        ,target ,@args)))
                               (push att (bpf-session-attachments *bpf-session*))
                               att)))))
                     (bpf:map-ref (map-name key)
                       (let* ((mname (string-downcase
                                      (substitute #\_ #\-
                                                  (symbol-name map-name))))
                              (ks (gethash mname ',map-key-sizes)))
                         `(let ((result (map-lookup
                                         (cdr (assoc ,mname
                                                     (bpf-session-maps *bpf-session*)
                                                     :test #'string=))
                                         (encode-int-key ,key ,(or ks 4)))))
                            (when result
                              (decode-int-value result))))))
                  ,@runtime-body)
             (session-close *bpf-session*)))))))
