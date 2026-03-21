;;; loader.lisp — Top-level BPF object loading and management
;;;
;;; SPDX-License-Identifier: MIT

(in-package #:whistler/loader)

;;; ========== BPF object ==========

(defstruct bpf-object
  pathname elf maps progs attachments)

;;; ========== Top-level API ==========

(defun open-bpf-object (pathname)
  "Parse a BPF ELF object file. Returns a bpf-object ready for loading."
  (let* ((elf (read-bpf-elf pathname))
         (map-infos (extract-map-defs elf)))
    (make-bpf-object :pathname pathname :elf elf
                     :maps map-infos :progs nil :attachments nil)))

(defun load-bpf-object (obj)
  "Create maps, patch relocations, and load all programs into the kernel."
  (let* ((elf (bpf-object-elf obj))
         (map-infos (bpf-object-maps obj))
         (symtab (bpf-elf-symtab elf))
         (license (or (bpf-elf-license elf) "GPL")))

    ;; Step 1: Create all maps
    (dolist (m map-infos)
      (create-map m)
      (format t "Created map ~a: fd=~d type=~d~%"
              (map-info-name m) (map-info-fd m) (map-info-type m)))

    ;; Build map-name → fd alist for relocation patching
    (let ((map-fds (mapcar (lambda (m) (cons (map-info-name m) (map-info-fd m)))
                           map-infos))
          (progs '()))

      ;; Step 2: For each program section, patch and load
      (dolist (prog-entry (bpf-elf-prog-sections elf))
        (let* ((sec-idx (car prog-entry))
               (sec (cdr prog-entry))
               (sec-name (elf-section-name sec))
               (insns (copy-seq (elf-section-data sec)))
               ;; Find relocations for this section
               (rels (cdr (assoc sec-idx (bpf-elf-rel-sections elf))))
               ;; Find the FUNC symbol for this section (prog name)
               (func-sym (find-if (lambda (s)
                                    (and (= (elf-sym-shndx s) sec-idx)
                                         (= (logand (elf-sym-info s) #xf) +stt-func+)))
                                  symtab))
               (prog-name (if func-sym (elf-sym-name func-sym) sec-name))
               (prog-type (section-to-prog-type sec-name)))

          ;; Patch map FD relocations
          (when rels
            (setf insns (patch-map-relocations insns rels symtab map-fds)))

          ;; Load program
          (let ((fd (load-program insns prog-type license)))
            (format t "Loaded ~a: ~d insns, fd=~d, section=~a~%"
                    prog-name (/ (length insns) 8) fd sec-name)
            (push (make-prog-info :name prog-name
                                  :section-name sec-name
                                  :type prog-type
                                  :insns insns
                                  :fd fd)
                  progs))))

      (setf (bpf-object-progs obj) (nreverse progs))))
  obj)

(defun close-bpf-object (obj)
  "Close all BPF resources: detach programs, close FDs."
  ;; Detach all attachments
  (dolist (att (bpf-object-attachments obj))
    (handler-case (detach att) (error () nil)))
  ;; Close program FDs
  (dolist (p (bpf-object-progs obj))
    (when (plusp (prog-info-fd p))
      (handler-case (sb-posix:close (prog-info-fd p)) (error () nil))
      (setf (prog-info-fd p) -1)))
  ;; Close map FDs
  (dolist (m (bpf-object-maps obj))
    (when (plusp (map-info-fd m))
      (handler-case (sb-posix:close (map-info-fd m)) (error () nil))
      (setf (map-info-fd m) -1)))
  (setf (bpf-object-attachments obj) nil))

;;; ========== with-bpf-object ==========

(defmacro with-bpf-object ((var pathname) &body body)
  "Open, load, and execute BODY with VAR bound to a loaded bpf-object.
   Automatically closes all BPF resources (maps, programs, attachments)
   on normal exit or error."
  `(let ((,var (load-bpf-object (open-bpf-object ,pathname))))
     (unwind-protect
          (progn ,@body)
       (close-bpf-object ,var))))

;;; ========== Accessors ==========

(defun bpf-object-map (obj name)
  "Find a map by name in a loaded BPF object."
  (find name (bpf-object-maps obj) :key #'map-info-name :test #'string=))

(defun bpf-object-prog (obj name)
  "Find a program by name in a loaded BPF object."
  (find name (bpf-object-progs obj) :key #'prog-info-name :test #'string=))

;;; ========== Convenience attachment wrappers ==========

(defun attach-obj-kprobe (obj prog-name function-name &key retprobe)
  "Attach a kprobe from a loaded BPF object by program name."
  (let ((prog (bpf-object-prog obj prog-name)))
    (unless prog (error "Program ~a not found" prog-name))
    (let ((att (attach-kprobe (prog-info-fd prog) function-name :retprobe retprobe)))
      (push att (bpf-object-attachments obj))
      att)))

(defun attach-obj-uprobe (obj prog-name binary-path symbol-name &key retprobe)
  "Attach a uprobe from a loaded BPF object by program name."
  (let ((prog (bpf-object-prog obj prog-name)))
    (unless prog (error "Program ~a not found" prog-name))
    (let ((att (attach-uprobe (prog-info-fd prog) binary-path symbol-name :retprobe retprobe)))
      (push att (bpf-object-attachments obj))
      att)))
