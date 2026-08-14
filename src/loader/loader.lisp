;;; loader.lisp — Top-level BPF object loading and management
;;;
;;; SPDX-License-Identifier: MIT

(in-package #:whistler/loader)

;;; ========== BPF object ==========

(defstruct bpf-object
  pathname elf maps progs attachments)

;;; ========== Kfunc relocation patching ==========

(defun patch-kfunc-relocations (insns rel-entries symtab)
  "Patch kfunc call instructions (R_BPF_64_32 relocations) with the kfunc's
   kernel BTF id. Each reloc's symbol names a kfunc; its id is resolved in
   /sys/kernel/btf/vmlinux and written into the call insn's 32-bit imm
   (bytes offset+4..offset+7). The insn's src_reg (BPF_PSEUDO_KFUNC_CALL)
   and off (0 = vmlinux) are already baked in by the compiler.
   Returns a new byte vector with patched instructions."
  (let ((patched (copy-seq insns))
        (cache (make-hash-table :test 'equal)))
    (dolist (rel rel-entries)
      (let* ((offset (elf-rel-offset rel))
             (sym-idx (elf-rel-sym-idx rel))
             (sym (nth sym-idx symtab))
             (kfunc-name (elf-sym-name sym))
             (btf-id (or (gethash kfunc-name cache)
                         (setf (gethash kfunc-name cache)
                               (resolve-btf-func-id kfunc-name)))))
        (setf (aref patched (+ offset 4)) (logand btf-id #xff))
        (setf (aref patched (+ offset 5)) (logand (ash btf-id -8) #xff))
        (setf (aref patched (+ offset 6)) (logand (ash btf-id -16) #xff))
        (setf (aref patched (+ offset 7)) (logand (ash btf-id -24) #xff))))
    patched))

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

          ;; Patch relocations, split by type: map fd (R_BPF_64_64) and
          ;; kfunc call (R_BPF_64_32) may both appear in one .rel section.
          (when rels
            (let ((map-rels (remove-if-not
                             (lambda (r) (= (elf-rel-type r) +r-bpf-64-64+)) rels))
                  (kfunc-rels (remove-if-not
                               (lambda (r) (= (elf-rel-type r) +r-bpf-64-32+)) rels)))
              (when map-rels
                (setf insns (patch-map-relocations insns map-rels symtab map-fds)))
              (when kfunc-rels
                (setf insns (patch-kfunc-relocations insns kfunc-rels symtab)))))

          ;; Load program
          (let* ((eat (section-to-expected-attach-type sec-name))
                 (btf-id (cond
                           ;; lsm/<hook> → BTF func "bpf_lsm_<hook>"
                           ((and (>= (length sec-name) 4)
                                 (string= (subseq sec-name 0 4) "lsm/"))
                            (resolve-btf-func-id
                             (lsm-hook-to-btf-func sec-name)))
                           ;; fentry/<func> / fexit/<func> → BTF func of <func>
                           ((and (>= (length sec-name) 7)
                                 (string= (subseq sec-name 0 7) "fentry/"))
                            (resolve-btf-func-id (subseq sec-name 7)))
                           ((and (>= (length sec-name) 6)
                                 (string= (subseq sec-name 0 6) "fexit/"))
                            (resolve-btf-func-id (subseq sec-name 6)))
                           (t nil)))
                 (fd (load-program insns prog-type license
                                   :expected-attach-type eat
                                   :attach-btf-id btf-id)))
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

(defun attach-obj-xdp (obj prog-name interface-name &key (mode "xdp"))
  "Attach an XDP program from a loaded BPF object by program name."
  (let ((prog (bpf-object-prog obj prog-name)))
    (unless prog (error "Program ~a not found" prog-name))
    (let ((att (attach-xdp (prog-info-fd prog) interface-name :mode mode)))
      (push att (bpf-object-attachments obj))
      att)))

(defun attach-obj-tc (obj prog-name interface-name &key (direction "ingress"))
  "Attach a TC program from a loaded BPF object by program name."
  (let ((prog (bpf-object-prog obj prog-name)))
    (unless prog (error "Program ~a not found" prog-name))
    (let ((att (attach-tc (prog-info-fd prog) interface-name :direction direction)))
      (push att (bpf-object-attachments obj))
      att)))

(defun attach-obj-cgroup (obj prog-name cgroup-path attach-type &key (flags 0))
  "Attach a cgroup program from a loaded BPF object by program name.
   CGROUP-PATH is the cgroup2 filesystem path.
   ATTACH-TYPE is one of the +bpf-cgroup-*+ constants."
  (let ((prog (bpf-object-prog obj prog-name)))
    (unless prog (error "Program ~a not found" prog-name))
    (let ((att (attach-cgroup (prog-info-fd prog) cgroup-path attach-type :flags flags)))
      (push att (bpf-object-attachments obj))
      att)))
