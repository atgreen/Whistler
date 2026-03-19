;;; -*- Mode: Lisp -*-
;;;
;;; Copyright (c) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; SPDX-License-Identifier: MIT

(in-package #:whistler/elf)

;;; Minimal ELF writer for BPF object files
;;; Produces 64-bit little-endian ELF relocatable objects

;; ELF constants
(defconstant +elfclass64+   2)
(defconstant +elfdata2lsb+  1)
(defconstant +ev-current+   1)
(defconstant +elfosabi-none+ 0)
(defconstant +et-rel+       1)    ; relocatable
(defconstant +em-bpf+       247)  ; eBPF
(defconstant +sht-null+     0)
(defconstant +sht-progbits+ 1)
(defconstant +sht-symtab+   2)
(defconstant +sht-strtab+   3)
(defconstant +sht-rel+      9)
(defconstant +shf-alloc+    #x2)
(defconstant +shf-execinstr+ #x4)
(defconstant +stt-notype+   0)
(defconstant +stt-object+   1)
(defconstant +stt-section+  3)
(defconstant +stt-func+     18)   ; STT_FUNC = 2, but encoded in st_info
(defconstant +stb-local+    0)
(defconstant +stb-global+   1)
(defconstant +shn-undef+    0)
(defconstant +r-bpf-64-64+  1)   ; BPF relocation type for map fd

;;; Binary writing utilities

(defun write-u8 (stream val)
  (write-byte (logand val #xff) stream))

(defun write-u16le (stream val)
  (write-u8 stream val)
  (write-u8 stream (ash val -8)))

(defun write-u32le (stream val)
  (write-u8 stream val)
  (write-u8 stream (ash val -8))
  (write-u8 stream (ash val -16))
  (write-u8 stream (ash val -24)))

(defun write-u64le (stream val)
  (write-u32le stream (logand val #xffffffff))
  (write-u32le stream (logand (ash val -32) #xffffffff)))

(defun write-bytes (stream bytes)
  (write-sequence bytes stream))

(defun write-padding (stream alignment current-pos)
  "Write zero padding to reach alignment. Returns new position."
  (let* ((rem (mod current-pos alignment))
         (pad (if (zerop rem) 0 (- alignment rem))))
    (dotimes (i pad) (write-byte 0 stream))
    (+ current-pos pad)))

(defun strtab-add (strtab string)
  "Add a string to string table, return its offset."
  (let ((offset (length strtab)))
    (loop for ch across string
          do (vector-push-extend (char-code ch) strtab))
    (vector-push-extend 0 strtab)  ; null terminator
    offset))

(defun make-strtab ()
  (let ((tab (make-array 16 :element-type '(unsigned-byte 8)
                            :adjustable t :fill-pointer 0)))
    (vector-push-extend 0 tab)  ; initial null byte
    tab))

;;; ELF section tracking

(defstruct elf-section
  name           ; string
  name-offset    ; offset in shstrtab
  type           ; section type
  flags          ; section flags
  data           ; byte vector
  link           ; link field
  info           ; info field
  addralign      ; alignment
  entsize        ; entry size
  file-offset)   ; computed during layout

;;; Map definition structure for the ".maps" section (BTF-defined maps)
;;; Each map entry is 32 bytes of zeros — actual configuration comes from BTF.

(defun encode-map-def (map-type key-size value-size max-entries &optional (flags 0))
  (let ((data (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; Write directly into byte array (little-endian)
    (flet ((put-u32 (offset val)
             (setf (aref data (+ offset 0)) (logand val #xff))
             (setf (aref data (+ offset 1)) (logand (ash val -8) #xff))
             (setf (aref data (+ offset 2)) (logand (ash val -16) #xff))
             (setf (aref data (+ offset 3)) (logand (ash val -24) #xff))))
      (put-u32 0  map-type)
      (put-u32 4  key-size)
      (put-u32 8  value-size)
      (put-u32 12 max-entries)
      (put-u32 16 flags))
    data))

;;; Relocation entry: 24 bytes (r_offset:8, r_info:8, r_addend:8... wait, SHT_REL is 16 bytes)
;;; For BPF we use SHT_REL (not RELA). Each entry is 16 bytes: r_offset(8) r_info(8)

(defun encode-rel (offset sym-index rel-type)
  (let ((data (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (flet ((put-u32 (off val)
             (setf (aref data (+ off 0)) (logand val #xff))
             (setf (aref data (+ off 1)) (logand (ash val -8) #xff))
             (setf (aref data (+ off 2)) (logand (ash val -16) #xff))
             (setf (aref data (+ off 3)) (logand (ash val -24) #xff))))
      ;; r_offset (8 bytes LE)
      (put-u32 0 (logand offset #xffffffff))
      (put-u32 4 (logand (ash offset -32) #xffffffff))
      ;; r_info = ELF64_R_INFO(sym, type) = (sym << 32) | type
      (put-u32 8 rel-type)
      (put-u32 12 sym-index))
    data))

;;; Symbol table entry: 24 bytes each
;;; st_name(4) st_info(1) st_other(1) st_shndx(2) st_value(8) st_size(8)

(defun encode-sym (name-offset info other shndx value size)
  (let ((data (make-array 24 :element-type '(unsigned-byte 8) :initial-element 0)))
    (flet ((put-u16 (off val)
             (setf (aref data (+ off 0)) (logand val #xff))
             (setf (aref data (+ off 1)) (logand (ash val -8) #xff)))
           (put-u32 (off val)
             (setf (aref data (+ off 0)) (logand val #xff))
             (setf (aref data (+ off 1)) (logand (ash val -8) #xff))
             (setf (aref data (+ off 2)) (logand (ash val -16) #xff))
             (setf (aref data (+ off 3)) (logand (ash val -24) #xff))))
      (put-u32 0 name-offset)               ; st_name
      (setf (aref data 4) info)             ; st_info
      (setf (aref data 5) other)            ; st_other
      (put-u16 6 shndx)                     ; st_shndx
      (put-u32 8 (logand value #xffffffff)) ; st_value low
      (put-u32 12 (logand (ash value -32) #xffffffff)) ; st_value high
      (put-u32 16 (logand size #xffffffff)) ; st_size low
      (put-u32 20 (logand (ash size -32) #xffffffff))) ; st_size high
    data))

(defun st-info (bind type)
  (logior (ash bind 4) type))

;;; Main ELF writer

(defun write-bpf-elf (pathname &key prog-sections maps license btf-data btf-ext-data)
  "Write a BPF ELF object file with one or more programs.
   PROG-SECTIONS: list of (section-name prog-bytes relocations core-relocs) per program
   MAPS: list of (name type key-size value-size max-entries &optional flags)
   LICENSE: string like \"GPL\"
   BTF-DATA: byte vector for .BTF section (or nil)
   BTF-EXT-DATA: byte vector for .BTF.ext section (or nil)"
  (let ((prog-sections prog-sections))
    (with-open-file (out pathname :direction :output
                                :element-type '(unsigned-byte 8)
                                :if-exists :supersede)
      (let* ((shstrtab (make-strtab))
             (strtab (make-strtab))
             (sections '())
             (syms '())
             (sec-index 0)
             (maps-sec-idx nil)
             (prog-sec-indices '()))  ; ((section-name . sec-idx) ...)

        (labels ((next-sec-idx () (incf sec-index)))

        ;; -- Program sections (one per program) --
        (dolist (prog-entry prog-sections)
          (let* ((sec-name (first prog-entry))
                 (prog-bytes (second prog-entry))
                 (name-off (strtab-add shstrtab sec-name)))
            (next-sec-idx)
            (push (cons sec-name sec-index) prog-sec-indices)
            (push (make-elf-section
                   :name sec-name
                   :name-offset name-off
                   :type +sht-progbits+
                   :flags (logior +shf-alloc+ +shf-execinstr+)
                   :data prog-bytes
                   :link 0 :info 0
                   :addralign 8
                   :entsize 0)
                  sections)))
        (setf prog-sec-indices (nreverse prog-sec-indices))

        ;; -- Maps section (if any maps) --
        (when maps
          (let* ((name-off (strtab-add shstrtab ".maps"))
                 (map-data (make-array (* 32 (length maps))
                                       :element-type '(unsigned-byte 8))))
            (next-sec-idx)
            (setf maps-sec-idx sec-index)
            (loop for map-entry in maps
                  for i from 0
                  for mtype = (second map-entry)
                  for ksize = (third map-entry)
                  for vsize = (fourth map-entry)
                  for maxent = (fifth map-entry)
                  for mflags = (or (sixth map-entry) 0)
                  for entry = (encode-map-def mtype ksize vsize maxent mflags)
                  do (replace map-data entry :start1 (* i 32)))
            (push (make-elf-section
                   :name ".maps"
                   :name-offset name-off
                   :type +sht-progbits+
                   :flags +shf-alloc+
                   :data map-data
                   :link 0 :info 0
                   :addralign 4
                   :entsize 0)
                  sections)))

        ;; -- License section --
        (let* ((lic-str (or license "GPL"))
               (lic-bytes (let ((v (make-array (1+ (length lic-str))
                                               :element-type '(unsigned-byte 8))))
                            (loop for i below (length lic-str)
                                  do (setf (aref v i) (char-code (char lic-str i))))
                            (setf (aref v (length lic-str)) 0)
                            v))
               (name-off (strtab-add shstrtab "license")))
          (next-sec-idx)
          (push (make-elf-section
                 :name "license"
                 :name-offset name-off
                 :type +sht-progbits+
                 :flags +shf-alloc+
                 :data lic-bytes
                 :link 0 :info 0
                 :addralign 1
                 :entsize 0)
                sections))

        ;; -- BTF section --
        (when btf-data
          (let ((name-off (strtab-add shstrtab ".BTF")))
            (next-sec-idx)
            (push (make-elf-section
                   :name ".BTF"
                   :name-offset name-off
                   :type +sht-progbits+
                   :flags 0
                   :data btf-data
                   :link 0 :info 0
                   :addralign 4
                   :entsize 0)
                  sections)))

        ;; -- BTF.ext section --
        (when btf-ext-data
          (let ((name-off (strtab-add shstrtab ".BTF.ext")))
            (next-sec-idx)
            (push (make-elf-section
                   :name ".BTF.ext"
                   :name-offset name-off
                   :type +sht-progbits+
                   :flags 0
                   :data btf-ext-data
                   :link 0 :info 0
                   :addralign 4
                   :entsize 0)
                  sections)))

        ;; -- Build symbol table --
        ;; Symbol 0: null
        (push (encode-sym 0 0 0 0 0 0) syms)

        ;; Section symbols for each program section (local)
        (dolist (entry prog-sec-indices)
          (push (encode-sym 0 (st-info +stb-local+ +stt-section+) 0
                            (cdr entry) 0 0)
                syms))

        ;; Map symbols (global)
        (let ((first-global-sym (length syms))
              ;; Map sym index base: null + N section syms
              (map-sym-base (1+ (length prog-sec-indices))))
          (when maps
            (loop for (name . rest) in maps
                  for i from 0
                  for name-off = (strtab-add strtab
                                  (substitute #\_ #\- (string-downcase (string name))))
                  do (push (encode-sym name-off
                                       (st-info +stb-global+ +stt-object+) 0
                                       maps-sec-idx (* i 32) 32)
                           syms)))

          ;; Program function symbols (global, one per program)
          (dolist (prog-entry prog-sections)
            (let* ((sec-name (first prog-entry))
                   (prog-bytes (second prog-entry))
                   (prog-name (or (fifth prog-entry) sec-name))
                   (sec-idx (cdr (assoc sec-name prog-sec-indices :test #'string=)))
                   (func-name-off (strtab-add strtab prog-name)))
              (push (encode-sym func-name-off
                                (st-info +stb-global+ 2) 0  ; STT_FUNC=2
                                sec-idx 0 (length prog-bytes))
                    syms)))

          ;; Finalize symbol table
          (setf syms (nreverse syms))
          (let* ((num-syms (length syms))
                 (symtab-data (make-array (* num-syms 24)
                                          :element-type '(unsigned-byte 8))))
            (loop for sym in syms for i from 0
                  do (replace symtab-data sym :start1 (* i 24)))

            ;; -- Strtab section --
            (let ((strtab-name-off (strtab-add shstrtab ".strtab")))
              (next-sec-idx)
              (let ((strtab-sec-idx sec-index))
                (push (make-elf-section
                       :name ".strtab"
                       :name-offset strtab-name-off
                       :type +sht-strtab+
                       :flags 0
                       :data (copy-seq strtab)
                       :link 0 :info 0
                       :addralign 1
                       :entsize 0)
                      sections)

                ;; -- Symtab section --
                (let ((symtab-name-off (strtab-add shstrtab ".symtab")))
                  (next-sec-idx)
                  (let ((symtab-sec-idx sec-index))
                    (push (make-elf-section
                           :name ".symtab"
                           :name-offset symtab-name-off
                           :type +sht-symtab+
                           :flags 0
                           :data symtab-data
                           :link strtab-sec-idx
                           :info first-global-sym
                           :addralign 8
                           :entsize 24)
                          sections)

                    ;; -- Relocation sections (one per program with relocations) --
                    (dolist (prog-entry prog-sections)
                      (let* ((sec-name (first prog-entry))
                             (relocations (third prog-entry))
                             (sec-idx (cdr (assoc sec-name prog-sec-indices
                                                  :test #'string=))))
                        (when (and relocations maps)
                          (let* ((rel-sec-name (format nil ".rel~a" sec-name))
                                 (rel-name-off (strtab-add shstrtab rel-sec-name))
                                 (rel-data (make-array (* 16 (length relocations))
                                                       :element-type '(unsigned-byte 8))))
                            (loop for (insn-off map-idx) in relocations
                                  for i from 0
                                  for sym-idx = (+ map-sym-base map-idx)
                                  for entry = (encode-rel insn-off sym-idx +r-bpf-64-64+)
                                  do (replace rel-data entry :start1 (* i 16)))
                            (next-sec-idx)
                            (push (make-elf-section
                                   :name rel-sec-name
                                   :name-offset rel-name-off
                                   :type +sht-rel+
                                   :flags 0
                                   :data rel-data
                                   :link symtab-sec-idx
                                   :info sec-idx
                                   :addralign 8
                                   :entsize 16)
                                  sections)))))

                    ;; -- Shstrtab section (must be last) --
                    (let ((shstrtab-name-off (strtab-add shstrtab ".shstrtab")))
                      (next-sec-idx)
                      (let ((shstrtab-sec-idx sec-index))
                        (push (make-elf-section
                               :name ".shstrtab"
                               :name-offset shstrtab-name-off
                               :type +sht-strtab+
                               :flags 0
                               :data (copy-seq shstrtab)
                               :link 0 :info 0
                               :addralign 1
                               :entsize 0)
                              sections)

                        ;; Reverse sections to correct order
                        (setf sections (nreverse sections))

                        ;; -- Layout: compute file offsets --
                        ;; ELF header = 64 bytes
                        ;; Sections follow, then section header table
                        (let ((pos 64))
                          ;; Align and assign offsets
                          (dolist (sec sections)
                            (let ((align (max 1 (elf-section-addralign sec))))
                              (setf pos (let ((rem (mod pos align)))
                                          (if (zerop rem) pos (+ pos (- align rem)))))
                              (setf (elf-section-file-offset sec) pos)
                              (incf pos (length (elf-section-data sec)))))

                          ;; Section header table offset (align to 8)
                          (let ((rem (mod pos 8)))
                            (unless (zerop rem) (setf pos (+ pos (- 8 rem)))))
                          (let ((shoff pos)
                                (num-sections (1+ (length sections)))) ; +1 for null

                            ;; === Write the file ===

                            ;; ELF header (64 bytes)
                            (write-bytes out #(#x7f #x45 #x4c #x46)) ; magic
                            (write-u8 out +elfclass64+)
                            (write-u8 out +elfdata2lsb+)
                            (write-u8 out +ev-current+)
                            (write-u8 out +elfosabi-none+)
                            (dotimes (i 8) (write-u8 out 0))  ; padding
                            (write-u16le out +et-rel+)         ; e_type
                            (write-u16le out +em-bpf+)         ; e_machine
                            (write-u32le out +ev-current+)     ; e_version
                            (write-u64le out 0)                ; e_entry
                            (write-u64le out 0)                ; e_phoff
                            (write-u64le out shoff)            ; e_shoff
                            (write-u32le out 0)                ; e_flags
                            (write-u16le out 64)               ; e_ehsize
                            (write-u16le out 0)                ; e_phentsize
                            (write-u16le out 0)                ; e_phnum
                            (write-u16le out 64)               ; e_shentsize
                            (write-u16le out num-sections)     ; e_shnum
                            (write-u16le out shstrtab-sec-idx) ; e_shstrndx

                            ;; Section data
                            (let ((cur-pos 64))
                              (dolist (sec sections)
                                ;; Write padding
                                (let ((target (elf-section-file-offset sec)))
                                  (dotimes (i (- target cur-pos))
                                    (write-u8 out 0))
                                  (setf cur-pos target))
                                ;; Write data
                                (write-sequence (elf-section-data sec) out)
                                (incf cur-pos (length (elf-section-data sec))))

                              ;; Pad to section header table
                              (dotimes (i (- shoff cur-pos))
                                (write-u8 out 0)))

                            ;; Section header table
                            ;; Entry 0: null
                            (dotimes (i 64) (write-u8 out 0))

                            ;; Remaining entries
                            (dolist (sec sections)
                              (write-u32le out (elf-section-name-offset sec)) ; sh_name
                              (write-u32le out (elf-section-type sec))        ; sh_type
                              (write-u64le out (elf-section-flags sec))       ; sh_flags
                              (write-u64le out 0)                             ; sh_addr
                              (write-u64le out (elf-section-file-offset sec)) ; sh_offset
                              (write-u64le out (length (elf-section-data sec))) ; sh_size
                              (write-u32le out (elf-section-link sec))        ; sh_link
                              (write-u32le out (elf-section-info sec))        ; sh_info
                              (write-u64le out (elf-section-addralign sec))   ; sh_addralign
                              (write-u64le out (elf-section-entsize sec)))))))))))))))))) ; sh_entsize

