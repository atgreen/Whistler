;;; -*- Mode: Lisp -*-
;;;
;;; Copyright (c) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; SPDX-License-Identifier: MIT

(in-package #:whistler/elf)

;;; Minimal ELF writer for BPF object files
;;; Produces 64-bit little-endian ELF relocatable objects

;; ELF constants and byte writers come from whistler/binary.

;;; Binary writing utilities

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

(defun collect-kfunc-names (prog-sections)
  "Return the ordered, deduplicated list of kfunc names referenced across
   PROG-SECTIONS. Each entry's 6th element is its kfunc relocations
   ((byte-offset name) ...); order follows first appearance."
  (let ((seen (make-hash-table :test 'equal))
        (names '()))
    (dolist (prog-entry prog-sections)
      (dolist (reloc (sixth prog-entry))
        (let ((name (second reloc)))
          (unless (gethash name seen)
            (setf (gethash name seen) t)
            (push name names)))))
    (nreverse names)))

;;; Builder state shared by the write-bpf-elf phases

(defstruct (elf-builder (:constructor make-elf-builder ()))
  (shstrtab (make-strtab))  ; section-name string table
  (strtab (make-strtab))    ; symbol-name string table
  (sections '())            ; elf-sections, in reverse order until layout
  (sec-index 0))            ; last assigned section header index

(defun builder-add-section (builder name &key type flags data
                                           (link 0) (info 0)
                                           (addralign 1) (entsize 0))
  "Add a section to BUILDER, interning NAME in its shstrtab.
   Returns the new section's header index."
  (let ((name-off (strtab-add (elf-builder-shstrtab builder) name)))
    (push (make-elf-section
           :name name
           :name-offset name-off
           :type type
           :flags flags
           :data data
           :link link :info info
           :addralign addralign
           :entsize entsize)
          (elf-builder-sections builder))
    (incf (elf-builder-sec-index builder))))

;;; Section-building phases

(defun add-prog-sections (builder prog-sections)
  "Add one executable section per program.
   Returns ((section-name . sec-idx) ...) in program order."
  (loop for prog-entry in prog-sections
        for sec-name = (first prog-entry)
        collect (cons sec-name
                      (builder-add-section
                       builder sec-name
                       :type +sht-progbits+
                       :flags (logior +shf-alloc+ +shf-execinstr+)
                       :data (second prog-entry)
                       :addralign 8))))

(defun add-maps-section (builder maps)
  "Add the .maps section, one 32-byte map def per map.
   Returns its section index, or NIL when there are no maps."
  (when maps
    (let ((map-data (make-array (* 32 (length maps))
                                :element-type '(unsigned-byte 8))))
      (loop for map-entry in maps
            for i from 0
            for mtype = (second map-entry)
            for ksize = (third map-entry)
            for vsize = (fourth map-entry)
            for maxent = (fifth map-entry)
            for mflags = (or (sixth map-entry) 0)
            for entry = (encode-map-def mtype ksize vsize maxent mflags)
            do (replace map-data entry :start1 (* i 32)))
      (builder-add-section builder ".maps"
                           :type +sht-progbits+
                           :flags +shf-alloc+
                           :data map-data
                           :addralign 4))))

(defun add-license-section (builder license)
  "Add the license section (NUL-terminated string, defaulting to \"GPL\")."
  (let* ((lic-str (or license "GPL"))
         (lic-bytes (let ((v (make-array (1+ (length lic-str))
                                         :element-type '(unsigned-byte 8))))
                      (loop for i below (length lic-str)
                            do (setf (aref v i) (char-code (char lic-str i))))
                      (setf (aref v (length lic-str)) 0)
                      v)))
    (builder-add-section builder "license"
                         :type +sht-progbits+
                         :flags +shf-alloc+
                         :data lic-bytes
                         :addralign 1)))

(defun add-btf-sections (builder btf-data btf-ext-data)
  "Add the .BTF and .BTF.ext sections when their data is present."
  (when btf-data
    (builder-add-section builder ".BTF"
                         :type +sht-progbits+
                         :flags 0
                         :data btf-data
                         :addralign 4))
  (when btf-ext-data
    (builder-add-section builder ".BTF.ext"
                         :type +sht-progbits+
                         :flags 0
                         :data btf-ext-data
                         :addralign 4)))

(defun build-symtab (builder prog-sections maps maps-sec-idx prog-sec-indices
                     kfunc-sym-index)
  "Build the symbol table: a null symbol, one local section symbol per
   program section, then global map, program function, and extern kfunc
   symbols. Names are interned in BUILDER's strtab; each kfunc's symbol
   index is recorded in KFUNC-SYM-INDEX for the relocation phase.
   Returns (values symtab-data first-global-sym map-sym-base)."
  (let ((strtab (elf-builder-strtab builder))
        (syms '()))
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
                            (st-info +stb-global+ +stt-func+) 0
                            sec-idx 0 (length prog-bytes))
                syms)))

      ;; Kfunc extern symbols (global, undefined). One per unique kfunc
      ;; name referenced by any program. A call relocation targets these;
      ;; the loader resolves each name to a kernel BTF id at load time.
      ;; kfunc syms follow map + prog-func syms, so their base index is
      ;; map-sym-base + n-maps + n-progs. Indices are recorded in the
      ;; kfunc-sym-index table for the relocation phase.
      (let ((kfunc-sym-base (+ map-sym-base (length maps)
                               (length prog-sections))))
        (loop for name in (collect-kfunc-names prog-sections)
              for i from 0
              for name-off = (strtab-add strtab name)
              do (setf (gethash name kfunc-sym-index) (+ kfunc-sym-base i))
                 (push (encode-sym name-off
                                   (st-info +stb-global+ +stt-notype+) 0
                                   +shn-undef+ 0 0)
                       syms)))

      ;; Finalize symbol table
      (setf syms (nreverse syms))
      (let* ((num-syms (length syms))
             (symtab-data (make-array (* num-syms 24)
                                      :element-type '(unsigned-byte 8))))
        (loop for sym in syms for i from 0
              do (replace symtab-data sym :start1 (* i 24)))
        (values symtab-data first-global-sym map-sym-base)))))

(defun add-rel-sections (builder prog-sections maps prog-sec-indices
                         symtab-sec-idx map-sym-base kfunc-sym-index)
  "Add one .rel<section> per program with relocations. Combines map fd
   relocations (R_BPF_64_64 on ld_imm64, sym = a map symbol) and kfunc
   call relocations (R_BPF_64_32 on the call imm, sym = an extern kfunc).
   A program may have kfunc relocs without any maps."
  (dolist (prog-entry prog-sections)
    (let* ((sec-name (first prog-entry))
           (map-relocations (third prog-entry))
           (kfunc-relocations (sixth prog-entry))
           (sec-idx (cdr (assoc sec-name prog-sec-indices
                                :test #'string=)))
           (rel-entries
            (append
             (when maps
               (loop for (insn-off map-idx) in map-relocations
                     collect (encode-rel insn-off
                                         (+ map-sym-base map-idx)
                                         +r-bpf-64-64+)))
             (loop for (insn-off name) in kfunc-relocations
                   collect (encode-rel
                            insn-off
                            (gethash name kfunc-sym-index)
                            +r-bpf-64-32+)))))
      (when rel-entries
        (let ((rel-data (make-array (* 16 (length rel-entries))
                                    :element-type '(unsigned-byte 8))))
          (loop for entry in rel-entries
                for i from 0
                do (replace rel-data entry :start1 (* i 16)))
          (builder-add-section builder (format nil ".rel~a" sec-name)
                               :type +sht-rel+
                               :flags 0
                               :data rel-data
                               :link symtab-sec-idx
                               :info sec-idx
                               :addralign 8
                               :entsize 16))))))

(defun add-shstrtab-section (builder)
  "Add the .shstrtab section (must be last). Its own name is interned
   before the table is snapshotted so it appears in its own data.
   Returns its section index."
  (let ((name-off (strtab-add (elf-builder-shstrtab builder) ".shstrtab")))
    (push (make-elf-section
           :name ".shstrtab"
           :name-offset name-off
           :type +sht-strtab+
           :flags 0
           :data (copy-seq (elf-builder-shstrtab builder))
           :link 0 :info 0
           :addralign 1
           :entsize 0)
          (elf-builder-sections builder))
    (incf (elf-builder-sec-index builder))))

;;; Layout and file writing

(defun layout-sections (sections)
  "Assign each section's file offset: the ELF header is 64 bytes, section
   data follows (aligned per section), then the section header table
   (aligned to 8). Returns the section header table offset."
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
    pos))

(defun write-elf-header (out shoff num-sections shstrtab-sec-idx)
  "Write the 64-byte ELF header."
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
  (write-u16le out shstrtab-sec-idx)) ; e_shstrndx

(defun write-section-data (out sections shoff)
  "Write each section's data at its laid-out offset, padding between
   sections and up to the section header table at SHOFF."
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
      (write-u8 out 0))))

(defun write-section-headers (out sections)
  "Write the section header table: a null entry, then one 64-byte header
   per section."
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
    (write-u64le out (elf-section-entsize sec))))   ; sh_entsize

(defun write-bpf-elf (pathname &key prog-sections maps license btf-data btf-ext-data)
  "Write a BPF ELF object file with one or more programs.
   PROG-SECTIONS: list of (section-name prog-bytes relocations core-relocs) per program
   MAPS: list of (name type key-size value-size max-entries &optional flags)
   LICENSE: string like \"GPL\"
   BTF-DATA: byte vector for .BTF section (or nil)
   BTF-EXT-DATA: byte vector for .BTF.ext section (or nil)"
  (with-open-file (out pathname :direction :output
                                :element-type '(unsigned-byte 8)
                                :if-exists :supersede)
    (let* ((builder (make-elf-builder))
           (kfunc-sym-index (make-hash-table :test 'equal))  ; kfunc name → sym idx
           ;; -- Sections: programs, maps, license, BTF --
           (prog-sec-indices (add-prog-sections builder prog-sections))
           (maps-sec-idx (add-maps-section builder maps)))
      (add-license-section builder license)
      (add-btf-sections builder btf-data btf-ext-data)

      ;; -- Symbol table, then .strtab/.symtab sections --
      (multiple-value-bind (symtab-data first-global-sym map-sym-base)
          (build-symtab builder prog-sections maps maps-sec-idx
                        prog-sec-indices kfunc-sym-index)
        (let* ((strtab-sec-idx
                (builder-add-section builder ".strtab"
                                     :type +sht-strtab+
                                     :flags 0
                                     :data (copy-seq (elf-builder-strtab builder))
                                     :addralign 1))
               (symtab-sec-idx
                (builder-add-section builder ".symtab"
                                     :type +sht-symtab+
                                     :flags 0
                                     :data symtab-data
                                     :link strtab-sec-idx
                                     :info first-global-sym
                                     :addralign 8
                                     :entsize 24)))

          ;; -- Relocation sections (one per program with relocations) --
          (add-rel-sections builder prog-sections maps prog-sec-indices
                            symtab-sec-idx map-sym-base kfunc-sym-index)

          ;; -- Shstrtab section (must be last), then layout and write --
          (let* ((shstrtab-sec-idx (add-shstrtab-section builder))
                 (sections (nreverse (elf-builder-sections builder)))
                 (shoff (layout-sections sections))
                 (num-sections (1+ (length sections)))) ; +1 for null
            (write-elf-header out shoff num-sections shstrtab-sec-idx)
            (write-section-data out sections shoff)
            (write-section-headers out sections)))))))

