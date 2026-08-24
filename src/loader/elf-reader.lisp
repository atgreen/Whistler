;;; elf-reader.lisp — Parse BPF ELF object files
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Reads 64-bit little-endian BPF ELF relocatable objects (.bpf.o).

(in-package #:whistler/loader)

;;; ELF constants and byte readers come from whistler/binary.

;;; ========== Data structures ==========

(defstruct elf-section
  name type flags data link info offset size)

(defstruct elf-sym
  name info shndx value size)

(defstruct elf-rel
  offset sym-idx type)

(defstruct bpf-elf
  sections symtab strtab shstrtab license
  prog-sections map-section rel-sections)

;;; ========== Parsing ==========

(defun read-elf-bytes (pathname)
  "Read a file into a byte vector."
  (with-open-file (f pathname :element-type '(unsigned-byte 8))
    (let ((bytes (make-array (file-length f) :element-type '(unsigned-byte 8))))
      (read-sequence bytes f)
      bytes)))

(defun elf-string (strtab offset)
  "Read a null-terminated string from a string table byte vector."
  (let ((end (position 0 strtab :start offset)))
    (map 'string #'code-char (subseq strtab offset (or end (length strtab))))))

(defun parse-section-header (bytes offset)
  "Parse a 64-byte ELF section header."
  (multiple-value-bind (name type flags sec-off size link info)
      (elf64-shdr-fields bytes offset)
    (make-elf-section
     :name name :type type :flags flags
     :offset sec-off :size size :link link :info info)))

(defun parse-symtab-entry (bytes offset strtab)
  "Parse a 24-byte ELF symbol table entry."
  (multiple-value-bind (name-off info shndx value size)
      (elf64-sym-fields bytes offset)
    (make-elf-sym
     :name (elf-string strtab name-off)
     :info info :shndx shndx :value value :size size)))

(defun parse-rel-entry (bytes offset)
  "Parse a 16-byte ELF REL entry.
   r_info packs sym index (high 32) and relocation type (low 32)."
  (let ((r-info (u64 bytes (+ offset 8))))
    (make-elf-rel
     :offset (u64 bytes offset)
     :sym-idx (ash r-info -32)
     :type (logand r-info #xffffffff))))

;;; ========== Top-level parser ==========

(defun read-bpf-elf (pathname)
  "Parse a BPF ELF object file. Returns a bpf-elf structure."
  (let* ((bytes (read-elf-bytes pathname))
         ;; Validate ELF header
         (magic (u32 bytes 0))
         (class (aref bytes 4))
         (data (aref bytes 5))
         (machine (u16 bytes 18)))
    (unless (= magic +elf-magic+)
      (error "Not an ELF file: ~a" pathname))
    (unless (and (= class 2) (= data 1) (= machine +em-bpf+))
      (error "Not a 64-bit LE BPF ELF: class=~d data=~d machine=~d"
             class data machine))

    (multiple-value-bind (e-shoff e-shentsize e-shnum e-shstrndx)
        (elf64-shdr-table bytes)
      (let* (;; Parse all section headers
           (sections (loop for i below e-shnum
                           collect (parse-section-header
                                    bytes (+ e-shoff (* i e-shentsize)))))
           ;; Get section name string table
           (shstrtab-sec (nth e-shstrndx sections))
           (shstrtab (subseq bytes
                             (elf-section-offset shstrtab-sec)
                             (+ (elf-section-offset shstrtab-sec)
                                (elf-section-size shstrtab-sec)))))

      ;; Resolve section names and extract data
      (dolist (sec sections)
        (setf (elf-section-name sec)
              (elf-string shstrtab (elf-section-name sec)))
        (when (plusp (elf-section-size sec))
          (setf (elf-section-data sec)
                (subseq bytes
                        (elf-section-offset sec)
                        (+ (elf-section-offset sec) (elf-section-size sec))))))

      ;; Find symtab and its string table
      (let* ((symtab-sec (find +sht-symtab+ sections :key #'elf-section-type))
             (strtab-sec (when symtab-sec
                           (nth (elf-section-link symtab-sec) sections)))
             (strtab (when strtab-sec (elf-section-data strtab-sec)))
             (symtab (when (and symtab-sec strtab)
                       (let ((data (elf-section-data symtab-sec)))
                         (loop for off from 0 below (length data) by 24
                               collect (parse-symtab-entry data off strtab)))))
             ;; Find license
             (license-sec (find "license" sections
                                :key #'elf-section-name :test #'string=))
             (license (when license-sec
                        (let ((data (elf-section-data license-sec)))
                          (map 'string #'code-char
                               (subseq data 0 (or (position 0 data)
                                                   (length data)))))))
             ;; Categorize sections
             (prog-sections '())
             (map-section nil)
             (rel-sections '()))

        ;; Sort sections by type
        (loop for sec in sections
              for idx from 0
              do (cond
                   ;; Program sections: PROGBITS with EXECINSTR
                   ((and (= (elf-section-type sec) +sht-progbits+)
                         (logtest (elf-section-flags sec) +shf-execinstr+))
                    (push (cons idx sec) prog-sections))
                   ;; Maps section
                   ((and (= (elf-section-type sec) +sht-progbits+)
                         (member (elf-section-name sec) '("maps" ".maps")
                                 :test #'string=))
                    (setf map-section (cons idx sec)))
                   ;; Relocation sections
                   ((= (elf-section-type sec) +sht-rel+)
                    (let ((target-idx (elf-section-info sec))
                          (data (elf-section-data sec)))
                      (when data
                        (push (cons target-idx
                                    (loop for off from 0 below (length data) by 16
                                          collect (parse-rel-entry data off)))
                              rel-sections))))))

        (make-bpf-elf
         :sections sections
         :symtab symtab
         :strtab strtab
         :shstrtab shstrtab
         :license license
         :prog-sections (nreverse prog-sections)
         :map-section map-section
         :rel-sections rel-sections))))))
