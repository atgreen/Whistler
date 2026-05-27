;;; elf.lisp — minimal ELF64 reader for symbol resolution
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Parses an ELF64 file just far enough to extract function symbols
;;; from `.symtab' (if present, full table) or `.dynsym' (always
;;; present in dynamically-linked binaries, only the exports).
;;;
;;; Layout we care about (all little-endian for the architectures
;;; bpf actually runs on):
;;;
;;;   Bytes 0..63           : ELF header (Elf64_Ehdr)
;;;     0..15  e_ident       : 0x7F 'E' 'L' 'F', class, data, version, …
;;;     16     e_type        : 1=REL, 2=EXEC, 3=DYN (PIE / .so)
;;;     32     e_phoff       : program header table offset
;;;     40     e_shoff       : section header table offset
;;;     54     e_shentsize   : section header entry size (64 for ELF64)
;;;     56     e_shnum       : number of section headers
;;;     58     e_shstrndx    : section index of section-name string table
;;;
;;;   Each section header (64 bytes, Elf64_Shdr):
;;;     0      sh_name       : offset into shstrtab
;;;     4      sh_type       : SHT_SYMTAB=2, SHT_DYNSYM=11, SHT_NOTE=7, ...
;;;     16     sh_addr
;;;     24     sh_offset     : file offset of the section's bytes
;;;     32     sh_size
;;;     40     sh_link       : index of associated section (e.g. strtab)
;;;     ...
;;;
;;;   Each Elf64_Sym (24 bytes):
;;;     0      st_name       : offset into linked strtab
;;;     4      st_info       : low nybble = TYPE (STT_FUNC=2),
;;;                            high nybble = BIND
;;;     5      st_other
;;;     6      st_shndx
;;;     8      st_value      : virtual address (for ET_DYN: relative
;;;                            to load base; for ET_EXEC: absolute)
;;;     16     st_size

(in-package #:whistler/symbolize)

;;; ========== Byte-level helpers ==========

(declaim (inline u8 u16 u32 u64))

(defun u8  (buf off) (aref buf off))
(defun u16 (buf off)
  (logior (aref buf off)
          (ash (aref buf (+ off 1))  8)))
(defun u32 (buf off)
  (logior (aref buf off)
          (ash (aref buf (+ off 1))  8)
          (ash (aref buf (+ off 2)) 16)
          (ash (aref buf (+ off 3)) 24)))
(defun u64 (buf off)
  (logior (u32 buf off) (ash (u32 buf (+ off 4)) 32)))

(defun read-file-bytes (path)
  "Read PATH into a fresh (UNSIGNED-BYTE 8) vector. Returns NIL on any
   I/O error (missing file, permission denied, etc.)."
  (handler-case
      (with-open-file (s path :direction :input
                              :element-type '(unsigned-byte 8))
        (let* ((len (file-length s))
               (buf (make-array len :element-type '(unsigned-byte 8))))
          (read-sequence buf s)
          buf))
    (error () nil)))

;;; ========== ELF constants ==========

(defconstant +sht-symtab+   2)
(defconstant +sht-dynsym+  11)
(defconstant +sht-note+     7)
(defconstant +sht-progbits+ 1)
(defconstant +stt-func+     2)
(defconstant +nt-gnu-build-id+ 3)

(defconstant +et-exec+ 2)
(defconstant +et-dyn+  3)

;;; ========== Per-file info ==========

(defstruct elf-info
  path            ; "/usr/lib64/libc.so.6"
  pie-p           ; T if e_type is ET_DYN (loaded at a relocatable base)
  symbols)        ; sorted vector of #(VADDR SIZE NAME) entries

;;; ========== Parsing ==========

(defun valid-elf64-p (buf)
  "Quick sanity check: ELF magic, 64-bit class, little-endian."
  (and (>= (length buf) 64)
       (= (u8 buf 0) #x7f)
       (= (u8 buf 1) (char-code #\E))
       (= (u8 buf 2) (char-code #\L))
       (= (u8 buf 3) (char-code #\F))
       (= (u8 buf 4) 2)            ; ELFCLASS64
       (= (u8 buf 5) 1)))          ; ELFDATA2LSB

(defstruct section
  name-off       ; sh_name (offset into shstrtab)
  type           ; sh_type
  offset         ; sh_offset (file offset of bytes)
  size           ; sh_size
  link)          ; sh_link

(defun read-section-headers (buf)
  "Walk the section header table; return (values SECTIONS SHSTRTAB-SEC)."
  (let* ((e-shoff     (u64 buf 40))
         (e-shentsize (u16 buf 58))
         (e-shnum     (u16 buf 60))
         (e-shstrndx  (u16 buf 62))
         (secs (make-array e-shnum)))
    (dotimes (i e-shnum)
      (let ((off (+ e-shoff (* i e-shentsize))))
        (setf (aref secs i)
              (make-section :name-off (u32 buf off)
                            :type     (u32 buf (+ off 4))
                            :offset   (u64 buf (+ off 24))
                            :size     (u64 buf (+ off 32))
                            :link     (u32 buf (+ off 40))))))
    (values secs (aref secs e-shstrndx))))

(defun section-name (buf shstrtab sec)
  (let ((base (section-offset shstrtab))
        (off  (section-name-off sec)))
    (cstring-at buf (+ base off))))

(defun cstring-at (buf off)
  "Read a NUL-terminated UTF-8 string starting at OFF, return as a
   Lisp string."
  (let ((end off)
        (n   (length buf)))
    (loop while (and (< end n) (not (zerop (aref buf end))))
          do (incf end))
    (sb-ext:octets-to-string buf :start off :end end
                                 :external-format :utf-8)))

(defun parse-symbol-table (buf sym-sec str-sec)
  "Parse Elf64_Sym entries; return a vector of #(VADDR SIZE NAME)
   for STT_FUNC entries with non-zero size."
  (let* ((base      (section-offset sym-sec))
         (size      (section-size sym-sec))
         (str-base  (section-offset str-sec))
         (n         (floor size 24))
         (out       (make-array (max 1 n) :fill-pointer 0 :adjustable t)))
    (dotimes (i n)
      (let* ((off    (+ base (* i 24)))
             (info   (u8  buf (+ off 4)))
             (type   (logand info #x0f))
             (st-val (u64 buf (+ off 8)))
             (st-sz  (u64 buf (+ off 16))))
        (when (and (= type +stt-func+) (plusp st-sz))
          (let* ((name-off (u32 buf off))
                 (name (cstring-at buf (+ str-base name-off))))
            (when (plusp (length name))
              (vector-push-extend (vector st-val st-sz name) out))))))
    (sort out #'< :key (lambda (e) (aref e 0)))))

;;; ========== Build-ID / .gnu_debuglink ==========
;;;
;;; A stripped binary still ships its `.dynsym' (exports), but the
;;; full `.symtab' and any local-symbol info live in a separate
;;; .debug file. Two ways to find it:
;;;
;;;   1. Build-ID: a 20-byte SHA1 in `.note.gnu.build-id'. Debug file
;;;      lives at /usr/lib/debug/.build-id/XX/YYYY...debug, where XX
;;;      is the first 2 hex chars and YYYY... is the remaining 38.
;;;   2. `.gnu_debuglink' section: contains a filename + CRC. The
;;;      file lives in /usr/lib/debug/<dir-of-original>/<filename>,
;;;      or beside the original.
;;;
;;; We try (1) first because it's the modern convention and doesn't
;;; rely on path layout. (2) is a fallback.

(defun read-build-id (buf secs shstrtab)
  "Find `.note.gnu.build-id', extract the 20-byte build-id as a
   lowercase hex string. Returns NIL if absent."
  (loop for sec across secs
        when (and (= (section-type sec) +sht-note+)
                  (string= (section-name buf shstrtab sec)
                           ".note.gnu.build-id"))
          return (let* ((off     (section-offset sec))
                        (namesz  (u32 buf off))
                        (descsz  (u32 buf (+ off 4)))
                        (ntype   (u32 buf (+ off 8)))
                        (desc-off (+ off 12
                                     ;; name is NUL-terminated, padded to 4
                                     (logand (+ namesz 3) (lognot 3)))))
                   (when (= ntype +nt-gnu-build-id+)
                     (with-output-to-string (s)
                       (dotimes (i descsz)
                         (format s "~(~2,'0X~)" (u8 buf (+ desc-off i)))))))))

(defun read-debuglink (buf secs shstrtab)
  "Read `.gnu_debuglink' content: a NUL-terminated filename. Returns
   the filename string or NIL."
  (loop for sec across secs
        when (and (= (section-type sec) +sht-progbits+)
                  (string= (section-name buf shstrtab sec)
                           ".gnu_debuglink"))
          return (cstring-at buf (section-offset sec))))

(defun find-debug-file (path build-id debuglink)
  "Try the standard debuginfo locations. Returns a readable path or NIL."
  (flet ((readable (p) (and p (probe-file p) p)))
    (or
     ;; Build-ID convention: /usr/lib/debug/.build-id/XX/YYYY...debug
     (and build-id (>= (length build-id) 2)
          (readable
           (format nil "/usr/lib/debug/.build-id/~A/~A.debug"
                   (subseq build-id 0 2) (subseq build-id 2))))
     ;; debuglink relative to original
     (and debuglink
          (let* ((dir (directory-namestring path)))
            (or
             (readable (format nil "/usr/lib/debug~A~A" dir debuglink))
             (readable (format nil "~A.debug/~A" dir debuglink))
             (readable (format nil "~A~A" dir debuglink))))))))

(defun parse-elf-symbols-from (path)
  "Parse PATH and return its function-symbol vector (or NIL)."
  (let ((info (parse-elf path)))
    (and info (elf-info-symbols info))))

(defun merge-symbols (a b)
  "Merge two sorted symbol vectors into one. Duplicates (same VADDR)
   prefer A. Both inputs may be empty."
  (let ((out (make-array (+ (length a) (length b))
                         :fill-pointer 0 :adjustable t))
        (seen (make-hash-table :test 'eql)))
    (loop for v across a
          do (vector-push-extend v out)
             (setf (gethash (aref v 0) seen) t))
    (loop for v across b
          unless (gethash (aref v 0) seen)
            do (vector-push-extend v out))
    (sort out #'< :key (lambda (e) (aref e 0)))))

(defun parse-elf (path)
  "Read PATH, parse ELF header + section headers, extract function
   symbols. Tries `.symtab' first (full table, only present in
   unstripped binaries) then `.dynsym' (exports), then falls back to
   the separate debug file via build-id or .gnu_debuglink.

   Returns an ELF-INFO, or NIL if the file isn't a readable ELF64
   we understand."
  (let ((buf (read-file-bytes path)))
    (when (and buf (valid-elf64-p buf))
      (let ((e-type (u16 buf 16)))
        (multiple-value-bind (secs shstrtab) (read-section-headers buf)
          (let (symtab-sec dynsym-sec)
            (loop for sec across secs
                  when (= (section-type sec) +sht-symtab+) do (setf symtab-sec sec)
                  when (= (section-type sec) +sht-dynsym+) do (setf dynsym-sec sec))
            (let* ((sym-sec (or symtab-sec dynsym-sec))
                   (str-sec (and sym-sec (aref secs (section-link sym-sec))))
                   (own-syms (and sym-sec
                                  (parse-symbol-table buf sym-sec str-sec)))
                   ;; If there's no .symtab in this file, try fetching one
                   ;; from a separate debug file. Merge with whatever we
                   ;; got from .dynsym (which has exports only).
                   (debug-syms
                     (unless symtab-sec
                       (let* ((build-id (read-build-id buf secs shstrtab))
                              (link     (read-debuglink buf secs shstrtab))
                              (dbg-path (find-debug-file path build-id link)))
                         (when dbg-path
                           (parse-elf-symbols-from dbg-path)))))
                   (syms (if debug-syms
                             (merge-symbols (or own-syms #()) debug-syms)
                             (or own-syms #()))))
              (make-elf-info :path path
                             :pie-p (= e-type +et-dyn+)
                             :symbols syms))))))))

(defun elf-find-symbol (elf-info vaddr)
  "Binary search ELF-INFO's symbol vector for the entry whose
   [vaddr, vaddr+size) range contains VADDR. Returns the entry
   #(VADDR SIZE NAME) or NIL."
  (let* ((syms (elf-info-symbols elf-info))
         (lo 0)
         (hi (length syms)))
    (loop while (< lo hi)
          do (let* ((mid (floor (+ lo hi) 2))
                    (e   (aref syms mid))
                    (start (aref e 0))
                    (end   (+ start (aref e 1))))
               (cond
                 ((< vaddr start) (setf hi mid))
                 ((>= vaddr end)  (setf lo (1+ mid)))
                 (t (return-from elf-find-symbol e)))))
    nil))
