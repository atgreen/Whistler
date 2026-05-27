;;; symbolize.lisp — public lookup API
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; (symbolize SYMB PID IP) is the only function callers reach for.
;;; It returns a SYM struct with the best-effort name resolution:
;;;
;;;     1. Check /tmp/perf-PID.map first  (covers JIT'd code that has
;;;        no ELF backing — V8, .NET, etc.).
;;;     2. Find the executable mapping covering IP in /proc/PID/maps.
;;;     3. Open the mapping's file (cached), translate IP to a
;;;        symbol-table virtual address, look it up.
;;;
;;; When the file is PIE / .so (`ET_DYN'), symbols are recorded
;;; relative to the library's load base. Per the ELF program-header
;;; convention, the load base for a mapping with file-offset FOFF and
;;; segment virtual address VADDR is `MAPPING-START - (VADDR - FOFF)'.
;;; For our purposes — looking up an address inside a single
;;; executable PT_LOAD — `MAPPING-START - MAPPING-OFFSET' approximates
;;; this since the program header's vaddr usually equals its file
;;; offset for that segment, modulo page padding.

(in-package #:whistler/symbolize)

(defstruct sym
  addr           ; original input IP (always set)
  name           ; symbol name string  or NIL when unresolved
  offset         ; bytes past the start of the symbol; 0 when unresolved
  file)          ; "/usr/lib64/libc.so.6"  or NIL

(defun symbolize (symb pid ip)
  "Resolve IP (a u64 virtual address in process PID) to a SYM struct.
   Always returns a SYM — fields are NIL/0 when nothing matches."
  (let* ((data     (pid-data symb pid))
         (maps     (car data))
         (perf-map (cdr data)))
    (or
     ;; (1) JIT overlay — highest priority. JIT'd code typically lives
     ;; in anon executable mappings that have no file to symbolise.
     (let ((entry (find-perf-map-entry perf-map ip)))
       (when entry
         (make-sym :addr ip
                   :name (aref entry 2)
                   :offset (- ip (aref entry 0))
                   :file "<jit>")))
     ;; (2) Mapped file — find segment, translate IP, look up symbol.
     (let ((m (find-mapping maps ip)))
       (cond
         ((null m) (make-sym :addr ip))
         (t
          (let ((elf (cached-elf symb (mapping-path m))))
            (cond
              ((null elf)
               (make-sym :addr ip :file (mapping-path m)))
              (t
               (let* ((vaddr (if (elf-info-pie-p elf)
                                 ;; Translate runtime IP back into the
                                 ;; symbol's recorded vaddr, accounting
                                 ;; for the segment's file offset.
                                 (- ip
                                    (mapping-start m)
                                    (- 0 (mapping-offset m)))
                                 ip))
                      (entry (elf-find-symbol elf vaddr)))
                 (cond
                   (entry
                    (make-sym :addr ip
                              :name (aref entry 2)
                              :offset (- vaddr (aref entry 0))
                              :file (mapping-path m)))
                   (t
                    (make-sym :addr ip :file (mapping-path m))))))))))))))
