;;; binary.lisp — shared binary-format constants and byte-IO helpers
;;;
;;; Copyright (c) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Single home for the ELF/BTF constants and little-endian byte
;;; helpers shared by the ELF writer (whistler/elf), the BTF reader
;;; (vmlinux import), the loader (whistler/loader), and the symbolizer
;;; (whistler/symbolize).

(defpackage #:whistler/binary
  (:use #:cl)
  (:export
   ;; Little-endian buffer readers
   #:u8 #:u16 #:u32 #:u64
   ;; Little-endian stream writers
   #:write-u8 #:write-u16le #:write-u32le #:write-u64le
   ;; ELF identification / header
   #:+elf-magic+ #:+elfclass64+ #:+elfdata2lsb+ #:+ev-current+
   #:+elfosabi-none+ #:+et-rel+ #:+et-exec+ #:+et-dyn+ #:+em-bpf+
   ;; Section types / flags
   #:+sht-null+ #:+sht-progbits+ #:+sht-symtab+ #:+sht-strtab+
   #:+sht-note+ #:+sht-rel+ #:+sht-dynsym+
   #:+shf-alloc+ #:+shf-execinstr+
   ;; Symbol table
   #:+stt-notype+ #:+stt-object+ #:+stt-func+ #:+stt-section+
   #:+stb-local+ #:+stb-global+ #:+shn-undef+
   ;; Notes
   #:+nt-gnu-build-id+
   ;; BPF relocation types
   #:+r-bpf-64-64+ #:+r-bpf-64-32+
   ;; BTF
   #:+btf-magic+
   #:+btf-kind-int+ #:+btf-kind-ptr+ #:+btf-kind-array+ #:+btf-kind-struct+
   #:+btf-kind-union+ #:+btf-kind-enum+ #:+btf-kind-fwd+ #:+btf-kind-typedef+
   #:+btf-kind-volatile+ #:+btf-kind-const+ #:+btf-kind-restrict+
   #:+btf-kind-func+ #:+btf-kind-func-proto+ #:+btf-kind-var+
   #:+btf-kind-datasec+ #:+btf-kind-float+ #:+btf-kind-enum64+))

(in-package #:whistler/binary)

;;; ========== ELF constants ==========

(defconstant +elf-magic+    #x464c457f)  ; "\x7fELF" read as LE u32
(defconstant +elfclass64+   2)
(defconstant +elfdata2lsb+  1)
(defconstant +ev-current+   1)
(defconstant +elfosabi-none+ 0)
(defconstant +et-rel+       1)    ; relocatable
(defconstant +et-exec+      2)
(defconstant +et-dyn+       3)    ; PIE / .so
(defconstant +em-bpf+       247)  ; eBPF

(defconstant +sht-null+     0)
(defconstant +sht-progbits+ 1)
(defconstant +sht-symtab+   2)
(defconstant +sht-strtab+   3)
(defconstant +sht-note+     7)
(defconstant +sht-rel+      9)
(defconstant +sht-dynsym+   11)
(defconstant +shf-alloc+    #x2)
(defconstant +shf-execinstr+ #x4)

(defconstant +stt-notype+   0)
(defconstant +stt-object+   1)
(defconstant +stt-func+     2)
(defconstant +stt-section+  3)
(defconstant +stb-local+    0)
(defconstant +stb-global+   1)
(defconstant +shn-undef+    0)

(defconstant +nt-gnu-build-id+ 3)

;; BPF relocation types (r_info low 32 bits)
(defconstant +r-bpf-64-64+  1)   ; map fd on ld_imm64
(defconstant +r-bpf-64-32+  10)  ; call imm (kfunc btf-id)

;;; ========== BTF constants ==========

(defconstant +btf-magic+ #xeB9F)

;; BTF type kinds (stored in bits 24-28 of the info field)
(defconstant +btf-kind-int+        1)
(defconstant +btf-kind-ptr+        2)
(defconstant +btf-kind-array+      3)
(defconstant +btf-kind-struct+     4)
(defconstant +btf-kind-union+      5)
(defconstant +btf-kind-enum+       6)
(defconstant +btf-kind-fwd+        7)
(defconstant +btf-kind-typedef+    8)
(defconstant +btf-kind-volatile+   9)
(defconstant +btf-kind-const+     10)
(defconstant +btf-kind-restrict+  11)
(defconstant +btf-kind-func+      12)
(defconstant +btf-kind-func-proto+ 13)
(defconstant +btf-kind-var+       14)
(defconstant +btf-kind-datasec+   15)
(defconstant +btf-kind-float+     16)
(defconstant +btf-kind-enum64+    19)

;;; ========== Little-endian buffer readers ==========

(declaim (inline u8 u16 u32 u64))

(defun u8 (buf off)
  (aref buf off))

(defun u16 (buf off)
  (logior (aref buf off)
          (ash (aref buf (+ off 1)) 8)))

(defun u32 (buf off)
  (logior (aref buf off)
          (ash (aref buf (+ off 1)) 8)
          (ash (aref buf (+ off 2)) 16)
          (ash (aref buf (+ off 3)) 24)))

(defun u64 (buf off)
  (logior (u32 buf off) (ash (u32 buf (+ off 4)) 32)))

;;; ========== Little-endian stream writers ==========

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
