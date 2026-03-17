;;; -*- Mode: Lisp -*-
;;;
;;; Copyright (c) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; SPDX-License-Identifier: MIT

(in-package #:whistler/bpf)

;;; eBPF constants

;; Registers
(defconstant +bpf-reg-0+  0)
(defconstant +bpf-reg-1+  1)
(defconstant +bpf-reg-2+  2)
(defconstant +bpf-reg-3+  3)
(defconstant +bpf-reg-4+  4)
(defconstant +bpf-reg-5+  5)
(defconstant +bpf-reg-6+  6)
(defconstant +bpf-reg-7+  7)
(defconstant +bpf-reg-8+  8)
(defconstant +bpf-reg-9+  9)
(defconstant +bpf-reg-10+ 10)

;; Instruction classes
(defconstant +bpf-ld+    #x00)
(defconstant +bpf-ldx+   #x01)
(defconstant +bpf-st+    #x02)
(defconstant +bpf-stx+   #x03)
(defconstant +bpf-alu+   #x04)
(defconstant +bpf-jmp+   #x05)
(defconstant +bpf-alu64+ #x07)

;; Source
(defconstant +bpf-k+ #x00)
(defconstant +bpf-x+ #x08)

;; ALU operations
(defconstant +bpf-add+  #x00)
(defconstant +bpf-sub+  #x10)
(defconstant +bpf-mul+  #x20)
(defconstant +bpf-div+  #x30)
(defconstant +bpf-or+   #x40)
(defconstant +bpf-and+  #x50)
(defconstant +bpf-lsh+  #x60)
(defconstant +bpf-rsh+  #x70)
(defconstant +bpf-neg+  #x80)
(defconstant +bpf-mod+  #x90)
(defconstant +bpf-xor+  #xa0)
(defconstant +bpf-mov+  #xb0)
(defconstant +bpf-arsh+ #xc0)

;; Jump operations
(defconstant +bpf-ja+   #x00)
(defconstant +bpf-jeq+  #x10)
(defconstant +bpf-jgt+  #x20)
(defconstant +bpf-jge+  #x30)
(defconstant +bpf-jset+ #x40)
(defconstant +bpf-jne+  #x50)
(defconstant +bpf-jsgt+ #x60)
(defconstant +bpf-jsge+ #x70)
(defconstant +bpf-jlt+  #xa0)
(defconstant +bpf-jle+  #xb0)
(defconstant +bpf-jslt+ #xc0)
(defconstant +bpf-jsle+ #xd0)

;; Memory sizes
(defconstant +bpf-w+  #x00)  ; 32-bit
(defconstant +bpf-h+  #x08)  ; 16-bit
(defconstant +bpf-b+  #x10)  ; 8-bit
(defconstant +bpf-dw+ #x18)  ; 64-bit

;; Memory modes
(defconstant +bpf-imm+    #x00)
(defconstant +bpf-mem+    #x60)
(defconstant +bpf-atomic+ #xc0)

;; Special
(defconstant +bpf-call+ #x80)
(defconstant +bpf-exit+ #x90)

;; Pseudo source for 64-bit imm
(defconstant +bpf-pseudo-map-fd+ 1)

;; Map types
(defconstant +bpf-map-type-hash+          1)
(defconstant +bpf-map-type-array+         2)
(defconstant +bpf-map-type-percpu-hash+   5)
(defconstant +bpf-map-type-percpu-array+  6)
(defconstant +bpf-map-type-prog-array+    3)
(defconstant +bpf-map-type-lpm-trie+      11)
(defconstant +bpf-map-type-ringbuf+       27)

;; Map flags
(defconstant +bpf-f-no-prealloc+ 1)

;; Helper function IDs
(defconstant +bpf-func-map-lookup-elem+      1)
(defconstant +bpf-func-map-update-elem+      2)
(defconstant +bpf-func-map-delete-elem+      3)
(defconstant +bpf-func-ktime-get-ns+         5)
(defconstant +bpf-func-trace-printk+         6)
(defconstant +bpf-func-get-prandom-u32+      7)
(defconstant +bpf-func-get-smp-processor-id+ 8)
(defconstant +bpf-func-redirect+             23)
(defconstant +bpf-func-map-lookup-and-delete-elem+ 46)

;; XDP return codes
(defconstant +xdp-aborted+  0)
(defconstant +xdp-drop+     1)
(defconstant +xdp-pass+     2)
(defconstant +xdp-tx+       3)
(defconstant +xdp-redirect+ 4)

;;; eBPF instruction representation

(defstruct bpf-insn
  (code 0 :type (unsigned-byte 8))
  (dst  0 :type (unsigned-byte 4))
  (src  0 :type (unsigned-byte 4))
  (off  0 :type integer)
  (imm  0 :type integer))

(defun insn (code dst src off imm)
  (make-bpf-insn :code code :dst dst :src src :off off :imm imm))

;;; Instruction constructors

(defun emit-alu64-reg (op dst src)
  (list (insn (logior +bpf-alu64+ +bpf-x+ op) dst src 0 0)))

(defun emit-alu64-imm (op dst imm)
  (list (insn (logior +bpf-alu64+ +bpf-k+ op) dst 0 0 imm)))

(defun emit-alu32-reg (op dst src)
  (list (insn (logior +bpf-alu+ +bpf-x+ op) dst src 0 0)))

(defun emit-alu32-imm (op dst imm)
  (list (insn (logior +bpf-alu+ +bpf-k+ op) dst 0 0 imm)))

(defun emit-mov64-reg (dst src)
  (emit-alu64-reg +bpf-mov+ dst src))

(defun emit-mov64-imm (dst imm)
  (emit-alu64-imm +bpf-mov+ dst imm))

(defun emit-mov32-imm (dst imm)
  (emit-alu32-imm +bpf-mov+ dst imm))

(defun emit-ldx-mem (size dst src off)
  (list (insn (logior +bpf-ldx+ +bpf-mem+ size) dst src off 0)))

(defun emit-stx-mem (size dst src off)
  (list (insn (logior +bpf-stx+ +bpf-mem+ size) dst src off 0)))

(defun emit-st-mem (size dst off imm)
  (list (insn (logior +bpf-st+ +bpf-mem+ size) dst 0 off imm)))

(defun emit-stx-atomic (size dst src off op)
  (list (insn (logior +bpf-stx+ +bpf-atomic+ size) dst src off op)))

(defun emit-jmp-reg (op dst src off)
  (list (insn (logior +bpf-jmp+ +bpf-x+ op) dst src off 0)))

(defun emit-jmp-imm (op dst imm off)
  (list (insn (logior +bpf-jmp+ +bpf-k+ op) dst 0 off imm)))

(defun emit-jmp-a (off)
  (list (insn (logior +bpf-jmp+ +bpf-ja+) 0 0 off 0)))

(defun emit-call (func-id)
  (list (insn (logior +bpf-jmp+ +bpf-call+) 0 0 0 func-id)))

(defun emit-exit ()
  (list (insn (logior +bpf-jmp+ +bpf-exit+) 0 0 0 0)))

;; Byte-swap (endian conversion) instructions
;; BPF_ALU | BPF_END | BPF_SRC, imm = bit width
(defconstant +bpf-end+  #xd0)
(defconstant +bpf-to-le+ #x00)  ; to little-endian (no-op on LE host)
(defconstant +bpf-to-be+ #x08)  ; to big-endian

(defun emit-bswap16 (dst)
  "Byte-swap 16-bit value in DST (for ntohs/htons)."
  (list (insn (logior +bpf-alu+ +bpf-end+ +bpf-to-be+) dst 0 0 16)))

(defun emit-bswap32 (dst)
  "Byte-swap 32-bit value in DST (for ntohl/htonl)."
  (list (insn (logior +bpf-alu+ +bpf-end+ +bpf-to-be+) dst 0 0 32)))

(defun emit-bswap64 (dst)
  "Byte-swap 64-bit value in DST."
  (list (insn (logior +bpf-alu+ +bpf-end+ +bpf-to-be+) dst 0 0 64)))

(defun emit-ld-imm64 (dst imm)
  "Emit a 64-bit immediate load (2 instructions)."
  (list (insn (logior +bpf-ld+ +bpf-dw+ +bpf-imm+) dst 0 0
              (logand imm #xffffffff))
        (insn 0 0 0 0
              (logand (ash imm -32) #xffffffff))))

(defun emit-ld-map-fd (dst fd)
  "Emit a 64-bit load with pseudo map fd source."
  (list (insn (logior +bpf-ld+ +bpf-dw+ +bpf-imm+) dst +bpf-pseudo-map-fd+ 0
              (logand fd #xffffffff))
        (insn 0 0 0 0
              (logand (ash fd -32) #xffffffff))))

;;; Encoding to bytes

(defun u8 (val)
  (logand val #xff))

(defun s16-to-u16 (val)
  (logand val #xffff))

(defun s32-to-u32 (val)
  (logand val #xffffffff))

(defun encode-insn (insn)
  "Encode a bpf-insn to an 8-byte vector (little-endian)."
  (let ((bytes (make-array 8 :element-type '(unsigned-byte 8))))
    (setf (aref bytes 0) (u8 (bpf-insn-code insn)))
    ;; dst_reg is low nibble, src_reg is high nibble
    (setf (aref bytes 1) (logior (logand (bpf-insn-dst insn) #xf)
                                 (ash (logand (bpf-insn-src insn) #xf) 4)))
    (let ((off (s16-to-u16 (bpf-insn-off insn))))
      (setf (aref bytes 2) (logand off #xff))
      (setf (aref bytes 3) (ash off -8)))
    (let ((imm (s32-to-u32 (bpf-insn-imm insn))))
      (setf (aref bytes 4) (logand imm #xff))
      (setf (aref bytes 5) (logand (ash imm -8) #xff))
      (setf (aref bytes 6) (logand (ash imm -16) #xff))
      (setf (aref bytes 7) (logand (ash imm -24) #xff)))
    bytes))

(defun insn-bytes (insns)
  "Encode a list of bpf-insn structs to a flat byte vector."
  (let* ((n (length insns))
         (bytes (make-array (* n 8) :element-type '(unsigned-byte 8))))
    (loop for insn in insns
          for i from 0
          for encoded = (encode-insn insn)
          do (replace bytes encoded :start1 (* i 8)))
    bytes))
