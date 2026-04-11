;;; -*- Mode: Lisp -*-
;;;
;;; Copyright (c) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; SPDX-License-Identifier: MIT

(defpackage #:whistler/bpf
  (:use #:cl)
  (:export
   ;; Instruction constructors
   #:insn #:emit-alu64-reg #:emit-alu64-imm #:emit-alu32-reg #:emit-alu32-imm
   #:emit-mov64-reg #:emit-mov64-imm #:emit-mov32-imm
   #:emit-ldx-mem #:emit-stx-mem #:emit-st-mem
   #:emit-stx-atomic
   #:emit-jmp-reg #:emit-jmp-imm #:emit-jmp-a
   #:emit-call #:emit-exit
   #:emit-ld-imm64 #:emit-ld-map-fd
   ;; Constants
   #:+bpf-reg-0+ #:+bpf-reg-1+ #:+bpf-reg-2+ #:+bpf-reg-3+ #:+bpf-reg-4+
   #:+bpf-reg-5+ #:+bpf-reg-6+ #:+bpf-reg-7+ #:+bpf-reg-8+ #:+bpf-reg-9+
   #:+bpf-reg-10+
   ;; ALU ops
   #:+bpf-add+ #:+bpf-sub+ #:+bpf-mul+ #:+bpf-div+ #:+bpf-or+ #:+bpf-and+
   #:+bpf-lsh+ #:+bpf-rsh+ #:+bpf-neg+ #:+bpf-mod+ #:+bpf-xor+ #:+bpf-mov+
   #:+bpf-arsh+
   ;; Jump ops
   #:+bpf-jeq+ #:+bpf-jgt+ #:+bpf-jge+ #:+bpf-jset+ #:+bpf-jne+
   #:+bpf-jsgt+ #:+bpf-jsge+ #:+bpf-jlt+ #:+bpf-jle+ #:+bpf-jslt+ #:+bpf-jsle+
   ;; Instruction classes
   #:+bpf-ld+ #:+bpf-ldx+ #:+bpf-st+ #:+bpf-stx+
   #:+bpf-alu+ #:+bpf-jmp+ #:+bpf-alu64+
   ;; Source
   #:+bpf-k+ #:+bpf-x+
   ;; Special
   #:+bpf-call+ #:+bpf-exit+
   ;; Memory modes
   #:+bpf-imm+ #:+bpf-mem+ #:+bpf-atomic+
   ;; Sizes
   #:+bpf-w+ #:+bpf-h+ #:+bpf-b+ #:+bpf-dw+
   ;; Map types
   #:+bpf-map-type-hash+ #:+bpf-map-type-lru-hash+ #:+bpf-map-type-array+
   #:+bpf-map-type-prog-array+
   #:+bpf-map-type-lpm-trie+
   #:+bpf-map-type-percpu-hash+ #:+bpf-map-type-percpu-array+
   #:+bpf-map-type-ringbuf+
   ;; Map flags
   #:+bpf-f-no-prealloc+
   ;; Helper function IDs
   #:+bpf-func-map-lookup-elem+ #:+bpf-func-map-update-elem+
   #:+bpf-func-map-delete-elem+ #:+bpf-func-ktime-get-ns+
   #:+bpf-func-trace-printk+ #:+bpf-func-get-prandom-u32+
   #:+bpf-func-get-smp-processor-id+
   #:+bpf-func-redirect+ #:+bpf-func-map-lookup-and-delete-elem+
   ;; XDP return codes
   #:+xdp-aborted+ #:+xdp-drop+ #:+xdp-pass+ #:+xdp-tx+ #:+xdp-redirect+
   ;; Instruction struct
   #:bpf-insn #:bpf-insn-code #:bpf-insn-dst #:bpf-insn-src
   #:bpf-insn-off #:bpf-insn-imm
   ;; Byte-swap
   #:emit-bswap16 #:emit-bswap32 #:emit-bswap64
   #:encode-insn #:insn-bytes))

(defpackage #:whistler/elf
  (:use #:cl)
  (:export #:write-bpf-elf))

(defpackage #:whistler/btf
  (:use #:cl)
  (:export #:generate-btf #:generate-btf-and-ext))

(defpackage #:whistler/compiler
  (:use #:cl #:whistler/bpf)
  (:export #:whistler-error #:*helper-arg-counts*
           #:make-compilation-unit #:cu-insns #:cu-maps
           #:cu-section #:cu-name #:cu-license #:cu-map-relocs #:cu-core-relocs
           #:whistler-macroexpand #:constant-fold-sexpr #:resolve-map-type
           #:bpf-map #:bpf-map-name #:bpf-map-type #:bpf-map-key-size
           #:bpf-map-value-size #:bpf-map-max-entries #:bpf-map-flags #:bpf-map-index
           #:make-bpf-map
           #:sym= #:bpf-type-p #:bpf-type-size #:builtin-helper-p
           #:*builtin-helpers* #:*builtin-constants* #:*whistler-builtins*))

(defpackage #:whistler/ir
  (:use #:cl)
  (:export #:ir-insn #:make-ir-insn #:ir-insn-op #:ir-insn-dst #:ir-insn-args
           #:ir-insn-type #:ir-insn-id
           #:basic-block #:make-basic-block #:basic-block-label #:basic-block-insns
           #:basic-block-succs #:basic-block-preds
           #:ir-program #:make-ir-program #:ir-program-blocks #:ir-program-entry
           #:ir-program-next-vreg #:ir-program-maps #:ir-program-map-relocs
           #:ir-program-section #:ir-program-license
           #:ir-fresh-vreg #:ir-fresh-label #:ir-find-block #:ir-add-block
           #:bb-emit #:bb-terminator-p
           #:ir-insn-vreg-uses #:ir-insn-side-effect-p #:ir-insn-all-vreg-uses
           #:call-like-op-p #:helper-effects #:helper-invalidates-p #:ir-dump
           ;; Lowering
           #:lower-program
           ;; Optimization
           #:copy-propagation #:dead-code-elimination #:sccp #:optimize-ir
           ;; Register allocation
           #:linear-scan-alloc #:compute-liveness
           ;; Emission
           #:emit-ir-to-bpf
           ;; Peephole
           #:peephole-optimize))

(defpackage #:whistler
  (:use #:cl #:whistler/bpf #:whistler/compiler #:whistler/elf #:whistler/btf)
  (:shadow #:case #:defstruct #:incf #:decf)
  (:export #:compile-file* #:defmap #:defprog #:compile-to-elf #:main
           #:reset-compilation-state
           ;; Surface language macros
           #:when-let #:if-let #:case
           #:incf #:decf
           #:incf-map #:getmap #:setmap #:delmap #:remmap
           #:parse-eth #:parse-ipv4 #:parse-tcp #:parse-udp
           #:xdp-data #:xdp-data-end
           ;; Protocol macros
           #:defheader #:with-packet #:with-eth #:with-ipv4 #:with-tcp #:with-udp
           ;; Ethernet
           #:eth-type #:eth-dst-mac-hi #:eth-dst-mac-lo
           #:eth-src-mac-hi #:eth-src-mac-lo
           #:+ethertype-ipv4+ #:+ethertype-ipv6+ #:+ethertype-arp+ #:+eth-hdr-len+
           ;; IPv4
           #:ipv4-src-addr #:ipv4-dst-addr #:ipv4-protocol #:ipv4-ttl
           #:ipv4-total-len #:ipv4-ver-ihl #:ipv4-tos
           #:+ipv4-hdr-len+ #:+ip-proto-tcp+ #:+ip-proto-udp+ #:+ip-proto-icmp+
           #:+ip-proto-ipv6-icmp+
           ;; IPv6
           #:ipv6-ver-tc-flow #:ipv6-payload-len #:ipv6-nexthdr #:ipv6-hop-limit
           #:ipv6-src-addr-hi #:ipv6-src-addr-lo
           #:ipv6-dst-addr-hi #:ipv6-dst-addr-lo
           #:+ipv6-hdr-len+
           ;; ICMP
           #:icmp-type #:icmp-code #:icmp-checksum #:icmp-rest
           #:+icmp-hdr-len+
           ;; TCP
           #:tcp-src-port #:tcp-dst-port #:tcp-flags #:tcp-seq #:tcp-ack-seq
           #:+tcp-hdr-len+ #:+tcp-syn+ #:+tcp-ack+ #:+tcp-fin+ #:+tcp-rst+
           ;; UDP
           #:udp-src-port #:udp-dst-port #:udp-length
           #:+udp-hdr-len+
           ;; Structs
           #:defstruct #:struct-set #:struct-ref #:sizeof
           ;; Kernel integration
           #:deftracepoint #:import-kernel-struct
           ;; Memory operations
           #:memset #:memcpy
           ;; User-space iteration
           #:do-user-ptrs #:do-user-array
           ;; Ring buffer and process metadata
           #:with-ringbuf #:fill-process-info
           ;; pt_regs access (x86-64)
           #:pt-regs-parm1 #:pt-regs-parm2 #:pt-regs-parm3
           #:pt-regs-parm4 #:pt-regs-parm5 #:pt-regs-parm6
           #:pt-regs-ret
           ;; Safe kernel memory access
           #:kernel-load
           ;; Typed kernel struct pointers
           #:typed-ptr #:strip-typed-ptr #:check-struct-ptr-type))

(defpackage #:whistler-user
  (:use #:cl #:whistler)
  (:shadowing-import-from #:whistler #:incf #:decf #:case #:defstruct))
