(in-package #:whistler/tests)

(in-suite byteswap-suite)

;;; Adapted from LLVM test/CodeGen/BPF/bswap.ll
;;; BPF byte swap uses dedicated endian instructions.

;; BPF bswap opcodes: dc (LE bswap) with imm = bit width
(defconstant +bpf-bswap+ #xdc)

(test ntohs-compiles
  "ntohs (16-bit byte swap) should compile"
  (let ((bytes (w-body "(let ((x u16 (ctx-load u16 0)))
                          (return (ntohs x)))")))
    (is (has-opcode-p bytes +bpf-bswap+)
        "Expected byte swap instruction for ntohs")))

(test htons-compiles
  "htons should compile identically to ntohs"
  (let ((bytes (w-body "(let ((x u16 (ctx-load u16 0)))
                          (return (htons x)))")))
    (is (has-opcode-p bytes +bpf-bswap+)
        "Expected byte swap instruction for htons")))

(test ntohl-compiles
  "ntohl (32-bit byte swap) should compile"
  (let ((bytes (w-body "(let ((x u32 (ctx-load u32 0)))
                          (return (ntohl x)))")))
    (is (has-opcode-p bytes +bpf-bswap+)
        "Expected byte swap instruction for ntohl")))

(test htonl-compiles
  "htonl should compile identically to ntohl"
  (let ((bytes (w-body "(let ((x u32 (ctx-load u32 0)))
                          (return (htonl x)))")))
    (is (has-opcode-p bytes +bpf-bswap+)
        "Expected byte swap instruction for htonl")))

(test ntohll-compiles
  "ntohll (64-bit byte swap) should compile"
  (let ((bytes (w-body "(let ((x u64 (ctx-load u64 0)))
                          (return (ntohll x)))")))
    (is (has-opcode-p bytes +bpf-bswap+)
        "Expected byte swap instruction for ntohll")))

(test htonll-compiles
  "htonll should compile identically to ntohll"
  (let ((bytes (w-body "(let ((x u64 (ctx-load u64 0)))
                          (return (htonll x)))")))
    (is (has-opcode-p bytes +bpf-bswap+)
        "Expected byte swap instruction for htonll")))
