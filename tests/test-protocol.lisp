(in-package #:whistler/tests)

(in-suite protocol-suite)

;;; ========== Protocol header field access ==========

(test eth-type-access
  "eth-type should emit a load + byte swap (network order)"
  (let ((bytes (w-body "(let ((data u64 (ctx-load u32 0))
                              (data-end u64 (ctx-load u32 4)))
                          (when (> (+ data 14) data-end)
                            (return 2))
                          (return (eth-type data)))")))
    ;; eth-type is u16 at offset 12 with net-order → load + ntohs
    (is (has-opcode-p bytes +ldxh+)
        "Expected ldxh for u16 eth-type load")))

(test ipv4-protocol-access
  "ipv4-protocol should emit a u8 load (no byte swap)"
  (let ((bytes (w-body "(let ((data u64 (ctx-load u32 0))
                              (data-end u64 (ctx-load u32 4)))
                          (when (> (+ data 34) data-end)
                            (return 2))
                          (let ((ip u64 (+ data 14)))
                            (return (ipv4-protocol ip))))")))
    (is (has-opcode-p bytes +ldxb+)
        "Expected ldxb for u8 ipv4-protocol")))

(test tcp-flags-access
  "tcp-flags should emit a u8 load"
  (let ((bytes (w-body "(let ((data u64 (ctx-load u32 0))
                              (data-end u64 (ctx-load u32 4)))
                          (when (> (+ data 54) data-end)
                            (return 2))
                          (let ((tcp u64 (+ data 34)))
                            (return (tcp-flags tcp))))")))
    (is (has-opcode-p bytes +ldxb+)
        "Expected ldxb for u8 tcp-flags")))

(test tcp-dst-port-access
  "tcp-dst-port should emit u16 load + byte swap (network order)"
  (let ((bytes (w-body "(let ((data u64 (ctx-load u32 0))
                              (data-end u64 (ctx-load u32 4)))
                          (when (> (+ data 54) data-end)
                            (return 2))
                          (let ((tcp u64 (+ data 34)))
                            (return (tcp-dst-port tcp))))")))
    (is (has-opcode-p bytes +ldxh+)
        "Expected ldxh for u16 tcp-dst-port")))

;;; ========== Packet parsing macros ==========

(test with-eth-compiles
  "with-eth should compile with bounds check"
  (let ((n (w-count "(with-eth (data data-end)
                       (return (eth-type data)))
                     (return 2)")))
    ;; ctx-load × 2 + bounds check + load + bswap + returns
    (is (> n 5) "with-eth should produce multiple instructions")))

(test with-tcp-compiles
  "with-tcp should compile with full protocol chain"
  (let ((n (w-count "(with-tcp (data data-end tcp)
                       (return (tcp-flags tcp)))
                     (return 2)")))
    ;; Bounds + ethertype check + protocol check + tcp access
    (is (> n 10) "with-tcp should produce many instructions")))

(test with-udp-compiles
  "with-udp should compile with full protocol chain"
  (let ((n (w-count "(with-udp (data data-end udp)
                       (return (udp-dst-port udp)))
                     (return 2)")))
    (is (> n 10) "with-udp should produce many instructions")))

(test parse-eth-compiles
  "parse-eth should compile to bounds check returning pointer or 0"
  (let ((n (w-count "(let ((data u64 (ctx-load u32 0))
                           (data-end u64 (ctx-load u32 4)))
                       (let ((eth u64 (parse-eth data data-end)))
                         (if eth (return 1) (return 0))))")))
    (is (> n 4) "parse-eth should produce bounds check")))

(test parse-tcp-compiles
  "parse-tcp should compile full protocol chain"
  (let ((n (w-count "(let ((data u64 (ctx-load u32 0))
                           (data-end u64 (ctx-load u32 4)))
                       (let ((tcp u64 (parse-tcp data data-end)))
                         (if tcp (return 1) (return 0))))")))
    (is (> n 8) "parse-tcp should produce protocol chain checks")))

;;; ========== Full example programs ==========

(test drop-port-example-compiles
  "The drop-port example should compile without error"
  (let ((whistler::*maps* nil)
        (whistler::*programs* nil)
        (whistler::*struct-defs* (make-hash-table :test 'equal)))
    (finishes
      (load (merge-pathnames "examples/drop-port.lisp"
                             (asdf:system-source-directory :whistler))))))

(test ratelimit-example-compiles
  "The ratelimit-xdp example should compile without error"
  (let ((whistler::*maps* nil)
        (whistler::*programs* nil)
        (whistler::*struct-defs* (make-hash-table :test 'equal)))
    (finishes
      (load (merge-pathnames "examples/ratelimit-xdp.lisp"
                             (asdf:system-source-directory :whistler))))))
