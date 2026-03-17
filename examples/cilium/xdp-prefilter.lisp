;;; Cilium-style XDP CIDR source IP prefilter
;;;
;;; Reimplements the prefilter logic from Cilium's bpf_xdp.c:
;;; Drops packets whose source IPv4 address matches a blocklist
;;; stored in an LPM trie (dynamic prefixes) or a hash map (fixed prefixes).
;;;
;;; The LPM trie key is 8 bytes: prefixlen (u32) + IPv4 addr (u32).
;;; BPF_F_NO_PREALLOC (1) is required for LPM trie maps.

(in-package #:whistler)

;;; Maps

;; Dynamic CIDR blocklist — LPM trie for prefix matching
;; Key: 8 bytes (prefixlen u32 + addr u32), Value: 1 byte flags
(defmap cidr-v4-dyn
  :type :lpm-trie
  :key-size 8
  :value-size 1
  :max-entries 1024
  :map-flags 1)   ; BPF_F_NO_PREALLOC

;; Fixed CIDR blocklist — hash map for exact /32 or known-prefix lookups
;; Key: 8 bytes (prefixlen u32 + addr u32), Value: 1 byte flags
(defmap cidr-v4-fix
  :type :hash
  :key-size 8
  :value-size 1
  :max-entries 1024)

;;; Program

(defprog xdp-prefilter (:type :xdp :section "xdp" :license "GPL")
  (let ((data     (xdp-data))
        (data-end (xdp-data-end)))
    ;; Bounds check: need at least Ethernet + IPv4 headers
    (when (> (+ data 34) data-end)              ; 14 + 20 = 34
      (return XDP_PASS))
    ;; Check EtherType is IPv4
    (when (/= (eth-type data) +ethertype-ipv4+)
      (return XDP_PASS))
    ;; Extract source IPv4 address (network byte order, raw 32-bit)
    (let ((src-addr (ipv4-src-addr (+ data +eth-hdr-len+))))
      ;; Build LPM key on stack: 8 bytes = [u32 prefixlen] [u32 addr]
      (let ((key-buf 0))
        (store u32 (stack-addr key-buf) 0 32)
        (store u32 (stack-addr key-buf) 4 src-addr)
        ;; Lookup in dynamic LPM trie — drop if found
        (when (map-lookup cidr-v4-dyn key-buf)
          (return XDP_DROP))
        ;; Lookup in fixed hash map — drop if found
        (when (map-lookup cidr-v4-fix key-buf)
          (return XDP_DROP)))))
  XDP_PASS)
