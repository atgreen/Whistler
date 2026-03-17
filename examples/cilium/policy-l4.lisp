;;; Cilium-style L3/L4 Policy Enforcement (IPv4)
;;;
;;; Reimplements core policy enforcement from Cilium's lib/policy.h:
;;; Identity-based allowlist for L4 traffic. Each source IP is mapped
;;; to a security identity (u32), then the (identity, dst-port, proto)
;;; tuple is checked against an allow policy map.
;;;
;;; Simplified vs. Cilium: no label-based identity inheritance, no
;;; wildcard entries, no policy audit mode, no proxy redirect, no
;;; identity caching in CT. Just the core lookup chain.
;;;
;;; Flow:
;;; 1. Parse Ethernet + IPv4 + L4 headers
;;; 2. Lookup source IP in identity map → get security identity
;;; 3. Build policy key: (identity, dst-port, proto)
;;; 4. Lookup policy → allow/deny
;;; 5. Unknown identity or no policy → drop

(in-package #:whistler)

;;; Struct definitions

;; Policy lookup key
(defstruct policy-key
  (identity  u32)   ; offset 0  — source security identity
  (dport     u16)   ; offset 4  — destination port (network byte order)
  (proto     u8)    ; offset 6  — IP protocol
  (pad       u8))   ; offset 7  — padding (total: 8 bytes)

;;; Maps

;; IP → identity mapping
;; Key: 4 bytes (IPv4 address, network byte order)
;; Value: 4 bytes (security identity u32)
(defmap ipcache-v4
  :type :hash
  :key-size 4
  :value-size 4
  :max-entries 65536)

;; Policy allowlist
;; Key: policy-key (8 bytes)
;; Value: 4 bytes (flags/action u32: nonzero = allow)
(defmap policy-v4
  :type :hash
  :key-size 8
  :value-size 4
  :max-entries 16384)

;; Statistics
;; Index 0: total evaluated
;; Index 1: allowed
;; Index 2: denied (no identity)
;; Index 3: denied (no policy)
(defmap policy-stats
  :type :array
  :key-size 4
  :value-size 8
  :max-entries 4)

;;; Constants

(defconstant +stat-policy-total+       0)
(defconstant +stat-policy-allowed+     1)
(defconstant +stat-policy-no-identity+ 2)
(defconstant +stat-policy-denied+      3)

;; Reserved identities (like Cilium's WORLD, HOST, etc.)
(defconstant +identity-unknown+ 0)

;;; Program

(defprog policy-enforce (:type :xdp :section "xdp" :license "GPL")
  (let ((data     (xdp-data))
        (data-end (xdp-data-end)))
    ;; Bounds check: Eth + IPv4 + 4 bytes L4 (ports)
    (when (> (+ data 38) data-end)
      (return XDP_PASS))
    ;; IPv4 only; let non-IPv4 through
    (when (/= (eth-type data) +ethertype-ipv4+)
      (return XDP_PASS))
    (let ((ip    (+ data +eth-hdr-len+))
          (proto (ipv4-protocol (+ data +eth-hdr-len+))))
      ;; Only enforce policy on TCP and UDP
      (when (and (/= proto +ip-proto-tcp+) (/= proto +ip-proto-udp+))
        (return XDP_PASS))

      (incf (getmap policy-stats +stat-policy-total+))

      (let ((src-addr (ipv4-src-addr ip))
            (dst-port (load u16 (+ ip +ipv4-hdr-len+) 2)))

        ;; Step 1: Resolve source IP to security identity
        (if-let (id-ptr (map-lookup ipcache-v4 src-addr))
          ;; Known source — check policy
          (let ((identity (load u32 id-ptr 0)))
            ;; Step 2: Check policy for (identity, dst-port, proto)
            (let ((pkey (make-policy-key)))
              (setf (policy-key-identity pkey) identity)
              (setf (policy-key-dport pkey) dst-port)
              (setf (policy-key-proto pkey) proto)

              (if (map-lookup-ptr policy-v4 pkey)
                  ;; Policy match — allow
                  (progn
                    (incf (getmap policy-stats +stat-policy-allowed+))
                    (return XDP_PASS))
                  ;; No policy — deny
                  (progn
                    (incf (getmap policy-stats +stat-policy-denied+))
                    (return XDP_DROP)))))
          ;; Unknown source — drop
          (progn
            (incf (getmap policy-stats +stat-policy-no-identity+))
            (return XDP_DROP))))))
  ;; Default: pass (reached for non-TCP/UDP)
  XDP_PASS)
