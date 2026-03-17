;;; Cilium-style simplified Connection Tracker (IPv4)
;;;
;;; Reimplements core CT4 logic from Cilium's lib/conntrack.h:
;;; Tracks TCP/UDP connections by 5-tuple, maintains per-flow state
;;; with lifetime management. New connections create entries;
;;; established flows are fast-pathed; expired entries are cleaned.
;;;
;;; Simplified vs. Cilium: no NAT state, no CT labels, no related
;;; entries, no reply-direction tracking. Just forward-direction
;;; 5-tuple tracking with basic lifetime and TCP state.
;;;
;;; Flow:
;;; 1. Parse Ethernet + IPv4 + L4 headers
;;; 2. Build CT key: (src-ip, dst-ip, src-port, dst-port, proto)
;;; 3. Lookup in conntrack map
;;; 4. If found: check lifetime, update timestamp, pass
;;; 5. If expired: delete stale entry, create new one
;;; 6. If not found: create new entry with current timestamp
;;; 7. All traffic passes (tracking only, no enforcement)

(in-package #:whistler)

;;; Struct definitions

;; Connection tracking key — 5-tuple identifying a flow
(defstruct ct4-key
  (src-addr  u32)   ; offset 0  — source IP
  (dst-addr  u32)   ; offset 4  — destination IP
  (src-port  u16)   ; offset 8  — source port
  (dst-port  u16)   ; offset 10 — destination port
  (proto     u8)    ; offset 12 — IP protocol
  (flags     u8)    ; offset 13 — reserved
  (pad       u16))  ; offset 14 — padding (total: 16 bytes)

;; Connection tracking value
(defstruct ct4-value
  (last-seen u64)   ; offset 0  — ktime_ns of last packet
  (packets   u32)   ; offset 8  — packet count
  (tcp-flags u8)    ; offset 12 — accumulated TCP flags
  (pad1      u8)    ; offset 13
  (pad2      u16))  ; offset 14 — (total: 16 bytes)

;;; Maps

;; Connection tracking table
;; Key: ct4-key (16 bytes), Value: ct4-value (16 bytes)
(defmap ct4-map
  :type :hash
  :key-size 16
  :value-size 16
  :max-entries 65536)

;; Statistics counters
;; Index 0: total tracked packets
;; Index 1: new connections
;; Index 2: expired/cleaned entries
(defmap ct4-stats
  :type :array
  :key-size 4
  :value-size 8
  :max-entries 3)

;;; Constants

(defconstant +ct-lifetime-ns+ 300000000000)  ; 300 seconds in nanoseconds
(defconstant +stat-ct-total+   0)
(defconstant +stat-ct-new+     1)
(defconstant +stat-ct-expired+ 2)

;;; Helper — create a new CT value on stack

(defmacro make-ct4-entry (now-expr)
  "Create a ct4-value struct initialized with timestamp and packet count 1."
  (let ((v (gensym "VAL")))
    `(let ((,v (make-ct4-value)))
       (setf (ct4-value-last-seen ,v) ,now-expr)
       (setf (ct4-value-packets ,v) 1)
       ,v)))

;;; Program

(defprog ct4-track (:type :xdp :section "xdp" :license "GPL")
  (let ((data     (xdp-data))
        (data-end (xdp-data-end)))
    ;; Bounds check: Eth + IPv4 + 4 bytes L4 (ports)
    (when (> (+ data 38) data-end)
      (return XDP_PASS))
    ;; IPv4 only
    (when (/= (eth-type data) +ethertype-ipv4+)
      (return XDP_PASS))
    (let ((ip    (+ data +eth-hdr-len+))
          (proto (ipv4-protocol (+ data +eth-hdr-len+))))
      ;; TCP or UDP only
      (when (and (/= proto +ip-proto-tcp+) (/= proto +ip-proto-udp+))
        (return XDP_PASS))
      (let ((l4 (+ ip +ipv4-hdr-len+)))
        ;; Build CT key
        (let ((key (make-ct4-key)))
          (setf (ct4-key-src-addr key) (ipv4-src-addr ip))
          (setf (ct4-key-dst-addr key) (ipv4-dst-addr ip))
          (setf (ct4-key-src-port key) (load u16 l4 0))
          (setf (ct4-key-dst-port key) (load u16 l4 2))
          (setf (ct4-key-proto key) proto)

          (let ((now (ktime-get-ns)))
            (if-let (val (map-lookup-ptr ct4-map key))
              ;; Existing entry — check lifetime
              (let ((last-seen (load u64 val 0)))
                (when (<= (- now last-seen) +ct-lifetime-ns+)
                  ;; Still valid — update timestamp, packet count, TCP flags
                  (store u64 val 0 now)
                  (atomic-add val 8 1)
                  (when (= proto +ip-proto-tcp+)
                    (when (> (+ l4 14) data-end)
                      (return XDP_PASS))
                    (let ((tcp-flags (tcp-flags l4))
                          (old-flags (load u8 val 12)))
                      (store u8 val 12 (logior old-flags tcp-flags))))
                  (incf (getmap ct4-stats +stat-ct-total+))
                  (return XDP_PASS))
                ;; Expired — delete, fall through to shared create path
                (incf (getmap ct4-stats +stat-ct-expired+))
                (map-delete-ptr ct4-map key))
              ;; New connection — fall through to shared create path
              (incf (getmap ct4-stats +stat-ct-new+)))
            ;; Shared: create entry (used by both expired and new paths)
            (let ((new-val (make-ct4-entry now)))
              (map-update-ptr ct4-map key new-val 0))
            (incf (getmap ct4-stats +stat-ct-total+)))))))
  XDP_PASS)
