;;; Cilium-style XDP Health Probe Responder
;;;
;;; Reimplements the health/ping responder from Cilium's bpf_xdp.c:
;;; Responds to ICMP echo requests at XDP level for a configured
;;; virtual IP, avoiding the kernel network stack entirely for
;;; health probes. This is how Cilium nodes quickly answer
;;; cluster health checks.
;;;
;;; Flow:
;;; 1. Parse Ethernet + IPv4 + ICMP headers
;;; 2. Check if destination IP matches our health VIP
;;; 3. Check if ICMP type = echo request (type 8, code 0)
;;; 4. Swap Ethernet src/dst MACs
;;; 5. Swap IPv4 src/dst addresses
;;; 6. Change ICMP type to echo reply (type 0)
;;; 7. Fixup ICMP checksum
;;; 8. Fixup IPv4 checksum for address swap
;;; 9. XDP_TX (transmit back out same interface)

(in-package #:whistler)

;;; Maps

;; Health VIP configuration
;; Key: 0 (single entry)
;; Value: 4 bytes (IPv4 address to respond for)
(defmap health-vip
  :type :array
  :key-size 4
  :value-size 4
  :max-entries 1)

;; Health statistics
;; Index 0: pings received
;; Index 1: pongs sent
(defmap health-stats
  :type :array
  :key-size 4
  :value-size 8
  :max-entries 2)

;;; Constants

(defconstant +icmp-echo-request+ 8)
(defconstant +icmp-echo-reply+   0)
(defconstant +icmp-hdr-len+      8)  ; type(1) + code(1) + csum(2) + id(2) + seq(2)
(defconstant +stat-ping-rx+      0)
(defconstant +stat-pong-tx+      1)

;;; Helpers

;; Incremental checksum fixup for a u16 field change
(defmacro csum-fixup-u16 (csum-ptr csum-off old-val new-val)
  "Update a 16-bit checksum after changing a u16 field."
  (let ((csum (gensym "CSUM")))
    `(let ((,csum (load u16 ,csum-ptr ,csum-off)))
       ;; ~(~old_csum + ~old_val + new_val)
       (setf ,csum (logand (logxor ,csum #xffff) #xffff))
       (setf ,csum (- ,csum (logand ,old-val #xffff)))
       (setf ,csum (+ ,csum (logand ,new-val #xffff)))
       ;; Fold carry
       (setf ,csum (+ (logand ,csum #xffff) (>> ,csum 16)))
       (setf ,csum (+ (logand ,csum #xffff) (>> ,csum 16)))
       ;; Invert back
       (setf ,csum (logand (logxor ,csum #xffff) #xffff))
       (store u16 ,csum-ptr ,csum-off ,csum))))

;;; Program

(defprog health-responder (:type :xdp :section "xdp" :license "GPL")
  (let ((data     (xdp-data))
        (data-end (xdp-data-end)))
    ;; Bounds check: Eth(14) + IPv4(20) + ICMP header(8) = 42
    (when (> (+ data 42) data-end)
      (return XDP_PASS))
    ;; IPv4 only
    (when (/= (eth-type data) +ethertype-ipv4+)
      (return XDP_PASS))
    (let ((ip    (+ data +eth-hdr-len+))
          (proto (ipv4-protocol (+ data +eth-hdr-len+))))
      ;; ICMP only
      (when (/= proto +ip-proto-icmp+)
        (return XDP_PASS))

      (let ((icmp     (+ ip +ipv4-hdr-len+))
            (dst-addr (ipv4-dst-addr ip)))

        ;; Check if this is destined for our health VIP
        (when-let ((vip-ptr (map-lookup health-vip 0)))
          (let ((vip-addr (load u32 vip-ptr 0)))
            (when (= dst-addr vip-addr)
              ;; Check ICMP echo request (type=8, code=0)
              (let ((icmp-type (load u8 icmp 0))
                    (icmp-code (load u8 icmp 1)))
                (when (and (= icmp-type +icmp-echo-request+)
                           (= icmp-code 0))

                  (incf (getmap health-stats +stat-ping-rx+))

                  ;; === Build echo reply in-place ===

                  ;; 1. Swap Ethernet MAC addresses
                  ;;    dst-mac = bytes 0-5, src-mac = bytes 6-11
                  (let ((mac0-hi (load u32 data 0))    ; dst mac high 4 bytes
                        (mac0-lo (load u16 data 4))    ; dst mac low 2 bytes
                        (mac1-hi (load u32 data 6))    ; src mac high 4 bytes
                        (mac1-lo (load u16 data 10)))  ; src mac low 2 bytes
                    ;; Write src → dst, dst → src
                    (store u32 data 0 mac1-hi)
                    (store u16 data 4 mac1-lo)
                    (store u32 data 6 mac0-hi)
                    (store u16 data 10 mac0-lo))

                  ;; 2. Swap IPv4 src/dst addresses
                  (let ((src-addr (ipv4-src-addr ip))
                        (old-dst dst-addr))
                    (store u32 ip 12 old-dst)     ; new src = old dst
                    (store u32 ip 16 src-addr)    ; new dst = old src
                    ;; IPv4 checksum: src/dst swap is a no-op for the checksum
                    ;; (adding and subtracting same values cancels out)
                    )

                  ;; 3. Change ICMP type: echo request (8) → echo reply (0)
                  (store u8 icmp 0 +icmp-echo-reply+)

                  ;; 4. Fix ICMP checksum for type change (8 → 0)
                  ;;    ICMP checksum is at offset 2 in ICMP header
                  (csum-fixup-u16 icmp 2 +icmp-echo-request+ +icmp-echo-reply+)

                  (incf (getmap health-stats +stat-pong-tx+))

                  (return XDP_TX)))))))))
  XDP_PASS)
