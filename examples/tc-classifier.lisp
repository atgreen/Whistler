;;; tc-classifier.lisp — TC packet classifier
;;;
;;; A traffic control classifier that classifies packets by protocol
;;; and port, counting traffic by category. Demonstrates TC-specific
;;; features vs XDP:
;;; - __sk_buff context (data at offset 76, not 0 like xdp_md)
;;; - TC_ACT_OK / TC_ACT_SHOT return codes
;;; - Port-based blocklist with hash map
;;;
;;; Attach with:
;;;   tc qdisc add dev eth0 clsact
;;;   tc filter add dev eth0 ingress bpf da obj tc-classifier.bpf.o sec classifier

(in-package #:whistler)

;;; Maps

;; Per-category packet counters
;; 0: total, 1: high-priority (SSH/DNS), 2: web, 3: blocked
(defmap tc-stats :type :array
  :key-size 4 :value-size 8 :max-entries 4)

;; Port blocklist — hash set of blocked destination ports
;; Key: 2 bytes (port in host byte order), Value: 1 byte
(defmap blocked-ports :type :hash
  :key-size 2 :value-size 1 :max-entries 256)

;;; Constants

(defconstant +stat-total+    0)
(defconstant +stat-highpri+  1)
(defconstant +stat-web+      2)
(defconstant +stat-blocked+  3)

;;; Program

(defprog tc-classify (:type :tc :section "classifier" :license "GPL")
  (let ((data     (ctx data))
        (data-end (ctx data-end)))
    ;; Bounds check: Eth(14) + IPv4(20) + L4 ports(4) = 38
    (when (> (+ data 38) data-end)
      (return TC_ACT_OK))
    ;; IPv4 only
    (when (/= (eth-type data) +ethertype-ipv4+)
      (return TC_ACT_OK))
    (let ((ip    (+ data +eth-hdr-len+))
          (proto (ipv4-protocol (+ data +eth-hdr-len+))))
      ;; Only classify TCP and UDP
      (when (and (/= proto +ip-proto-tcp+) (/= proto +ip-proto-udp+))
        (return TC_ACT_OK))

      (incf (getmap tc-stats +stat-total+))

      (let ((dst-port (tcp-dst-port (+ ip +ipv4-hdr-len+))))
        ;; Check blocklist — drop if port is blocked
        (when (map-lookup blocked-ports dst-port)
          (incf (getmap tc-stats +stat-blocked+))
          (return TC_ACT_SHOT))
        ;; Classify by destination port
        (cond
          ;; High priority: SSH (22), DNS (53)
          ((or (= dst-port 22) (= dst-port 53))
           (incf (getmap tc-stats +stat-highpri+)))
          ;; Web: HTTP (80), HTTPS (443)
          ((or (= dst-port 80) (= dst-port 443))
           (incf (getmap tc-stats +stat-web+)))))))
  TC_ACT_OK)
