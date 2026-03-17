;;; ratelimit-xdp.lisp — Per-source-IP rate limiter
;;;
;;; Parses Ethernet + IPv4 headers, extracts the source IP,
;;; and maintains a per-IP packet counter in a hash map.
;;; If a source exceeds the threshold, subsequent packets are dropped.

(in-package #:whistler)

(defmap ip-counter :type :hash
  :key-size 4 :value-size 8 :max-entries 65536)

(defmap stats :type :array
  :key-size 4 :value-size 8 :max-entries 2)

(defconstant +drop-threshold+ 1000)
(defconstant +stat-total+ 0)
(defconstant +stat-dropped+ 1)

(defprog ratelimit (:type :xdp :section "xdp" :license "GPL")
  (when-let ((ip (parse-ipv4 (xdp-data) (xdp-data-end))))
    (incf (getmap stats +stat-total+))
    (let ((src (ipv4-src-addr ip)))
      (if-let (count-ptr (map-lookup ip-counter src))
        ;; Known IP
        (if (> (load u64 count-ptr 0) +drop-threshold+)
            (progn (incf (getmap stats +stat-dropped+))
                   (return XDP_DROP))
            (atomic-add count-ptr 0 1))
        ;; New IP
        (setf (getmap ip-counter src) 1))))
  XDP_PASS)
