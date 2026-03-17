;;; synflood-xdp.lisp — TCP SYN flood mitigation
;;;
;;; Tracks SYN packets per source IP. If a source sends more than
;;; +syn-threshold+ SYNs, drop them. Non-SYN TCP and all other
;;; traffic passes through.

(in-package #:whistler)

(defmap syn-counter :type :hash
  :key-size 4 :value-size 8 :max-entries 32768)

(defmap syn-stats :type :array
  :key-size 4 :value-size 8 :max-entries 3)

(defconstant +syn-threshold+ 100)
(defconstant +stat-syn-total+   0)
(defconstant +stat-syn-dropped+ 1)
(defconstant +stat-syn-new-ip+  2)

(defmacro bump-stat (idx)
  `(let ((k ,idx))
     (declare (type u32 k))
     (when-let ((p (map-lookup syn-stats k)))
       (atomic-add p 0 1))))

(defprog synflood (:type :xdp :section "xdp" :license "GPL")
  (with-tcp (data data-end tcp)
    ;; SYN set, ACK not set — single mask+compare instead of two branches
    (when (= (logand (tcp-flags tcp) #x12) +tcp-syn+)

      (bump-stat +stat-syn-total+)

      (let ((src (ipv4-src-addr (+ data +eth-hdr-len+))))
        (if-let (count-ptr (map-lookup syn-counter src))
          ;; Known IP
          (if (> (load u64 count-ptr 0) +syn-threshold+)
              (progn (bump-stat +stat-syn-dropped+)
                     (return XDP_DROP))
              (atomic-add count-ptr 0 1))
          ;; New IP
          (progn (bump-stat +stat-syn-new-ip+)
                 (setf (getmap syn-counter src) 1))))))
  XDP_PASS)
