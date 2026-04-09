;;; cgroup-skb-count.lisp — Count egress packets using cgroup_skb
;;;
;;; Usage (requires root):
;;;   sudo sbcl --load examples/cgroup-skb-count.lisp
;;;
;;; This demonstrates cgroup_skb/egress attachment via pre-compiled ELF,
;;; counting all outbound packets for processes in the target cgroup.

(require :asdf)
(asdf:load-system "whistler/loader")

(in-package #:whistler)

(defmap pkt-count :type :array
  :key-size 4 :value-size 8 :max-entries 1)

(defprog count-egress
    (:type :cgroup-skb :section "cgroup_skb/egress" :license "GPL")
  (incf (getmap pkt-count 0))
  1)  ;; 1 = allow (SK_PASS for cgroup_skb)

(compile-to-elf "/tmp/cgroup-skb-count.bpf.o")

(format t "Compiled cgroup_skb/egress program to /tmp/cgroup-skb-count.bpf.o~%")

(whistler/loader:with-bpf-object (obj "/tmp/cgroup-skb-count.bpf.o")
  (let ((map (whistler/loader:bpf-object-map obj "pkt_count"))
        (att (whistler/loader:attach-obj-cgroup
              obj "count_egress" "/sys/fs/cgroup"
              whistler/loader:+bpf-cgroup-inet-egress+)))
    (declare (ignore att))
    (format t "Attached to /sys/fs/cgroup (egress). Counting packets...~%")
    (loop repeat 10
          do (sleep 1)
             (let ((val (whistler/loader:map-lookup
                         map
                         (whistler/loader:encode-int-key 0 4))))
               (format t "  egress packets: ~d~%"
                       (if val (whistler/loader:decode-int-value val) 0))))))
