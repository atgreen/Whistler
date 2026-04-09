;;; cgroup-skb-session.lisp — Inline cgroup_skb using with-bpf-session
;;;
;;; Usage (requires root):
;;;   sudo sbcl --load examples/cgroup-skb-session.lisp

(require :asdf)
(asdf:load-system "whistler/loader")

(use-package :whistler/loader)

(with-bpf-session ()
  (bpf:map pkt-count :type :array :key-size 4 :value-size 8 :max-entries 1)

  (bpf:prog count-egress
      (:type :cgroup-skb :section "cgroup_skb/egress" :license "GPL")
    (incf (getmap pkt-count 0))
    1)

  (bpf:attach count-egress "/sys/fs/cgroup")
  (format t "Counting egress packets on /sys/fs/cgroup...~%")
  (loop repeat 10
        do (sleep 1)
           (format t "  packets: ~d~%" (or (bpf:map-ref pkt-count 0) 0))))
