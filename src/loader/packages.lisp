;;; packages.lisp — Package definition for whistler/loader
;;;
;;; SPDX-License-Identifier: MIT

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :sb-posix))

(defpackage #:whistler/loader
  (:use #:cl)
  (:export
   ;; Top-level
   #:with-bpf-session #:*bpf-session* #:bpf-session-maps #:bpf-session-progs
   #:encode-int-key #:decode-int-value
   #:with-bpf-object #:open-bpf-object #:load-bpf-object #:close-bpf-object
   ;; Accessors
   #:bpf-object-map #:bpf-object-prog #:prog-info-fd #:prog-info-name
   ;; Map operations
   #:map-lookup #:map-update #:map-delete #:map-get-next-key
   #:map-info-fd #:map-info-name
   ;; Attachment
   #:attach-kprobe #:attach-uprobe #:attach-tracepoint #:attach-xdp #:attach-tc
   #:attach-cgroup #:detach
   #:attach-obj-kprobe #:attach-obj-uprobe #:attach-obj-cgroup
   ;; Cgroup constants
   #:+bpf-cgroup-inet-ingress+ #:+bpf-cgroup-inet-egress+
   #:+bpf-cgroup-inet-sock-create+ #:+bpf-cgroup-inet-sock-release+
   #:+bpf-cgroup-inet4-connect+ #:+bpf-cgroup-inet6-connect+
   #:+bpf-cgroup-udp4-sendmsg+ #:+bpf-cgroup-udp6-sendmsg+
   ;; Program type constants
   #:+bpf-prog-type-cgroup-skb+ #:+bpf-prog-type-cgroup-sock+
   #:+bpf-prog-type-cgroup-sock-addr+
   ;; Ring buffer
   #:open-ring-consumer #:ring-poll #:ring-consume #:close-ring-consumer
   ;; Conditions
   #:bpf-error #:bpf-verifier-error))
