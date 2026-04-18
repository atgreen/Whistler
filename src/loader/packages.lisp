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
   #:bpf-session-map #:bpf-session-prog
   #:encode-int-key #:decode-int-value
   #:with-bpf-object #:open-bpf-object #:load-bpf-object #:close-bpf-object
   ;; Accessors
   #:bpf-object-map #:bpf-object-prog #:prog-info-fd #:prog-info-name
   ;; Map operations
   #:map-lookup #:map-lookup-int #:map-update #:map-update-int
   #:map-lookup-struct #:map-lookup-struct-int
   #:map-update-struct #:map-update-struct-int
   #:map-delete #:map-delete-int #:map-delete-struct
   #:map-get-next-key #:map-get-next-key-int #:map-get-next-key-struct
   #:map-info-fd #:map-info-name
   ;; Attachment
   #:attach-kprobe #:attach-uprobe #:attach-tracepoint #:attach-xdp #:attach-tc
   #:attach-cgroup #:detach
   #:attach-obj-kprobe #:attach-obj-uprobe #:attach-obj-cgroup
   #:attach-obj-xdp #:attach-obj-tc
   ;; Cgroup constants
   #:+bpf-cgroup-inet-ingress+ #:+bpf-cgroup-inet-egress+
   #:+bpf-cgroup-inet-sock-create+ #:+bpf-cgroup-inet-sock-release+
   #:+bpf-cgroup-inet4-bind+ #:+bpf-cgroup-inet6-bind+
   #:+bpf-cgroup-inet4-post-bind+ #:+bpf-cgroup-inet6-post-bind+
   #:+bpf-cgroup-inet4-connect+ #:+bpf-cgroup-inet6-connect+
   #:+bpf-cgroup-udp4-sendmsg+ #:+bpf-cgroup-udp6-sendmsg+
   ;; Program type constants
   #:+bpf-prog-type-cgroup-skb+ #:+bpf-prog-type-cgroup-sock+
   #:+bpf-prog-type-cgroup-sock-addr+
   ;; Ring buffer
   #:open-ring-consumer #:ring-poll #:ring-consume #:close-ring-consumer
   #:open-decoding-ring-consumer #:with-decoding-ring-consumer
   ;; Conditions
   #:bpf-error #:bpf-verifier-error))

(defpackage #:whistler-loader-user
  (:use #:cl #:whistler #:whistler/loader)
  (:shadowing-import-from #:whistler #:incf #:decf #:case #:defstruct))
