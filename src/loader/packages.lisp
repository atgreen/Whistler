;;; packages.lisp — Package definition for whistler/loader
;;;
;;; SPDX-License-Identifier: MIT

(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :sb-posix))

(defpackage #:whistler/loader
  (:use #:cl)
  (:export
   ;; Top-level
   #:open-bpf-object #:load-bpf-object #:close-bpf-object
   ;; Accessors
   #:bpf-object-map #:bpf-object-prog
   ;; Map operations
   #:map-lookup #:map-update #:map-delete #:map-get-next-key
   #:map-info-fd #:map-info-name
   ;; Attachment
   #:attach-kprobe #:attach-uprobe #:attach-xdp #:detach
   ;; Ring buffer
   #:open-ring-consumer #:ring-poll #:ring-consume #:close-ring-consumer
   ;; Conditions
   #:bpf-error #:bpf-verifier-error))
