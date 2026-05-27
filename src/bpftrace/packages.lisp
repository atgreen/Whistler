;;; packages.lisp — whistler/bpftrace package
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Frontend that reads bpftrace source and compiles it through Whistler.

(defpackage #:whistler/bpftrace
  (:use #:cl)
  (:shadow #:compile-file)
  (:export
   ;; Public API
   #:compile-script
   #:compile-file
   #:run
   #:run-file
   ;; Errors
   #:bpftrace-error
   #:bpftrace-parse-error
   #:bpftrace-unsupported
   ;; CLI knobs
   #:*pid-filter*
   #:*child-process*
   #:*post-attach-hook*))
