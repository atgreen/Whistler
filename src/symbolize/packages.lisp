;;; packages.lisp — whistler/symbolize package
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; A focused per-process address symbolizer. Given a pid and a virtual
;;; address (typically an IP captured by bpf_get_stackid with
;;; BPF_F_USER_STACK), return the symbol name + offset + owning file.
;;;
;;; Standalone — no dependencies beyond SBCL. Designed to be the
;;; userspace counterpart to whistler/bpftrace's existing kallsyms
;;; symboliser, used by `ustack' rendering and any future tool that
;;; needs to make sense of userland addresses.

(defpackage #:whistler/symbolize
  (:use #:cl)
  (:export
   ;; Public API
   #:open-symbolizer
   #:close-symbolizer
   #:snapshot-pid
   #:symbolize
   ;; Result struct
   #:sym
   #:sym-addr
   #:sym-name
   #:sym-offset
   #:sym-file
   ;; Mapping struct (exposed for debugging / introspection)
   #:mapping
   #:mapping-start
   #:mapping-end
   #:mapping-offset
   #:mapping-path))
