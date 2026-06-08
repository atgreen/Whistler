;;; sk-lookup-catchall.lisp — Catch-all sk_lookup that pins every
;;; incoming TCP/UDP connection to a single pre-stashed socket.
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; A userspace process opens a listener, pins its fd into REDIR-SOCKMAP
;;; at index 0, then loads + attaches this program to a netns. The
;;; kernel calls into us during the listener-lookup path for every
;;; inbound TCP SYN / UDP packet; we look up index 0 and assign the
;;; connection to that socket, regardless of the destination port. This
;;; is the building block for protocol-aware service routing on top of
;;; a single bound port.

(in-package #:whistler)

;; SOCKMAP holds a single struct sock * pointer keyed by u32. A lookup in
;; sk_lookup context returns a *reference-counted* socket (the verifier
;; tags it with a ref_obj_id), so the reference must be released with
;; sk-release before the program exits — bpf_sk_assign borrows the socket
;; but does not consume the reference. Skipping the release is a verifier
;; error ("unreleased reference ... reference leak").
(defmap redir-sockmap :type :sockmap
  :key-size 4 :value-size 8 :max-entries 1)

(defprog catch-all (:type :sk-lookup :section "sk_lookup" :license "GPL")
  ;; Single-socket redirect: look up slot 0 in the sockmap and, if
  ;; populated, pin this connection to it, then release the socket
  ;; reference. SK_PASS in any case so the kernel proceeds with its normal
  ;; listener resolution when the sockmap is empty (e.g. during setup).
  (when-let ((sk (map-lookup redir-sockmap 0)))
    (sk-assign (ctx-ptr) sk 0)
    (sk-release sk))
  SK_PASS)
