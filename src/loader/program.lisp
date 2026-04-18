;;; program.lisp — BPF program relocation patching and loading
;;;
;;; SPDX-License-Identifier: MIT

(in-package #:whistler/loader)

;;; ========== Program info ==========

(defstruct prog-info
  name section-name type insns (fd -1))

;;; ========== Relocation patching ==========

(defconstant +bpf-pseudo-map-fd+ 1)

(defun patch-map-relocations (insns rel-entries symtab map-fds)
  "Patch LD_IMM64 instructions with map FDs based on relocations.
   MAP-FDS is an alist of (symbol-name . fd).
   Returns a new byte vector with patched instructions."
  (let ((patched (copy-seq insns)))
    (dolist (rel rel-entries)
      (let* ((offset (elf-rel-offset rel))
             (sym-idx (elf-rel-sym-idx rel))
             (sym (nth sym-idx symtab))
             (map-name (elf-sym-name sym))
             (fd (cdr (assoc map-name map-fds :test #'string=))))
        (unless fd
          (error "No map FD for relocation symbol ~a" map-name))
        ;; Patch LD_IMM64: set src_reg = BPF_PSEUDO_MAP_FD (1) in byte 1 high nibble
        (setf (aref patched (+ offset 1))
              (logior (logand (aref patched (+ offset 1)) #x0f)
                      (ash +bpf-pseudo-map-fd+ 4)))
        ;; Set imm = map FD (u32 LE at offset+4)
        (setf (aref patched (+ offset 4)) (logand fd #xff))
        (setf (aref patched (+ offset 5)) (logand (ash fd -8) #xff))
        (setf (aref patched (+ offset 6)) (logand (ash fd -16) #xff))
        (setf (aref patched (+ offset 7)) (logand (ash fd -24) #xff))))
    patched))

;;; ========== Program type detection ==========

(defun section-to-prog-type (section-name)
  "Determine BPF program type from ELF section name."
  (cond
    ((or (string= section-name "xdp")
         (and (> (length section-name) 4)
              (string= (subseq section-name 0 4) "xdp/")))
     +bpf-prog-type-xdp+)
    ((or (and (>= (length section-name) 7)
              (string= (subseq section-name 0 7) "kprobe/"))
         (and (>= (length section-name) 7)
              (string= (subseq section-name 0 7) "uprobe/")))
     +bpf-prog-type-kprobe+)
    ((and (>= (length section-name) 11)
          (string= (subseq section-name 0 11) "tracepoint/"))
     +bpf-prog-type-tracepoint+)
    ((or (string= section-name "tc")
         (and (> (length section-name) 3)
              (string= (subseq section-name 0 3) "tc/")))
     +bpf-prog-type-sched-cls+)
    ;; Cgroup program types
    ((and (>= (length section-name) 10)
          (string= (subseq section-name 0 10) "cgroup_skb"))
     +bpf-prog-type-cgroup-skb+)
    ((and (>= (length section-name) 7)
          (string= (subseq section-name 0 7) "cgroup/")
          (let ((rest (subseq section-name 7)))
            (or (string= rest "sock_create")
                (string= rest "sock_release")
                (string= rest "post_bind4")
                (string= rest "post_bind6"))))
     +bpf-prog-type-cgroup-sock+)
    ((and (>= (length section-name) 7)
          (string= (subseq section-name 0 7) "cgroup/")
          (let ((rest (subseq section-name 7)))
            (or (string= rest "connect4")
                (string= rest "connect6")
                (string= rest "sendmsg4")
                (string= rest "sendmsg6")
                (string= rest "bind4")
                (string= rest "bind6"))))
     +bpf-prog-type-cgroup-sock-addr+)
    (t +bpf-prog-type-socket-filter+)))

(defun section-to-expected-attach-type (section-name)
  "Determine BPF expected attach type from ELF section name.
   Returns nil for program types that don't require an expected attach type."
  (cond
    ((string= section-name "cgroup_skb/ingress") +bpf-cgroup-inet-ingress+)
    ((string= section-name "cgroup_skb/egress")  +bpf-cgroup-inet-egress+)
    ((string= section-name "cgroup/sock_create")  +bpf-cgroup-inet-sock-create+)
    ((string= section-name "cgroup/sock_release") +bpf-cgroup-inet-sock-release+)
    ((string= section-name "cgroup/connect4")     +bpf-cgroup-inet4-connect+)
    ((string= section-name "cgroup/connect6")     +bpf-cgroup-inet6-connect+)
    ((string= section-name "cgroup/sendmsg4")     +bpf-cgroup-udp4-sendmsg+)
    ((string= section-name "cgroup/sendmsg6")     +bpf-cgroup-udp6-sendmsg+)
    ((string= section-name "cgroup/bind4")        +bpf-cgroup-inet4-bind+)
    ((string= section-name "cgroup/bind6")        +bpf-cgroup-inet6-bind+)
    ((string= section-name "cgroup/post_bind4")   +bpf-cgroup-inet4-post-bind+)
    ((string= section-name "cgroup/post_bind6")   +bpf-cgroup-inet6-post-bind+)
    (t nil)))

;;; ========== Program loading ==========

(defun load-program (insns prog-type license &key (log-level 0) (log-buf-size (ash 1 20))
                                                   expected-attach-type)
  "Load a BPF program into the kernel. Returns the prog FD.
   EXPECTED-ATTACH-TYPE is required for cgroup program types.
   On failure, retries with logging and signals bpf-verifier-error."
  (let ((buf (make-attr-buf))
        (insn-count (/ (length insns) 8)))
    (sb-sys:with-pinned-objects (insns)
      (let ((license-bytes (sb-ext:string-to-octets license :null-terminate t)))
        (sb-sys:with-pinned-objects (license-bytes)
          (put-u32 buf 0 prog-type)
          (put-u32 buf 4 insn-count)
          (put-ptr buf 8 (sb-sys:vector-sap insns))
          (put-ptr buf 16 (sb-sys:vector-sap license-bytes))
          (put-u32 buf 24 log-level)
          (when expected-attach-type
            (put-u32 buf 68 expected-attach-type))
          ;; Try without log first
          (handler-case
              (%bpf +bpf-prog-load+ buf 128 "prog-load")
            (bpf-error ()
              ;; Retry with verifier log
              (let ((log-buf (make-array log-buf-size
                                         :element-type '(unsigned-byte 8)
                                         :initial-element 0)))
                (sb-sys:with-pinned-objects (log-buf)
                  (fill buf 0)
                  (put-u32 buf 0 prog-type)
                  (put-u32 buf 4 insn-count)
                  (put-ptr buf 8 (sb-sys:vector-sap insns))
                  (put-ptr buf 16 (sb-sys:vector-sap license-bytes))
                  (put-u32 buf 24 6)  ; log_level = stats + detailed
                  (put-u32 buf 28 log-buf-size)
                  (put-ptr buf 32 (sb-sys:vector-sap log-buf))
                  (when expected-attach-type
                    (put-u32 buf 68 expected-attach-type))
                  (handler-case
                      (%bpf +bpf-prog-load+ buf 128 "prog-load")
                    (bpf-error (e)
                      (let* ((end (or (position 0 log-buf) (length log-buf)))
                             (log-str (sb-ext:octets-to-string
                                       log-buf :end end :external-format :utf-8)))
                        (error 'bpf-verifier-error
                               :context "prog-load"
                               :errno (bpf-error-errno e)
                               :log log-str)))))))))))))
