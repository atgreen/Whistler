;;; ffi-call-tracker.lisp — Standalone inline eBPF uprobe for libffi ffi_call
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Traces all ffi_call() invocations via a uprobe on libffi.so, counts
;;; calls by (program, signature), and dumps stats on Ctrl-C.
;;;
;;; Usage: sudo sbcl --eval '(require :asdf)'
;;;              --eval '(push #p"/path/to/whistler/" asdf:*central-registry*)'
;;;              --eval '(asdf:load-system "whistler/loader")'
;;;              --load examples/ffi-call-tracker.lisp
;;;
;;; The entire BPF program, compilation, loading, and userspace analysis
;;; lives in this single Lisp file. No .bpf.o, no C, no Go.

(in-package #:whistler)

;;; ========== BPF struct definitions ==========

(defstruct ffi-cif
  (abi u32) (nargs u32) (arg-types u64) (rtype u64))

(defstruct ffi-type
  (size u64) (alignment u16) (type-code u16))

(defstruct stats-key
  (comm (array u8 16)) (arg-types (array u8 16))
  (nargs u16) (rtype u8) (abi u8) (pad u32))

(defconstant +max-args+ 16)

;;; ========== FFI type name tables ==========

(defparameter *ffi-type-names*
  #("void" "int" "float" "double" "longdouble"
    "u8" "s8" "u16" "s16" "u32" "s32" "u64" "s64"
    "struct" "ptr" "complex" "u128" "s128"))

(defun ffi-type-name (code)
  (if (< code (length *ffi-type-names*))
      (aref *ffi-type-names* code)
      "?"))

(defun ffi-abi-name (abi)
  (cl:case abi (2 "unix64") (3 "win64") (4 "gnuw64") (otherwise "?")))

;;; ========== Stats key decoder ==========

(defun decode-stats-key (key-bytes)
  "Decode a stats-key byte array into (comm signature)."
  (let* ((comm-end (or (position 0 key-bytes :end 16) 16))
         (comm (map 'string #'code-char (subseq key-bytes 0 comm-end)))
         (nargs (logior (aref key-bytes 32) (ash (aref key-bytes 33) 8)))
         (rtype (aref key-bytes 34))
         (abi (aref key-bytes 35))
         (n (min nargs 16))
         (args (with-output-to-string (s)
                 (dotimes (i n)
                   (when (plusp i) (write-string ", " s))
                   (write-string (ffi-type-name (aref key-bytes (+ 16 i))) s))
                 (when (> nargs 16)
                   (format s ", +~d more" (- nargs 16)))))
         (sig (format nil "~a(~a) [~a]"
                      (ffi-type-name rtype) args (ffi-abi-name abi))))
    (values comm sig)))

;;; ========== Main ==========

(defun run-ffi-tracker (&optional (libffi-path "/lib64/libffi.so.8"))
  (format *error-output* "Compiling and loading BPF program...~%")
  (whistler/loader:with-bpf-session ()
    ;; ---- BPF side: compiled at macroexpand time ----
    (bpf:map stats :type :hash :key-size 40 :value-size 8 :max-entries 10240)

    (bpf:prog ffi_call_tracker (:type :kprobe
                                 :section "uprobe/ffi_call"
                                 :license "GPL")
      (let ((cif (make-ffi-cif))
            (ft  (make-ffi-type))
            (key (make-stats-key)))
        (probe-read-user cif (sizeof ffi-cif) (pt-regs-parm1))
        (probe-read-user ft (sizeof ffi-type) (ffi-cif-rtype cif))
        (setf (stats-key-rtype key) (ffi-type-type-code ft)
              (stats-key-abi key)   (ffi-cif-abi cif)
              (stats-key-nargs key) (ffi-cif-nargs cif))
        (get-current-comm (stats-key-comm-ptr key) 16)
        (memset key 16 #xFF 16)
        (do-user-ptrs (atype-ptr (ffi-cif-arg-types cif) (ffi-cif-nargs cif)
                                 +max-args+ :index i)
          (probe-read-user ft (sizeof ffi-type) atype-ptr)
          (setf (stats-key-arg-types key i) (ffi-type-type-code ft)))
        (incf (getmap stats key)))
      0)

    ;; ---- Userspace side: runs at runtime ----
    (format *error-output* "Attaching uprobe to ffi_call in ~a...~%" libffi-path)
    (bpf:attach ffi_call_tracker libffi-path "ffi_call")
    (format *error-output* "Tracing ffi_call. Press Ctrl-C to dump stats.~%")

    ;; Wait for Ctrl-C
    (handler-case
        (loop (sleep 1))
      (sb-sys:interactive-interrupt ()
        (let ((stats-map (cdr (assoc "stats"
                                     (whistler/loader:bpf-session-maps
                                      whistler/loader:*bpf-session*)
                                     :test #'string=)))
              (entries nil))
          (when stats-map
            (let ((key nil))
              (loop
                (let ((next-key (whistler/loader:map-get-next-key stats-map key)))
                  (unless next-key (return))
                  (let ((value (whistler/loader:map-lookup stats-map next-key)))
                    (when value
                      (multiple-value-bind (comm sig) (decode-stats-key next-key)
                        (push (list (whistler/loader:decode-int-value value) comm sig)
                              entries))))
                  (setf key next-key)))))
          (if (null entries)
              (format t "~&No ffi_call events recorded.~%")
              (progn
                (setf entries (sort entries #'> :key #'first))
                (format t "~&~%~10a  ~16a  ~a~%" "COUNT" "COMM" "SIGNATURE")
                (format t "~10a  ~16a  ~a~%" "--------" "----------------" "---------")
                (dolist (e entries)
                  (format t "~10d  ~16a  ~a~%"
                          (first e) (second e) (third e))))))))))

(run-ffi-tracker (or (second sb-ext:*posix-argv*) "/lib64/libffi.so.8"))
