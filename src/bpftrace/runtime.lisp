;;; runtime.lisp — userspace runtime (load, attach, print loop)
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Given a generated plist from codegen.lisp, builds a live BPF
;;; session: compiles the defmap/defprog forms, creates the maps,
;;; loads the programs, attaches every kernel probe by parsing the
;;; ELF section name, then enters a print loop that periodically
;;; dumps each map's contents in a bpftrace-style layout.

(in-package #:whistler/bpftrace)

;;; ========== Compiling generated forms ==========

(defun compile-generated (gen)
  "Run the BPF compiler over the maps + programs in GEN.
   Returns (values map-specs prog-specs info-list) — same as
   compile-bpf-forms but driven by our dynamically generated forms.
   :info is augmented with the map's runtime key/value sizes so the
   printer doesn't have to re-introspect."
  (let* ((map-forms  (getf gen :maps))
         (prog-forms (getf gen :progs))
         (info-list  (getf gen :info)))
    (multiple-value-bind (map-specs prog-specs)
        (whistler/loader::compile-bpf-forms map-forms prog-forms)
      (values map-specs prog-specs info-list))))

;;; ========== Attaching kernel probes ==========

(defun split-section (section)
  "Split \"kprobe/foo\" or \"tracepoint/cat/event\" into a list of parts."
  (let ((parts nil)
        (start 0))
    (loop for i from 0 below (length section)
          when (char= (char section i) #\/)
            do (push (subseq section start i) parts)
               (setf start (1+ i)))
    (push (subseq section start) parts)
    (nreverse parts)))

(defun attach-probe (prog-info)
  "Inspect the program's section name and call the appropriate attach-*.
   Translates BPF errors into BPFTRACE-ATTACH-ERROR with hints."
  (let* ((section (whistler/loader::prog-info-section-name prog-info))
         (parts   (split-section section))
         (kind    (first parts))
         (target  (if (string= kind "tracepoint")
                      section
                      (second parts)))
         (fd      (whistler/loader::prog-info-fd prog-info)))
    (handler-case
        (cond
          ((string= kind "kprobe")
           (whistler/loader:attach-kprobe fd target))
          ((string= kind "kretprobe")
           (whistler/loader:attach-kprobe fd target :retprobe t))
          ((string= kind "tracepoint")
           (whistler/loader:attach-tracepoint fd target))
          (t (error 'bpftrace-attach-error
                    :section section :target target
                    :reason (format nil "unknown probe kind ~A" kind))))
      (error (e)
        (error 'bpftrace-attach-error
               :section section :target target :reason e)))))

(define-condition bpftrace-attach-error (error)
  ((section :initarg :section :reader attach-error-section)
   (target  :initarg :target  :reader attach-error-target)
   (reason  :initarg :reason  :reader attach-error-reason))
  (:report
   (lambda (c s)
     (format s "failed to attach probe ~A (target ~A): ~A"
             (attach-error-section c) (attach-error-target c)
             (attach-error-reason c))
     (let ((kind (first (split-section (attach-error-section c)))))
       (cond
         ((or (string= kind "kprobe") (string= kind "kretprobe"))
          (format s "~%~
                  Hint: ~A may not exist on this kernel.~%~
                        Check /proc/kallsyms or /sys/kernel/tracing/available_filter_functions.~%~
                        For storage I/O latency on modern kernels, use~%~
                          tracepoint:block:block_rq_issue / block_rq_complete~%~
                        (note: those require composite keys, not in Phase 1)."
                  (attach-error-target c)))
         ((string= kind "tracepoint")
          (format s "~%~
                  Hint: ensure the tracepoint exists in /sys/kernel/tracing/events.~%~
                        Run as root and make sure tracefs is mounted.")))))))

;;; ========== Pretty-printing maps ==========

(defun map-keys (info)
  "Walk the map (or array) and return a list of integer keys present.
   First call passes nil so the kernel returns the first key — passing
   a concrete zero key would *skip* key 0 if it happened to be in the
   map (e.g. `@m = …` stores at key 0)."
  (let ((keys nil)
        (cur  nil))
    (loop
      (let ((next (whistler/loader::map-get-next-key info cur)))
        (unless next (return))
        (push (whistler/loader::decode-int-value next) keys)
        (setf cur next)))
    (nreverse keys)))

(defun lookup-int (info key)
  (let ((bytes (whistler/loader::map-lookup-int info key)))
    (or bytes 0)))

(defun lookup-percpu-sum (info key)
  "For a percpu map, sum the per-CPU values at KEY (treated as u64)."
  (let* ((kbytes (whistler/loader::encode-int-key
                  key (whistler/loader::map-info-key-size info)))
         (per (whistler/loader::map-lookup info kbytes)))
    (if (and per (vectorp per))
        (loop for cpu-val across per
              sum (whistler/loader::decode-int-value cpu-val))
        0)))

(defun render-bar (count maxc width)
  (if (zerop maxc) ""
      (let* ((n (round (/ (* count width) maxc)))
             (out (make-string width :initial-element #\Space)))
        (dotimes (i n) (when (< i width) (setf (char out i) #\@)))
        out)))

(defun format-key (key &key (parts 1))
  "Render KEY (an integer) as bpftrace does. For composite keys (PARTS > 1)
   we recovered KEY by decoding 8*PARTS little-endian bytes into one big
   integer — split it back into PARTS 8-byte components and render as
   `a, b`. For scalar keys, bare decimal."
  (cond
    ((<= parts 1) (format nil "~D" key))
    (t
     (with-output-to-string (s)
       (loop for i below parts
             for v = (logand (ash key (* i -64)) #xffffffffffffffff)
             do (when (plusp i) (write-string ", " s))
                (format s "~D" v))))))

(defun si-number (n)
  "bpftrace-style SI suffix: 1024 → \"1K\", 1048576 → \"1M\"."
  (cond ((>= n (ash 1 60)) (format nil "~D~A" (ash n -60) "E"))
        ((>= n (ash 1 50)) (format nil "~D~A" (ash n -50) "P"))
        ((>= n (ash 1 40)) (format nil "~D~A" (ash n -40) "T"))
        ((>= n (ash 1 30)) (format nil "~D~A" (ash n -30) "G"))
        ((>= n (ash 1 20)) (format nil "~D~A" (ash n -20) "M"))
        ((>= n (ash 1 10)) (format nil "~D~A" (ash n -10) "K"))
        (t (format nil "~D" n))))

(defun hist-bucket-label (i)
  "bpftrace's bucket labels: [0], [1], [2, 4), [4, 8), …"
  (case i
    (0 "[0]")
    (1 "[1]")
    (t (format nil "[~A, ~A)"
               (si-number (ash 1 (1- i)))
               (si-number (ash 1 i))))))

(defun print-hist (label info)
  "Render a log2 histogram (percpu-array of u64, 64 buckets), bpftrace style."
  (let* ((buckets (loop for i below 64
                        collect (lookup-percpu-sum info i)))
         (last    (or (position-if-not #'zerop buckets :from-end t) -1))
         (maxc    (or (reduce #'max buckets) 0)))
    (format t "~%@~A:~%" label)
    (when (minusp last)
      (format t "    (no samples)~%")
      (return-from print-hist))
    (loop for i from 0 to last
          for count = (nth i buckets)
          do (format t "~16A ~10D |~A|~%"
                     (hist-bucket-label i)
                     count
                     (render-bar count maxc 52)))))

(defun print-scalar-map (label info &key (key-parts 1) keyed-p)
  "Print a hash map's contents in bpftrace's END-dump style.
   KEY-PARTS > 1 means a composite key — split the bignum back into
   8-byte components. KEYED-P=NIL means the script never used `[k]`
   (bare `@m = …`); bpftrace renders those as `@m: value` without the
   `[index]` part."
  (let* ((keys (map-keys info))
         (pairs (sort (mapcar (lambda (k) (cons k (lookup-int info k))) keys)
                      #'< :key #'cdr))
         (prefix (if (or (null label) (string= label "@")) "@" (format nil "@~A" label))))
    (dolist (kv pairs)
      (if keyed-p
          (format t "~A[~A]: ~D~%"
                  prefix (format-key (car kv) :parts key-parts) (cdr kv))
          (format t "~A: ~D~%" prefix (cdr kv))))))

(defun print-all-maps (info-list map-alist)
  "Dump every known map in bpftrace END style."
  (dolist (info-rec info-list)
    (let* ((raw-name    (first info-rec))
           (mname       (getf (cdr info-rec) :name))
           (kind        (getf (cdr info-rec) :kind))
           (key-parts   (or (getf (cdr info-rec) :key-parts) 1))
           (alist-key   (string-downcase
                         (substitute #\_ #\- (symbol-name mname))))
           (entry       (assoc alist-key map-alist :test #'string=))
           (mapinfo     (when entry (cdr entry))))
      (when mapinfo
        (case kind
          (:hist (print-hist raw-name mapinfo))
          (t     (print-scalar-map raw-name mapinfo
                                   :key-parts key-parts
                                   :keyed-p (getf (cdr info-rec) :keyed-p))))))))

;;; ========== Userspace BEGIN/END ==========

(defun run-user-probe (probe)
  "Run a BEGIN/END/interval probe userspace-side. Phase 1 only
   recognises (printf …) inside these blocks; everything else is
   skipped with a notice."
  (dolist (stmt (getf probe :body))
    (when (and (consp stmt) (eq (first stmt) :expr))
      (let ((e (second stmt)))
        (when (and (consp e) (eq (first e) :call)
                   (string= (getf (cdr e) :name) "printf"))
          (let ((args (getf (cdr e) :args)))
            (when (and args (eq (first (first args)) :str))
              (format t "~A" (second (first args)))
              (force-output))))))))

;;; ========== The runtime entry ==========

(defvar *bpftrace-running* nil)

(defun exit-flag-set-p (exit-info)
  "Read the hidden bt-exit map and return T if the kernel side set the
   flag. EXIT-INFO is the whistler/loader::map-info or NIL if the
   script doesn't use exit()."
  (and exit-info
       (let ((v (whistler/loader::map-lookup-int exit-info 0)))
         (and v (plusp v)))))

(defun find-exit-map (gen map-alist)
  "Look up the bt-exit map's map-info from MAP-ALIST, if any."
  (let ((sym (getf gen :exit-map)))
    (when sym
      (let ((key (string-downcase (substitute #\_ #\- (symbol-name sym)))))
        (cdr (assoc key map-alist :test #'string=))))))

(defun find-print-map (gen map-alist)
  (let ((sym (getf gen :print-map)))
    (when sym
      (let ((key (string-downcase (substitute #\_ #\- (symbol-name sym)))))
        (cdr (assoc key map-alist :test #'string=))))))

;;; ========== printf record decoding ==========

(defun sap-read-u32-le (sap offset)
  (sb-sys:sap-ref-32 sap offset))

(defun sap-read-u64-le (sap offset)
  (sb-sys:sap-ref-64 sap offset))

(defun signed-64 (u)
  "Reinterpret a 64-bit unsigned integer as signed."
  (if (>= u (ash 1 63)) (- u (ash 1 64)) u))

(defun format-printf (fmt args)
  "Minimal C-style printf: walks FMT looking for %d/%i/%u/%lld/%llu/
   %x/%lx/%llx/%X/%p/%c/%% specifiers and consumes one ARG each. %s
   is not supported in Phase 1 (would require pulling string bytes
   through the ringbuf). Returns the formatted output string."
  (with-output-to-string (s)
    (loop with i = 0
          with n = (length fmt)
          with rest = args
          while (< i n)
          for c = (char fmt i)
          do (cond
               ((not (char= c #\%))
                (write-char c s) (incf i))
               ;; Two-char sequences
               ((and (< (1+ i) n) (char= (char fmt (1+ i)) #\%))
                (write-char #\% s) (incf i 2))
               ;; Parse [%][l|ll][d|i|u|x|X|p|c|s]
               (t
                (let ((j (1+ i)))
                  ;; consume "l" or "ll"
                  (loop while (and (< j n) (char= (char fmt j) #\l))
                        do (incf j))
                  (when (>= j n) (write-char c s) (return))
                  (let ((spec (char fmt j))
                        (arg  (pop rest)))
                    (case spec
                      ((#\d #\i)
                       (format s "~D" (signed-64 (or arg 0))))
                      ((#\u)
                       (format s "~D" (or arg 0)))
                      ((#\x #\p)
                       (format s "~(~X~)" (or arg 0)))
                      ((#\X)
                       (format s "~X" (or arg 0)))
                      ((#\c)
                       (write-char (code-char (logand (or arg 0) #xff)) s))
                      ((#\s)
                       (write-string "<str>" s))
                      (t
                       (write-char #\% s)
                       (write-char spec s))))
                  (setf i (1+ j))))))))

(defun make-printf-callback (printf-table)
  "Return a lambda suitable for OPEN-RING-CONSUMER: pops an event from
   the ringbuf, looks up its format string in PRINTF-TABLE, and writes
   the formatted output to stdout."
  (lambda (sap len)
    (declare (ignore len))
    (let* ((id   (sap-read-u32-le sap 0))
           (n    (sap-read-u32-le sap 4))
           (entry (find id printf-table :key #'first :test #'=)))
      (when entry
        (let ((fmt   (second entry))
              (args  (loop for k below n
                           collect (sap-read-u64-le sap (+ 8 (* k 8))))))
          (write-string (format-printf fmt args))
          (force-output))))))

(defun test-run-section-p (section)
  "T iff SECTION is one of our synthetic BEGIN/END sections."
  (and section
       (>= (length section) 9)
       (string= (subseq section 0 9) "test_run/")))

(defun begin-section-p (section)
  (and (test-run-section-p section)
       (>= (length section) 15)
       (string= (subseq section 9 15) "begin_")))

(defun end-section-p (section)
  (and (test-run-section-p section)
       (>= (length section) 13)
       (string= (subseq section 9 13) "end_")))

(defun run-generated (gen)
  "Bring up GEN as a live BPF session and block until either Ctrl-C
   or a kernel-side exit() flips the bt-exit flag. BEGIN/END probes
   are kernel programs invoked via BPF_PROG_TEST_RUN; everything
   else attaches normally."
  (multiple-value-bind (map-specs prog-specs info-list)
      (compile-generated gen)
    (let* ((map-alist  (whistler/loader::session-create-maps map-specs))
           (prog-alist (whistler/loader::session-load-progs prog-specs map-alist))
           (atts       nil)
           (exit-info  (find-exit-map gen map-alist))
           (print-info (find-print-map gen map-alist))
           (printf-table (getf gen :printf-table))
           (ring-consumer
             (when print-info
               (whistler/loader::open-ring-consumer
                print-info (make-printf-callback printf-table))))
           (begin-progs (remove-if-not
                         (lambda (entry)
                           (begin-section-p
                            (whistler/loader::prog-info-section-name (cdr entry))))
                         prog-alist))
           (end-progs   (remove-if-not
                         (lambda (entry)
                           (end-section-p
                            (whistler/loader::prog-info-section-name (cdr entry))))
                         prog-alist))
           (attach-progs (remove-if
                          (lambda (entry)
                            (test-run-section-p
                             (whistler/loader::prog-info-section-name (cdr entry))))
                          prog-alist)))
      (unwind-protect
           (handler-case
               (progn
                 ;; BEGIN — kernel test_run, before any attaches.
                 (dolist (b begin-progs)
                   (whistler/loader::prog-test-run
                    (whistler/loader::prog-info-fd (cdr b))))
                 ;; Drain anything BEGIN already wrote to the ringbuf
                 ;; so its output prints before the main loop starts.
                 (when ring-consumer
                   (whistler/loader::ring-poll ring-consumer :timeout-ms 0))
                 ;; Attach all real probes.
                 (dolist (entry attach-progs)
                   (push (attach-probe (cdr entry)) atts))
                 ;; Poll-sleep until interrupted or exit() fires.
                 ;; Drain the printf ringbuf on every tick.
                 (setf *bpftrace-running* t)
                 (handler-case
                     (loop while (and *bpftrace-running*
                                      (not (exit-flag-set-p exit-info)))
                           do (if ring-consumer
                                  (whistler/loader::ring-poll
                                   ring-consumer :timeout-ms 100)
                                  (sleep 0.1)))
                   (sb-sys:interactive-interrupt ()
                     (format t "~&^C~%"))))
             (bpftrace-attach-error (e)
               (format *error-output* "~&~A~%" e)))
        ;; END — kernel test_run, then drain any final printf output,
        ;; then dump maps.
        (dolist (e end-progs)
          (handler-case
              (whistler/loader::prog-test-run
               (whistler/loader::prog-info-fd (cdr e)))
            (error () nil)))
        (when ring-consumer
          (whistler/loader::ring-poll ring-consumer :timeout-ms 0))
        (print-all-maps info-list map-alist)
        (dolist (a atts) (handler-case (whistler/loader::detach a) (error () nil)))
        (dolist (e prog-alist)
          (let ((fd (whistler/loader::prog-info-fd (cdr e))))
            (when (plusp fd)
              (handler-case (sb-posix:close fd) (error () nil)))))
        (dolist (e map-alist)
          (let ((fd (whistler/loader::map-info-fd (cdr e))))
            (when (plusp fd)
              (handler-case (sb-posix:close fd) (error () nil)))))))))
