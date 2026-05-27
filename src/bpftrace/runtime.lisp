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

;;; ========== /proc/kallsyms symboliser ==========
;;;
;;; Lazy: only parses on first lookup, caches forever within the
;;; running session. The file is sorted by address in the kernel's
;;; output, but we re-sort defensively. Binary search gives us
;;; the nearest symbol ≤ a given address, which we render as
;;; `name+0xOFFSET`.

(defvar *kallsyms* nil
  "Sorted vector of (ADDR . NAME) cons cells. NIL until loaded.")

(defun load-kallsyms ()
  "Parse /proc/kallsyms into *kallsyms*. Silently leaves it NIL if
   the file is unreadable (kptr_restrict, no root, etc.); the
   stack printer falls back to bare hex in that case."
  (handler-case
      (with-open-file (s "/proc/kallsyms" :direction :input)
        (let ((entries (make-array 100000 :fill-pointer 0 :adjustable t)))
          (loop for line = (read-line s nil nil)
                while line
                do (let ((sp1 (position #\Space line))
                         (sp2 nil))
                     (when sp1
                       (setf sp2 (position #\Space line :start (1+ sp1)))
                       (when sp2
                         (let ((addr (parse-integer line :end sp1 :radix 16 :junk-allowed t))
                               (name (subseq line (1+ sp2))))
                           (when (and addr (plusp addr))
                             (vector-push-extend (cons addr name) entries)))))))
          (setf *kallsyms* (sort entries #'< :key #'car))))
    (error () (setf *kallsyms* #()))))

(defun resolve-symbol (addr)
  "Return `name+0xOFFSET' for ADDR, or just the hex address if no
   match. Binary-searches the sorted *kallsyms* for the largest
   entry whose address is ≤ ADDR."
  (when (null *kallsyms*) (load-kallsyms))
  (cond
    ((zerop addr) nil)
    ((or (null *kallsyms*) (zerop (length *kallsyms*)))
     (format nil "0x~X" addr))
    (t
     (let ((lo 0)
           (hi (length *kallsyms*)))
       (loop while (< lo hi)
             do (let ((mid (floor (+ lo hi) 2)))
                  (if (<= (car (aref *kallsyms* mid)) addr)
                      (setf lo (1+ mid))
                      (setf hi mid))))
       (if (zerop lo)
           (format nil "0x~X" addr)
           (let* ((entry  (aref *kallsyms* (1- lo)))
                  (offset (- addr (car entry))))
             (if (zerop offset)
                 (cdr entry)
                 (format nil "~A+0x~X" (cdr entry) offset))))))))

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

(defun parse-interval-period-ns (section)
  "Extract the period (in ns) from `interval/period_N' section names."
  (let* ((parts (split-section section))
         (tail  (second parts)))
    (when (and tail (>= (length tail) 7)
               (string= (subseq tail 0 7) "period_"))
      (parse-integer tail :start 7 :junk-allowed t))))

(defun parse-profile-freq-hz (section)
  "Extract the frequency (Hz) from `profile/freq_N' section names."
  (let* ((parts (split-section section))
         (tail  (second parts)))
    (when (and tail (>= (length tail) 5)
               (string= (subseq tail 0 5) "freq_"))
      (parse-integer tail :start 5 :junk-allowed t))))

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
           (whistler/loader:attach-tracepoint fd section))
          ((string= kind "interval")
           (let ((period (parse-interval-period-ns section)))
             (unless period
               (error 'bpftrace-attach-error
                      :section section :target target
                      :reason "could not parse period from interval section"))
             (whistler/loader::attach-perf-timer fd period)))
          ((string= kind "profile")
           (let ((freq (parse-profile-freq-hz section)))
             (unless freq
               (error 'bpftrace-attach-error
                      :section section :target target
                      :reason "could not parse frequency from profile section"))
             (whistler/loader::attach-perf-profile fd freq)))
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

(defun bignum->comm-string (key)
  "Treat KEY as 16 little-endian bytes (a `comm' value) and convert
   the prefix up to the first NUL byte to a Lisp string."
  (let ((bytes (loop for i below 16
                     collect (logand (ash key (* i -8)) #xff))))
    (let ((end (or (position 0 bytes) 16)))
      (sb-ext:octets-to-string
       (coerce (subseq bytes 0 end) '(simple-array (unsigned-byte 8) (*)))
       :external-format :utf-8))))

(defun format-key (key &key (parts 1) key-builtin)
  "Render KEY (an integer) as bpftrace does.
   * scalar (PARTS=1): bare decimal — unless KEY-BUILTIN is :comm,
     in which case it's actually a 16-byte string masquerading as
     a 2-part integer that the caller forgot to split. (We won't
     hit this case in practice; the caller splits first.)
   * composite (PARTS>1): split into 8-byte chunks and render. When
     KEY-BUILTIN is :comm, the whole 16-byte key is a single string,
     not two integer slots — render it as ASCII."
  (cond
    ((eq key-builtin :comm)
     (format nil "~A" (bignum->comm-string key)))
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

(defun lookup-percpu-u64s (info key &optional (n-fields 1))
  "For a percpu map, look up KEY and return a list of u64s, one per
   field (in declaration order across all CPUs reduced however the
   caller wants). Each per-CPU value is N-FIELDS u64s (1 for sum,
   2 for avg/min/max). Returns ((cpu-fields …) per-cpu)."
  (let* ((kbytes (whistler/loader::encode-int-key
                  key (whistler/loader::map-info-key-size info)))
         (per    (whistler/loader::map-lookup info kbytes)))
    (when (and per (vectorp per))
      (loop for cpu-val across per
            collect (loop for i below n-fields
                          collect (let ((bytes (subseq cpu-val (* i 8) (+ (* i 8) 8))))
                                    (whistler/loader::decode-int-value bytes)))))))

(defun reduce-sum (info key)
  (loop for cpu-fields in (lookup-percpu-u64s info key 1)
        sum (first cpu-fields)))

(defun reduce-avg (info key)
  "Returns (values count sum)."
  (let ((count 0) (sum 0))
    (dolist (cpu-fields (lookup-percpu-u64s info key 2))
      (incf count (first cpu-fields))
      (incf sum   (second cpu-fields)))
    (values count sum)))

(defun reduce-min/max (info key mode)
  "Returns the min or max across CPUs of the cpus that have is_set=1."
  (let ((cur nil))
    (dolist (cpu-fields (lookup-percpu-u64s info key 2))
      (let ((v (first cpu-fields))
            (set (second cpu-fields)))
        (when (plusp set)
          (setf cur (cond ((null cur) v)
                          ((eq mode :min) (min cur v))
                          (t (max cur v)))))))
    (or cur 0)))

(defun print-scalar-map (label info &key (key-parts 1) keyed-p
                                          (kind :counter) key-builtin
                                          stacks-info stack-depth)
  "Print a hash or percpu-hash map's contents in bpftrace's END-dump
   style. KIND controls value decoding; KEY-BUILTIN is the key shape
   hint (:comm → ASCII; :kstack → multi-line symbolised stack)."
  (let* ((keys (map-keys info))
         (pairs (sort (mapcar
                       (lambda (k)
                         (cons k (case kind
                                   (:sum (reduce-sum info k))
                                   (:avg (multiple-value-bind (c s)
                                             (reduce-avg info k)
                                           (if (zerop c) 0 (floor s c))))
                                   ((:min) (reduce-min/max info k :min))
                                   ((:max) (reduce-min/max info k :max))
                                   (t     (lookup-int info k)))))
                       keys)
                      #'< :key #'cdr))
         (prefix (if (or (null label) (string= label "@")) "@" (format nil "@~A" label))))
    (cond
      ;; Stack keys render as a multi-line block of symbolised IPs.
      ((eq key-builtin :kstack)
       (dolist (kv pairs)
         (format t "~A[~%~A~%]: ~D~%"
                 prefix
                 (format-stack (car kv) stacks-info (or stack-depth 32))
                 (cdr kv))))
      (keyed-p
       (dolist (kv pairs)
         (format t "~A[~A]: ~D~%"
                 prefix
                 (format-key (car kv)
                             :parts key-parts
                             :key-builtin key-builtin)
                 (cdr kv))))
      (t
       (dolist (kv pairs)
         (format t "~A: ~D~%" prefix (cdr kv)))))))

(defun print-all-maps (info-list map-alist &key stacks-info stack-depth)
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
                                   :keyed-p (getf (cdr info-rec) :keyed-p)
                                   :key-builtin (getf (cdr info-rec) :key-builtin)
                                   :kind kind
                                   :stacks-info stacks-info
                                   :stack-depth stack-depth)))))))

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

(defun find-stacks-map (gen map-alist)
  (let ((sym (getf gen :stacks-map)))
    (when sym
      (let ((key (string-downcase (substitute #\_ #\- (symbol-name sym)))))
        (cdr (assoc key map-alist :test #'string=))))))

(defun lookup-stack-ips (stacks-info stack-id depth)
  "Look up a stack-trace map entry by stack ID and return a list of
   u64 IPs (truncated at the first 0)."
  (when (and stacks-info (not (zerop stack-id)))
    (let* ((kbytes (whistler/loader::encode-int-key
                    stack-id (whistler/loader::map-info-key-size stacks-info)))
           (raw    (whistler/loader::map-lookup stacks-info kbytes)))
      (when (and raw (vectorp raw))
        (loop for i below depth
              for ip = (whistler/loader::decode-int-value
                        (subseq raw (* i 8) (+ (* i 8) 8)))
              while (plusp ip)
              collect ip)))))

(defparameter *errno-names*
  ;; Just the errnos bpf_get_stackid actually returns. Anything else
  ;; falls back to the bare number.
  '((1  . "EPERM") (2  . "ENOENT") (11 . "EAGAIN") (12 . "ENOMEM")
    (14 . "EFAULT") (16 . "EBUSY") (17 . "EEXIST") (22 . "EINVAL")
    (28 . "ENOSPC") (75 . "EOVERFLOW")))

(defun stackid-errno (stack-id)
  "If STACK-ID has bit 31 set (i32 negative), return the matching
   errno name (or NIL if unknown). bpf_get_stackid returns -ERRNO
   reinterpreted as u32 when it can't capture a stack."
  (when (logbitp 31 stack-id)
    (let* ((neg  (- stack-id (ash 1 32)))
           (cell (assoc (- neg) *errno-names*)))
      (or (cdr cell) (format nil "-~D" (- neg))))))

(defun format-stack (stack-id stacks-info depth)
  "Render a kstack key as bpftrace's indented multi-line stack:
       kfunc1+0x12
       kfunc2+0x34
       …
   Returns the formatted block as a string (no trailing newline)."
  (with-output-to-string (s)
    (let ((errname (stackid-errno stack-id)))
      (if errname
          (format s "        <stack-trace: -~A>" errname)
          (let ((ips (lookup-stack-ips stacks-info stack-id depth)))
            (if ips
                (loop for ip in ips
                      for first-p = t then nil
                      do (unless first-p (terpri s))
                         (format s "        ~A" (resolve-symbol ip)))
                (format s "        <stack id ~D unavailable>" stack-id)))))))

;;; ========== printf record decoding ==========

(defun sap-read-u32-le (sap offset)
  (sb-sys:sap-ref-32 sap offset))

(defun sap-read-u64-le (sap offset)
  (sb-sys:sap-ref-64 sap offset))

(defun signed-64 (u)
  "Reinterpret a 64-bit unsigned integer as signed."
  (if (>= u (ash 1 63)) (- u (ash 1 64)) u))

(defun format-printf (fmt args)
  "C-style printf. ARGS is a list whose entries match the printf-table's
   per-arg type list: ints come through as integers, strings come
   through as Lisp strings. Supports %d/%i/%u/%lld/%llu/%x/%X/%p/%c/%s/%%."
  (with-output-to-string (s)
    (loop with i = 0
          with n = (length fmt)
          with rest = args
          while (< i n)
          for c = (char fmt i)
          do (cond
               ((not (char= c #\%))
                (write-char c s) (incf i))
               ((and (< (1+ i) n) (char= (char fmt (1+ i)) #\%))
                (write-char #\% s) (incf i 2))
               (t
                (let ((j (1+ i)))
                  (loop while (and (< j n) (char= (char fmt j) #\l))
                        do (incf j))
                  (when (>= j n) (write-char c s) (return))
                  (let ((spec (char fmt j))
                        (arg  (pop rest)))
                    (case spec
                      ((#\d #\i) (format s "~D" (signed-64 (or arg 0))))
                      ((#\u)     (format s "~D" (or arg 0)))
                      ((#\x #\p) (format s "~(~X~)" (or arg 0)))
                      ((#\X)     (format s "~X" (or arg 0)))
                      ((#\c)     (write-char (code-char (logand (or arg 0) #xff)) s))
                      ((#\s)     (write-string (if (stringp arg) arg "") s))
                      (t (write-char #\% s) (write-char spec s))))
                  (setf i (1+ j))))))))

(defun sap-read-string-fixed (sap offset max-len)
  "Read MAX-LEN bytes from (SAP+OFFSET), trim at the first NUL, return
   a Lisp string (assumed ASCII / UTF-8 clean for the `comm' use case)."
  (let ((bytes (make-array max-len :element-type '(unsigned-byte 8))))
    (dotimes (i max-len)
      (setf (aref bytes i) (sb-sys:sap-ref-8 sap (+ offset i))))
    (let ((end (or (position 0 bytes) max-len)))
      (sb-ext:octets-to-string bytes :end end :external-format :utf-8))))

(defun decode-printf-record (sap printf-table)
  "Pop a tag=0 (printf) record off the ringbuf and write its formatted
   text to stdout. SAP points at the start of the record; the u32 tag
   has already been read."
  (let* ((id    (sap-read-u32-le sap 4))
         (entry (find id printf-table :key #'first :test #'=)))
    (when entry
      (let* ((fmt   (second entry))
             (types (third entry))
             (args  (let ((off 8))
                      (loop for ty in types
                            collect (ecase ty
                                      (:int
                                       (prog1 (sap-read-u64-le sap off)
                                         (incf off 8)))
                                      (:string
                                       (prog1 (sap-read-string-fixed
                                               sap off 16)
                                         (incf off 16))))))))
        (write-string (format-printf fmt args))))))

;;; print/clear are async actions whose body runs userspace-side.
;;; The kernel side just emits a tagged ringbuf record; the runtime
;;; uses the map-id from the record to find the right map-info and
;;; calls into the existing print path or walks-and-deletes the map.

(defun find-map-by-id (map-id-table id map-alist info-list)
  "Resolve a (tag, map-id) record to (raw-name map-info info-rec)."
  (let* ((cell  (find id map-id-table :key #'cdr :test #'=))
         (msym  (car cell)))
    (when msym
      (let* ((key (string-downcase (substitute #\_ #\- (symbol-name msym))))
             (info-rec (find-if
                        (lambda (ir)
                          (eq (getf (cdr ir) :name) msym))
                        info-list))
             (entry (assoc key map-alist :test #'string=)))
        (values (first info-rec) (cdr entry) info-rec)))))

(defun decode-print-map-record (sap map-id-table map-alist info-list
                                stacks-info stack-depth)
  (let ((id (sap-read-u32-le sap 4)))
    (multiple-value-bind (raw map-info info-rec)
        (find-map-by-id map-id-table id map-alist info-list)
      (when map-info
        (case (getf (cdr info-rec) :kind)
          (:hist (print-hist raw map-info))
          (t     (print-scalar-map
                  raw map-info
                  :key-parts (or (getf (cdr info-rec) :key-parts) 1)
                  :keyed-p   (getf (cdr info-rec) :keyed-p)
                  :key-builtin (getf (cdr info-rec) :key-builtin)
                  :kind      (getf (cdr info-rec) :kind)
                  :stacks-info stacks-info
                  :stack-depth stack-depth)))))))

(defun decode-clear-map-record (sap map-id-table map-alist)
  (let ((id (sap-read-u32-le sap 4)))
    (let* ((cell  (find id map-id-table :key #'cdr :test #'=))
           (msym  (car cell)))
      (when msym
        (let* ((key (string-downcase (substitute #\_ #\- (symbol-name msym))))
               (entry (assoc key map-alist :test #'string=))
               (info (cdr entry)))
          (when info
            (dolist (k (map-keys info))
              (handler-case
                  (whistler/loader::map-delete
                   info (whistler/loader::encode-int-key
                         k (whistler/loader::map-info-key-size info)))
                (error () nil)))))))))

(defun decode-time-record ()
  (multiple-value-bind (sec _msec _usec _yr _mo _day) (get-decoded-time)
    (declare (ignore _msec _usec _yr _mo _day))
    (multiple-value-bind (s m h) (decode-universal-time (get-universal-time))
      (declare (ignore sec))
      (format t "~2,'0D:~2,'0D:~2,'0D~%" h m s))))

(defun make-ring-callback (printf-table map-id-table map-alist info-list
                           &key stacks-info stack-depth)
  "Build the dispatcher that READ_RING_BUFFER invokes for every record."
  (lambda (sap len)
    (declare (ignore len))
    (let ((tag (sap-read-u32-le sap 0)))
      (case tag
        (0 (decode-printf-record    sap printf-table))
        (1 (decode-print-map-record sap map-id-table map-alist info-list
                                    stacks-info stack-depth))
        (2 (decode-clear-map-record sap map-id-table map-alist))
        (3 (decode-time-record))
        (t nil)))
    (force-output)))

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
           (stacks-info (find-stacks-map gen map-alist))
           (stack-depth (or (getf gen :stack-depth) 32))
           (printf-table (getf gen :printf-table))
           (map-id-table (getf gen :map-id-table))
           (info-list-cached info-list)
           (ring-consumer
             (when print-info
               (whistler/loader::open-ring-consumer
                print-info
                (make-ring-callback printf-table map-id-table
                                    map-alist info-list-cached
                                    :stacks-info stacks-info
                                    :stack-depth stack-depth))))
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
        (print-all-maps info-list map-alist
                        :stacks-info stacks-info
                        :stack-depth stack-depth)
        (dolist (a atts) (handler-case (whistler/loader::detach a) (error () nil)))
        (dolist (e prog-alist)
          (let ((fd (whistler/loader::prog-info-fd (cdr e))))
            (when (plusp fd)
              (handler-case (sb-posix:close fd) (error () nil)))))
        (dolist (e map-alist)
          (let ((fd (whistler/loader::map-info-fd (cdr e))))
            (when (plusp fd)
              (handler-case (sb-posix:close fd) (error () nil)))))))))
