;;; maps.lisp — /proc/<pid>/maps parser
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Parses the executable text segments of a process's address space.
;;; Each /proc/<pid>/maps line has the form:
;;;
;;;   START-END PERMS OFFSET DEV INODE  PATH
;;;
;;; e.g.
;;;   55c8a47ed000-55c8a47f4000 r-xp 00002000 fe:01 12345  /usr/bin/sbcl
;;;
;;; We keep only segments with PERMS = `r-xp' (or `r-xs') and a real
;;; on-disk PATH — that's where executable code lives. Anonymous and
;;; pseudo-segments (`[vdso]', `[heap]', `[stack]', empty path,
;;; `(deleted)' tag) are dropped: there's no ELF file to symbolise
;;; against. Returned ordering is sorted by START so the consumer can
;;; binary-search.

(in-package #:whistler/symbolize)

(defstruct mapping
  start        ; virtual address, inclusive (u64)
  end          ; virtual address, exclusive (u64)
  offset       ; file offset of the segment's first byte
  path)        ; "/usr/bin/sbcl" — guaranteed non-empty

;;; ---- Line-level parsing ----

(defun skip-spaces (line i n)
  (loop while (and (< i n) (char= (char line i) #\Space))
        do (incf i)
        finally (return i)))

(defun read-token (line i n)
  "Read up to the next whitespace. Returns (values TOKEN END-INDEX)."
  (let ((start i))
    (loop while (and (< i n)
                     (not (char= (char line i) #\Space)))
          do (incf i))
    (values (subseq line start i) i)))

(defun parse-hex-range (token)
  "Split `START-END' (both hex) into two integers."
  (let ((dash (position #\- token)))
    (when dash
      (values (parse-integer token :end dash :radix 16)
              (parse-integer token :start (1+ dash) :radix 16)))))

(defun executable-perms-p (perms)
  "T iff the segment is executable. The third character of PERMS is
   `x' when the segment is executable."
  (and (>= (length perms) 3)
       (char= (char perms 2) #\x)))

(defun pseudo-path-p (path)
  "T for kernel-provided pseudo-segments we can't open as ELF files."
  (or (zerop (length path))
      (char= (char path 0) #\[)        ; [vdso], [heap], [stack], …
      ;; "(deleted)" tail: the binary was unlinked while still mapped.
      ;; We could still potentially symbolise from /proc/<pid>/exe but
      ;; the path on disk is gone; punt for v1.
      (search " (deleted)" path)))

(defun parse-mapping-line (line)
  "Parse a single /proc/<pid>/maps line. Returns a MAPPING or NIL if
   the line should be ignored (non-executable, pseudo-path, malformed)."
  (let ((n (length line))
        (i 0))
    (multiple-value-bind (range j) (read-token line i n)
      (multiple-value-bind (start end) (parse-hex-range range)
        (unless (and start end) (return-from parse-mapping-line nil))
        (setf i (skip-spaces line j n))
        (multiple-value-bind (perms k) (read-token line i n)
          (unless (executable-perms-p perms)
            (return-from parse-mapping-line nil))
          (setf i (skip-spaces line k n))
          (multiple-value-bind (offstr l) (read-token line i n)
            (let ((offset (parse-integer offstr :radix 16 :junk-allowed t)))
              (unless offset (return-from parse-mapping-line nil))
              (setf i (skip-spaces line l n))
              ;; Skip DEV and INODE
              (multiple-value-bind (_dev m) (read-token line i n)
                (declare (ignore _dev))
                (setf i (skip-spaces line m n)))
              (multiple-value-bind (_inode m) (read-token line i n)
                (declare (ignore _inode))
                (setf i (skip-spaces line m n)))
              ;; Whatever's left, modulo trailing whitespace, is the path
              (let ((path (string-right-trim '(#\Space #\Tab #\Newline)
                                             (subseq line i))))
                (if (pseudo-path-p path)
                    nil
                    (make-mapping :start start :end end
                                  :offset offset :path path))))))))))

;;; ---- File-level ----

(defun load-mappings (pid)
  "Read /proc/PID/maps and return a sorted vector of MAPPINGs covering
   the process's executable segments at this moment. Empty vector if
   the file is unreadable or the process has already exited."
  (let ((out (make-array 16 :fill-pointer 0 :adjustable t)))
    (handler-case
        (with-open-file (s (format nil "/proc/~D/maps" pid)
                           :direction :input :external-format :latin-1)
          (loop for line = (read-line s nil nil)
                while line
                for m = (parse-mapping-line line)
                when m do (vector-push-extend m out)))
      (error () nil))
    (sort out #'< :key #'mapping-start)))

(defun find-mapping (mappings ip)
  "Binary-search MAPPINGS (vector sorted by START) for the one whose
   [start,end) covers IP. Returns the MAPPING or NIL."
  (let ((lo 0) (hi (length mappings)))
    (loop while (< lo hi) do
      (let* ((mid (floor (+ lo hi) 2))
             (m   (aref mappings mid)))
        (cond
          ((< ip (mapping-start m))  (setf hi mid))
          ((>= ip (mapping-end m))   (setf lo (1+ mid)))
          (t (return-from find-mapping m)))))
    nil))

;;; ========== /tmp/perf-<pid>.map (JIT overlay) ==========
;;;
;;; perf-format JIT maps: each line is
;;;
;;;     <hex_start> <hex_size> <name>
;;;
;;; Used by V8, .NET, PHP, etc. to advertise their JIT'd code
;;; regions to external profilers. We consult this *first* in the
;;; symbolize lookup because the JIT'd code lives in anonymous
;;; executable mappings that don't appear in /proc/<pid>/maps as a
;;; file we can open.

(defun load-perf-map (pid)
  "Parse /tmp/perf-PID.map into a sorted vector of #(START SIZE NAME).
   Returns an empty vector if the file is absent or empty."
  (let ((path (format nil "/tmp/perf-~D.map" pid))
        (out  (make-array 16 :fill-pointer 0 :adjustable t)))
    (when (probe-file path)
      (handler-case
          (with-open-file (s path :direction :input :external-format :latin-1)
            (loop for line = (read-line s nil nil)
                  while line
                  for sp1 = (position #\Space line)
                  for sp2 = (and sp1 (position #\Space line :start (1+ sp1)))
                  when sp2
                    do (let ((start (parse-integer line :end sp1
                                                   :radix 16 :junk-allowed t))
                             (size  (parse-integer line :start (1+ sp1) :end sp2
                                                   :radix 16 :junk-allowed t))
                             (name  (subseq line (1+ sp2))))
                         (when (and start size)
                           (vector-push-extend
                            (vector start size name) out)))))
        (error () nil)))
    (sort out #'< :key (lambda (e) (aref e 0)))))

(defun find-perf-map-entry (perf-map ip)
  "Binary-search PERF-MAP for an entry whose [start, start+size) covers IP.
   Returns #(START SIZE NAME) or NIL."
  (let ((lo 0) (hi (length perf-map)))
    (loop while (< lo hi) do
      (let* ((mid (floor (+ lo hi) 2))
             (e   (aref perf-map mid))
             (start (aref e 0))
             (end   (+ start (aref e 1))))
        (cond
          ((< ip start)  (setf hi mid))
          ((>= ip end)   (setf lo (1+ mid)))
          (t (return-from find-perf-map-entry e)))))
    nil))
