;;; cache.lisp — per-symbolizer caches
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; A SYMBOLIZER bundles two caches:
;;;   * pid → (mappings, perf-map): captured by SNAPSHOT-PID at attach
;;;     time so we can still resolve addresses for short-lived
;;;     processes after they exit.
;;;   * file path → ELF-INFO: a binary's symbol table is the same for
;;;     every process that maps it, so we parse and cache once per file.

(in-package #:whistler/symbolize)

(defstruct (symbolizer (:constructor %make-symbolizer))
  pid-cache       ; eql hash table   PID  → (mappings . perf-map)
  elf-cache)      ; equal hash table PATH → ELF-INFO

(defun open-symbolizer ()
  "Allocate an empty symbolizer. Caches grow on demand."
  (%make-symbolizer
   :pid-cache (make-hash-table)
   :elf-cache (make-hash-table :test 'equal)))

(defun close-symbolizer (symb)
  "Drop all caches. The symbolizer is not usable after this."
  (clrhash (symbolizer-pid-cache symb))
  (clrhash (symbolizer-elf-cache symb))
  nil)

(defun snapshot-pid (symb pid)
  "Capture /proc/PID/maps and /tmp/perf-PID.map for PID. Idempotent
   — re-running on the same pid refreshes the snapshot."
  (setf (gethash pid (symbolizer-pid-cache symb))
        (cons (load-mappings pid) (load-perf-map pid)))
  nil)

(defun pid-data (symb pid)
  "Return (mappings . perf-map) for PID, snapshotting lazily if we
   haven't seen this pid before."
  (or (gethash pid (symbolizer-pid-cache symb))
      (progn (snapshot-pid symb pid)
             (gethash pid (symbolizer-pid-cache symb)))))

(defun cached-elf (symb path)
  "Open and parse PATH if needed, then cache. Returns ELF-INFO or NIL
   if the file can't be parsed."
  (multiple-value-bind (info present-p)
      (gethash path (symbolizer-elf-cache symb))
    (if present-p
        info
        (let ((parsed (parse-elf path)))
          (setf (gethash path (symbolizer-elf-cache symb)) parsed)
          parsed))))
