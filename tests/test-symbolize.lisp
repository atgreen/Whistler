(in-package #:whistler/tests)

(def-suite symbolize-suite
  :description "whistler/symbolize: /proc maps + ELF symbol resolution"
  :in whistler-suite)

(in-suite symbolize-suite)

;;; Distros locate libc.so.6 differently — Fedora puts it at
;;; /usr/lib64/, Debian/Ubuntu uses /lib/x86_64-linux-gnu/. Probe.
(defun libc-path ()
  (find-if #'probe-file
           '("/usr/lib64/libc.so.6"
             "/lib/x86_64-linux-gnu/libc.so.6"
             "/usr/lib/x86_64-linux-gnu/libc.so.6"
             "/usr/lib/aarch64-linux-gnu/libc.so.6")))

;;; ========== /proc/<pid>/maps parsing ==========

(test maps-parses-executable-only
  "Executable r-xp segments with on-disk paths are kept; everything
   else (non-executable, [vdso], (deleted), empty) is dropped."
  (let* ((line-x   "5500000000-5500001000 r-xp 00000000 fe:01 1  /bin/foo")
         (line-rw  "5500001000-5500002000 rw-p 00001000 fe:01 1  /bin/foo")
         (line-vdso "ffff0000-ffff1000 r-xp 00000000 00:00 0    [vdso]")
         (line-del "5500002000-5500003000 r-xp 00000000 fe:01 1  /bin/foo (deleted)"))
    (is (typep (whistler/symbolize::parse-mapping-line line-x) 'whistler/symbolize:mapping)
        "r-xp segment with a real path parses")
    (is (null (whistler/symbolize::parse-mapping-line line-rw))
        "non-executable segment is dropped")
    (is (null (whistler/symbolize::parse-mapping-line line-vdso))
        "[vdso] is dropped")
    (is (null (whistler/symbolize::parse-mapping-line line-del))
        "(deleted) is dropped")))

(test maps-fields-correct
  "Range, offset, and path are decoded correctly."
  (let ((m (whistler/symbolize::parse-mapping-line
            "55c8a47ed000-55c8a47f4000 r-xp 00002000 fe:01 12345  /usr/bin/sbcl")))
    (is (= #x55c8a47ed000 (whistler/symbolize:mapping-start m)))
    (is (= #x55c8a47f4000 (whistler/symbolize:mapping-end m)))
    (is (= #x2000 (whistler/symbolize:mapping-offset m)))
    (is (string= "/usr/bin/sbcl" (whistler/symbolize:mapping-path m)))))

;;; ========== ELF parsing ==========

(test elf-parses-libc
  "Parse the host libc and find a few well-known exports."
  (let ((path (libc-path)))
    (cond
      ((null path) (pass "no libc found on this host"))
      (t (let ((elf (whistler/symbolize::parse-elf path)))
           (is (not (null elf)) "libc parses")
           (is (whistler/symbolize::elf-info-pie-p elf) "libc is ET_DYN")
           (let* ((syms (whistler/symbolize::elf-info-symbols elf))
                  (names (loop for v across syms collect (aref v 2))))
             (is (member "malloc" names :test #'string=) "malloc is present")))))))

(test elf-build-id-and-debuglink-read
  "Build-ID and debuglink section content are extracted cleanly."
  (let ((path (libc-path)))
    (cond
      ((null path) (pass "no libc found on this host"))
      (t (let* ((buf (whistler/symbolize::read-file-bytes path)))
           (when buf
             (multiple-value-bind (secs shstrtab)
                 (whistler/symbolize::read-section-headers buf)
               (let ((bid (whistler/symbolize::read-build-id buf secs shstrtab))
                     (dl  (whistler/symbolize::read-debuglink buf secs shstrtab)))
                 ;; build-id is optional (Ubuntu ships it; some stripped
                 ;; builds don't). When present it must be hex.
                 (is (or (null bid)
                         (every (lambda (c) (or (digit-char-p c)
                                                (and (char>= c #\a) (char<= c #\f))))
                                bid))
                     "build-id, when present, is a hex string")
                 ;; debuglink is also optional.
                 (is (or (null dl) (search ".debug" dl))
                     "debuglink, when present, ends in .debug")))))))))

;;; ========== End-to-end lookup ==========

(test symbolize-libc-address
  "An address inside libc's r-xp segment resolves to a libc function."
  (let* ((symb (whistler/symbolize:open-symbolizer))
         (pid  (sb-posix:getpid)))
    (whistler/symbolize:snapshot-pid symb pid)
    (let* ((data (whistler/symbolize::pid-data symb pid))
           (libc (find-if (lambda (m)
                            (search "libc.so" (whistler/symbolize:mapping-path m)))
                          (coerce (car data) 'list))))
      (when libc
        (let* ((addr (+ (whistler/symbolize:mapping-start libc) #x80000))
               (sym  (whistler/symbolize:symbolize symb pid addr)))
          (is (not (null (whistler/symbolize:sym-name sym)))
              "lookup inside libc resolves to a name")
          (is (search "libc.so" (whistler/symbolize:sym-file sym))
              "file is libc"))))
    (whistler/symbolize:close-symbolizer symb)))

;;; ========== DWARF .debug_line ==========

(test dwarf-line-info-loaded-from-libc
  "When glibc-debuginfo is installed, libc's ELF-INFO carries a
   DWARF-LINE-INFO with thousands of rows resolvable to malloc.c."
  (let* ((path (libc-path))
         (elf  (and path (whistler/symbolize::parse-elf path))))
    (let ((li (and elf (whistler/symbolize::elf-info-line-info elf))))
      (cond
        ((null li)
         ;; No glibc debuginfo on this host; nothing to assert.
         (pass))
        (t
         (is (plusp (length (whistler/symbolize::dwarf-line-info-vaddrs li)))
             "line table has rows")
         (is (plusp (length (whistler/symbolize::dwarf-line-info-files li)))
             "file table is populated")
         ;; Look up the address of a known function and check the
         ;; resolved path mentions malloc.c.
         (let* ((syms (whistler/symbolize::elf-info-symbols elf))
                (malloc (find "__GI___libc_malloc" syms :test #'string=
                              :key (lambda (e) (aref e 2)))))
           (when malloc
             (multiple-value-bind (file line)
                 (whistler/symbolize::dwarf-line-find li (aref malloc 0))
               (is (and file (search "malloc.c" file))
                   "malloc's IP resolves to malloc.c")
               (is (and line (plusp line))
                   "line number is positive")))))))))
