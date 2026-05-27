(in-package #:whistler/tests)

(def-suite symbolize-suite
  :description "whistler/symbolize: /proc maps + ELF symbol resolution"
  :in whistler-suite)

(in-suite symbolize-suite)

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
  "Parse /usr/lib64/libc.so.6 and find a few well-known exports."
  (let ((elf (whistler/symbolize::parse-elf "/usr/lib64/libc.so.6")))
    (is (not (null elf)) "libc parses")
    (is (whistler/symbolize::elf-info-pie-p elf) "libc is ET_DYN")
    (let* ((syms (whistler/symbolize::elf-info-symbols elf))
           (names (loop for v across syms collect (aref v 2))))
      (is (member "malloc" names :test #'string=) "malloc is present"))))

(test elf-build-id-and-debuglink-read
  "Build-ID and debuglink section content are extracted cleanly."
  (let* ((buf (whistler/symbolize::read-file-bytes "/usr/lib64/libc.so.6")))
    (when buf
      (multiple-value-bind (secs shstrtab)
          (whistler/symbolize::read-section-headers buf)
        (let ((bid (whistler/symbolize::read-build-id buf secs shstrtab))
              (dl  (whistler/symbolize::read-debuglink buf secs shstrtab)))
          (is (and bid (every (lambda (c) (or (digit-char-p c)
                                              (and (char>= c #\a) (char<= c #\f))))
                              bid))
              "build-id is a hex string")
          (is (and dl (search ".debug" dl))
              "debuglink ends in .debug"))))))

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
