(in-package #:whistler/tests)

(in-suite optimization-suite)

;;; ========== Phi-threading regression tests (issue #12) ==========
;;;
;;; When phi-branch-threading redirects a predecessor, the corresponding
;;; phi input must be removed.  Otherwise simplify-cfg's block merge
;;; drops the phi definition while its uses survive, leaving an undefined
;;; vreg that the emitter assigns to a random callee-saved register.

(test phi-threading-removes-stale-input
  "Phi-threading must remove the redirected input from the phi (issue #12).
   After threading + simplify-cfg, every vreg used in the IR must have a definition."
  (let* ((body (read-whistler-forms
                "(let* ((pid-tgid (get-current-pid-tgid))
                        (pid (logand (ash pid-tgid -32) #xffffffff))
                        (now (ktime-get-ns))
                        (val (getmap stats pid)))
                   (if val
                       (progn
                         (store u64 val 0 (+ (load u64 val 0) 1))
                         (store u64 val 32 now))
                       (let ((init (struct-alloc 40)))
                         (store u64 init 0 1)
                         (store u64 init 32 now)
                         (map-update stats pid init 0))))"))
         (maps '((stats :type :hash :key-size 4 :value-size 40 :max-entries 256)))
         (map-structs
          (loop for (name . rest) in maps
                for idx from 0
                collect (whistler/compiler::make-bpf-map
                         :name name
                         :type (whistler/compiler:resolve-map-type (getf rest :type))
                         :key-size (getf rest :key-size)
                         :value-size (getf rest :value-size)
                         :max-entries (getf rest :max-entries)
                         :flags 0 :index idx)))
         ;; Macro-expand and constant-fold
         (expanded (let ((whistler::*maps* maps))
                     (mapcar (lambda (form)
                               (whistler/compiler:constant-fold-sexpr
                                (whistler/compiler:whistler-macroexpand form)))
                             body)))
         (ir (whistler/ir:lower-program "tp" "GPL" map-structs expanded)))
    ;; Run the optimizer (includes phi-branch-threading)
    (whistler/ir:optimize-ir ir)
    ;; Collect all defined vregs and all used vregs
    (let ((defined (make-hash-table))
          (used (make-hash-table)))
      (dolist (block (whistler/ir:ir-program-blocks ir))
        (dolist (insn (whistler/ir:basic-block-insns block))
          (when (whistler/ir:ir-insn-dst insn)
            (setf (gethash (whistler/ir:ir-insn-dst insn) defined) t))
          (dolist (vreg (whistler/ir::ir-insn-all-vreg-uses insn))
            (setf (gethash vreg used) t))))
      ;; Every used vreg must have a definition
      (let ((undefined nil))
        (maphash (lambda (vreg _)
                   (declare (ignore _))
                   (unless (gethash vreg defined)
                     (push vreg undefined)))
                 used)
        (is (null undefined)
            (format nil "Vregs used without definition: ~a" undefined))))))

(test phi-threading-helper-call-before-getmap
  "let* with helper call + getmap must not assign getmap result to the helper's register.
   Regression test for issue #12: ktime-get-ns result in R7 clobbered getmap's phi."
  (let* ((maps '((stats :type :hash :key-size 4 :value-size 40 :max-entries 256)))
         (bytes (let ((whistler::*maps* maps))
                  (w-body "(let* ((pid-tgid (get-current-pid-tgid))
                                  (pid (logand (ash pid-tgid -32) #xffffffff))
                                  (now (ktime-get-ns))
                                  (val (getmap stats pid)))
                             (if val
                                 (progn
                                   (store u64 val 0 (+ (load u64 val 0) 1))
                                   (store u64 val 32 now))
                                 (let ((init (struct-alloc 40)))
                                   (store u64 init 0 1)
                                   (store u64 init 32 now)
                                   (map-update stats pid init 0))))"
                         :maps maps)))
         (n (/ (length bytes) 8)))
    ;; Find the map_lookup_elem call (helper 1)
    (let ((map-call-idx
           (loop for i below n
                 when (and (= +jmp-call+ (nth-insn-opcode bytes i))
                           (= 1 (nth-insn-imm bytes i)))
                   return i)))
      (is (not (null map-call-idx))
          "Should contain a map_lookup_elem call")
      (when map-call-idx
        ;; After the map_lookup_elem call, the inner null check should test R0
        ;; (the return register), not R7 (a callee-saved register holding ktime).
        ;; Find the first conditional jump after the map_lookup call.
        (let ((first-cond-idx
               (loop for i from (1+ map-call-idx) below n
                     when (member (nth-insn-opcode bytes i)
                                  (list +jmp-jeq-imm+ +jmp-jne-imm+
                                        +jmp-jeq-reg+ +jmp-jne-reg+))
                       return i)))
          (when first-cond-idx
            (let* ((reg-byte (nth-insn-regs bytes first-cond-idx))
                   (dst-reg (logand reg-byte #x0f)))
              ;; The null check must test R0 (map_lookup_elem return value),
              ;; not R7 (ktime-get-ns result stashed in callee-saved)
              (is (= 0 dst-reg)
                  (format nil "Inner null check should test R0, got R~d" dst-reg)))))))))

(test phi-threading-getmap-without-helper-call
  "getmap without a preceding helper call in let* should still work correctly."
  (let* ((maps '((m :type :hash :key-size 4 :value-size 8 :max-entries 256)))
         (n (let ((whistler::*maps* maps))
              (w-count "(let* ((pid-tgid (get-current-pid-tgid))
                               (pid (logand (ash pid-tgid -32) #xffffffff))
                               (val (getmap m pid)))
                          (if val (return val) (return 0)))"
                       :maps maps))))
    ;; Should compile without issues
    (is (> n 5) "getmap without helper call should compile")))
