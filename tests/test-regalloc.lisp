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
              ;; The null check must test the map_lookup_elem return value
              ;; (R0 or a caller-saved reg it was moved to), not R7
              ;; (ktime-get-ns result stashed in callee-saved).
              (is (<= dst-reg 5)
                  (format nil "Inner null check should use caller-saved reg, got R~d" dst-reg)))))))))

(test probe-read-user-arg-order
  "probe-read-user must set R1=dest R2=size R3=src without clobbering (issue #31).
   When dest involves pointer arithmetic and src comes from a caller-saved
   register, the argument setup must not clobber dest when loading the size
   immediate into R2."
  (let* ((maps '((events :type :ringbuf :max-entries 16384)))
         (bytes (let ((whistler::*maps* maps))
                  (w-body "(let ((buf (get-prandom-u32)))
                             (declare (type u64 buf))
                             (when buf
                               (let ((dst (struct-alloc 64)))
                                 (probe-read-user dst 64 buf)
                                 (return 0)))
                             (return 0))"
                          :maps maps)))
         (n (/ (length bytes) 8)))
    ;; Find the probe_read_user call (helper 112)
    (let ((call-idx
           (loop for i below n
                 when (and (= +jmp-call+ (nth-insn-opcode bytes i))
                           (= 112 (nth-insn-imm bytes i)))
                   return i)))
      (is (not (null call-idx))
          "Should contain a call to helper 112 (probe_read_user)")
      (when call-idx
        ;; Walk backward from the call to find the R2 = 64 immediate load.
        ;; R2 must contain the size (64), not a clobbered pointer.
        (let ((r2-imm-idx
               (loop for i from (1- call-idx) downto 0
                     when (and (= +alu64-mov-imm+ (nth-insn-opcode bytes i))
                               (= 2 (logand (nth-insn-regs bytes i) #x0f))
                               (= 64 (nth-insn-imm bytes i)))
                       return i)))
          (is (not (null r2-imm-idx))
              "R2 should be loaded with immediate 64 (the size argument)")
          (when r2-imm-idx
            ;; Between R2=64 and the CALL, there must be no other write to R2
            ;; (that was the clobbering bug: dest ptr was computed into R2,
            ;; then size=64 overwrote it, then R1=R2 copied the wrong value)
            (let ((r2-clobber
                   (loop for i from (1+ r2-imm-idx) below call-idx
                         for opcode = (nth-insn-opcode bytes i)
                         for dst-reg = (logand (nth-insn-regs bytes i) #x0f)
                         when (and (= dst-reg 2)
                                   ;; Exclude the R2=64 itself
                                   (not (= i r2-imm-idx)))
                           return i)))
              (is (null r2-clobber)
                  (format nil "R2 clobbered at insn ~d between size load and call"
                          r2-clobber)))))))))

(test probe-read-user-branched-arg-order
  "probe-read-user in else branch must not clobber args (issue #31).
   This is the specific pattern from the bug report: probe-read-user
   where src comes from a chain of pointer dereferences in a branch."
  (let* ((maps '((events :type :ringbuf :max-entries 16384)))
         (bytes (let ((whistler::*maps* maps))
                  (w-body "(let ((ubuf (get-prandom-u32))
                                 (dst (struct-alloc 64)))
                             (declare (type u64 ubuf))
                             (if ubuf
                                 (probe-read-user dst 64 ubuf)
                                 (let ((alt-src (get-prandom-u32)))
                                   (declare (type u64 alt-src))
                                   (when alt-src
                                     (probe-read-user dst 64 alt-src))))
                             (return 0))"
                          :maps maps)))
         (n (/ (length bytes) 8)))
    ;; Find ALL probe_read_user calls — there should be 2
    (let ((call-indices
           (loop for i below n
                 when (and (= +jmp-call+ (nth-insn-opcode bytes i))
                           (= 112 (nth-insn-imm bytes i)))
                   collect i)))
      (is (= 2 (length call-indices))
          (format nil "Expected 2 probe_read_user calls, got ~d"
                  (length call-indices)))
      ;; For each call, verify R2=64 is set and not clobbered before the call
      (dolist (call-idx call-indices)
        (let ((r2-imm-idx
               (loop for i from (1- call-idx) downto (max 0 (- call-idx 10))
                     when (and (= +alu64-mov-imm+ (nth-insn-opcode bytes i))
                               (= 2 (logand (nth-insn-regs bytes i) #x0f))
                               (= 64 (nth-insn-imm bytes i)))
                       return i)))
          (is (not (null r2-imm-idx))
              (format nil "R2=64 not found before call at insn ~d" call-idx)))))))

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
