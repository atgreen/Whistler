;;; grammar.lisp — iparse grammar for the bpftrace subset
;;;
;;; SPDX-License-Identifier: MIT
;;;
;;; Phase 1 scope: enough to express biolatency / runqlat / opensnoop /
;;; execsnoop. The grammar is intentionally conservative — we'd rather
;;; report "unsupported" cleanly than parse and silently mis-handle.
;;;
;;; Supported probe types:  BEGIN, END, kprobe, kretprobe, tracepoint, interval
;;; Map ops:                @m, @m[k], @m[k,k], ++/--, +=/-=, =
;;; Aggregations:           count(), sum(x), avg(x), min(x), max(x),
;;;                         hist(x), lhist(x,min,max,step)
;;; Functions:              printf(...), exit(), delete(@m[k]), clear(@m)
;;; Built-ins:              pid tid uid gid nsecs cpu comm probe func
;;;                         arg0..arg9 retval args
;;; Control flow:           if (cond) {…} else {…} ;  predicates  /expr/
;;;
;;; Comments:               // line   and   /* block */     (stripped pre-parse)

(in-package #:whistler/bpftrace)

;;; ========== Comment stripping ==========

(defun strip-comments (source)
  "Remove // and /* */ comments from a bpftrace script.
   Preserves comments inside string literals."
  (with-output-to-string (out)
    (let ((i 0)
          (n (length source)))
      (loop while (< i n)
            for c = (char source i)
            do (cond
                 ;; String literal — copy through verbatim, watch for \"
                 ((char= c #\")
                  (write-char c out)
                  (incf i)
                  (loop while (and (< i n) (char/= (char source i) #\"))
                        do (when (and (char= (char source i) #\\) (< (1+ i) n))
                             (write-char (char source i) out)
                             (incf i))
                           (write-char (char source i) out)
                           (incf i))
                  (when (< i n)
                    (write-char (char source i) out)
                    (incf i)))
                 ;; Line comment
                 ((and (char= c #\/) (< (1+ i) n) (char= (char source (1+ i)) #\/))
                  (loop while (and (< i n) (char/= (char source i) #\Newline))
                        do (incf i)))
                 ;; Block comment
                 ((and (char= c #\/) (< (1+ i) n) (char= (char source (1+ i)) #\*))
                  (incf i 2)
                  (loop while (and (< (1+ i) n)
                                   (not (and (char= (char source i) #\*)
                                             (char= (char source (1+ i)) #\/))))
                        do (incf i))
                  (incf i 2))
                 (t (write-char c out)
                    (incf i)))))))

;;; ========== Grammar ==========
;;;
;;; The grammar is written in iparse's EBNF dialect. We hide whitespace
;;; with <ws> and explicitly tag every meaningful node so the codegen
;;; pass can keyword-dispatch on (:script (:probe …)).
;;;
;;; Operator precedence ladder follows C — the deepest rules bind tightest.

(defparameter *grammar-source*
  "
  script         = <ws> probe (<ws> probe)* <ws>

  probe          = probe-specs <ws> predicate? <ws> block
  probe-specs    = probe-spec (<ws> <','> <ws> probe-spec)*
  probe-spec     = begin-spec / end-spec / profile-spec / interval-spec /
                   kretfunc-spec / kfunc-spec /
                   kretprobe-spec / kprobe-spec / uretprobe-spec /
                   uprobe-spec / tracepoint-spec
  begin-spec     = 'BEGIN'
  end-spec       = 'END'
  kprobe-spec    = <'kprobe'> <':'> ident
  kretprobe-spec = <'kretprobe'> <':'> ident
  kfunc-spec     = <'kfunc'> <':'> ('vmlinux' <':'>)? ident
  kretfunc-spec  = <'kretfunc'> <':'> ('vmlinux' <':'>)? ident
  uprobe-spec    = <'uprobe'> <':'> upath <':'> ident
  uretprobe-spec = <'uretprobe'> <':'> upath <':'> ident
  upath          = #'[A-Za-z0-9_./-]+'
  tracepoint-spec= <'tracepoint'> <':'> ident <':'> ident
  interval-spec  = <'interval'> <':'> interval-unit <':'> integer
  profile-spec   = <'profile'> <':'> interval-unit <':'> integer
  interval-unit  = 's' / 'ms' / 'us' / 'hz'

  predicate      = <'/'> <ws> expr <ws> <'/'>

  block          = <'{'> <ws> statements? <ws> <'}'>
  statements     = statement (<ws> <';'> <ws> statement)* (<ws> <';'>)?
  statement      = if-stmt / assign-stmt / expr-stmt
  if-stmt        = <'if'> <ws> <'('> <ws> expr <ws> <')'> <ws> block (<ws> <'else'> <ws> block)?
  assign-stmt    = lhs <ws> assign-op <ws> expr  /
                   lhs <ws> incdec-op
  expr-stmt      = expr
  lhs            = map-access / scalar-var
  assign-op      = '=' / '+=' / '-=' / '*=' / '/=' / '%=' / '|=' / '&=' / '^='
  incdec-op      = '++' / '--'

  (* expressions, precedence-climbed *)
  expr           = ternary
  ternary        = lor <ws> (<'?'> <ws> expr <ws> <':'> <ws> expr)?
  lor            = land (<ws> '||' <ws> land)*
  land           = bor (<ws> '&&' <ws> bor)*
  bor            = bxor (<ws> '|' !'|' <ws> bxor)*
  bxor           = band (<ws> '^' <ws> band)*
  band           = eq (<ws> '&' !'&' <ws> eq)*
  eq             = rel (<ws> ('==' / '!=') <ws> rel)*
  rel            = shift (<ws> ('<=' / '>=' / '<' !'<' / '>' !'>') <ws> shift)*
  shift          = add (<ws> ('<<' / '>>') <ws> add)*
  add            = mul (<ws> ('+' / '-') <ws> mul)*
  mul            = unary (<ws> ('*' / '/' / '%') <ws> unary)*
  unary          = unary-op <ws> unary / postfix
  unary-op       = '!' / '-' / '~'

  postfix        = primary postfix-tail*
  postfix-tail   = field-access / arrow-access / index-access
  field-access   = <'.'> ident
  arrow-access   = <'->'> ident
  index-access   = <'['> <ws> expr (<ws> <','> <ws> expr)* <ws> <']'>

  primary        = parens / func-call / map-access / scalar-var / builtin /
                   constant / string-lit / hex-int / integer
  (* Bare identifier — used for symbolic constants like AF_INET. Comes
     after builtin and func-call so those keywords / call shapes win
     when applicable. !ident-char anchors the boundary so identifier
     prefixes don't match. *)
  constant       = ident !ident-char
  parens         = <'('> <ws> expr <ws> <')'>
  func-call      = ident <ws> <'('> <ws> arg-list? <ws> <')'>
  arg-list       = expr (<ws> <','> <ws> expr)*
  map-access     = <'@'> (ident <ws>)? map-keys? / <'@'>
  map-keys       = <'['> <ws> expr (<ws> <','> <ws> expr)* <ws> <']'>
  scalar-var     = <'$'> ident

  builtin        = builtin-name !ident-char
  builtin-name   = 'pid' / 'tid' / 'uid' / 'gid' / 'nsecs' / 'elapsed' /
                   'cpu' / 'comm' / 'probe' / 'func' / 'retval' / 'curtask' /
                   'cgroup' / 'rand' / 'args' / 'kstack' / 'ustack' /
                   'arg0' / 'arg1' / 'arg2' / 'arg3' / 'arg4' /
                   'arg5' / 'arg6' / 'arg7' / 'arg8' / 'arg9'

  ident          = #'[A-Za-z_][A-Za-z0-9_]*'
  <ident-char>   = #'[A-Za-z0-9_]'
  string-lit     = #'\"([^\"\\\\]|\\\\.)*\"'
  hex-int        = #'0[xX][0-9A-Fa-f]+'
  integer        = #'[0-9]+'
  <ws>           = #'[\\s]*'
  ")

(defvar *parser* nil
  "Cached iparse parser. Lazy-initialised on first call to PARSE-SCRIPT.")

(defun ensure-parser ()
  (or *parser*
      (setf *parser* (iparse:parser *grammar-source*))))

(define-condition bpftrace-parse-error (error)
  ((source :initarg :source :reader bpftrace-parse-error-source)
   (failure :initarg :failure :reader bpftrace-parse-error-failure))
  (:report (lambda (c s)
             (format s "bpftrace parse error: ~A"
                     (bpftrace-parse-error-failure c)))))

(defun parse-script (source)
  "Parse SOURCE (a bpftrace script string) and return the raw iparse tree.
   Signals BPFTRACE-PARSE-ERROR on failure."
  (let* ((clean (strip-comments source))
         (result (let ((iparse:*signal-errors* nil))
                   (iparse:parse (ensure-parser) clean))))
    (when (iparse:parse-failure-p result)
      (error 'bpftrace-parse-error :source source :failure result))
    ;; Strip metaobjects (line/column annotations) so the AST walker
    ;; sees plain (:tag …) lists.
    (iparse:transform (make-hash-table :test 'eq) result)))
