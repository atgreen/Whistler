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

;;; ========== Minimal preprocessor ==========
;;;
;;; bpftrace's tools commonly start with #include directives + a
;;; conditional like
;;;   #ifndef BPFTRACE_HAVE_BTF
;;;   #include <linux/socket.h>
;;;   #else
;;;   #define AF_INET 2
;;;   #endif
;;; We always have BTF, so the BTF branch wins. We do NOT parse the
;;; C headers — the structs they declare are resolved against the
;;; kernel's BTF at codegen time. The handful of #define constants
;;; users write inline get harvested into *user-cpp-defines*.

(defvar *user-cpp-defines* nil
  "Per-parse alist NAME → integer from user #define directives.
   Consulted by lower-expr's :constant case after the BTF-enum +
   curated tables. Reset on each parse-script call.")

(defun cpp-preprocess (source)
  "Strip C-style preprocessor directives bpftrace tools rely on:

     #include <…>            silently dropped
     #include \"…\"          silently dropped
     #define NAME INT_LIT    interned into *user-cpp-defines*
     #ifndef BPFTRACE_HAVE_BTF
     …
     #else
     …
     #endif                  the #else branch is kept

   Anything more complex (function-like macros, expression #if,
   multi-level nesting) is out of scope — write the constant inline."
  (setf *user-cpp-defines* nil)
  (with-output-to-string (out)
    (let ((skip-depth 0))
      (with-input-from-string (in source)
        (loop for line = (read-line in nil nil)
              while line
              for trim = (string-left-trim '(#\Space #\Tab) line)
              do (cond
                   ((and (>= (length trim) 2)
                         (string= (subseq trim 0 2) "#!"))
                    ;; #!/usr/bin/env bpftrace shebang — drop.
                    (write-char #\Newline out))
                   ((directive-p trim "#include")
                    (write-char #\Newline out))
                   ((directive-p trim "#define")
                    (intern-cpp-define trim)
                    (write-char #\Newline out))
                   ((directive-p trim "#ifndef BPFTRACE_HAVE_BTF")
                    ;; Always have BTF — skip the no-BTF branch.
                    (setf skip-depth 1)
                    (write-char #\Newline out))
                   ((directive-p trim "#ifdef BPFTRACE_HAVE_BTF")
                    ;; Always have BTF — keep this branch as-is.
                    (write-char #\Newline out))
                   ((directive-p trim "#else")
                    (setf skip-depth (if (zerop skip-depth) 1 0))
                    (write-char #\Newline out))
                   ((directive-p trim "#endif")
                    (setf skip-depth 0)
                    (write-char #\Newline out))
                   ((zerop skip-depth)
                    (write-line line out))
                   (t
                    (write-char #\Newline out))))))))

(defun directive-p (line prefix)
  (and (>= (length line) (length prefix))
       (string= (subseq line 0 (length prefix)) prefix)
       (or (= (length line) (length prefix))
           (let ((c (char line (length prefix))))
             (or (char= c #\Space) (char= c #\Tab))))))

(defun intern-cpp-define (line)
  "Parse `#define NAME VALUE' where VALUE is an integer literal
   (decimal, 0xHEX, octal-with-leading-zero, or parenthesised).
   Quietly ignore anything more elaborate."
  (let* ((rest (string-left-trim '(#\Space #\Tab) (subseq line 7)))  ; after "#define"
         (sp   (position-if (lambda (c) (or (char= c #\Space) (char= c #\Tab))) rest)))
    (when sp
      (let* ((name (subseq rest 0 sp))
             (val-str (string-trim '(#\Space #\Tab #\( #\))
                                   (subseq rest (1+ sp))))
             (val (parse-cpp-int val-str)))
        (when (and (plusp (length name)) val)
          (push (cons name val) *user-cpp-defines*))))))

(defun parse-cpp-int (s)
  "Try to read S as an integer literal. Returns the value or NIL."
  (handler-case
      (cond
        ((and (>= (length s) 2)
              (string= (subseq s 0 2) "0x"))
         (parse-integer s :start 2 :radix 16 :junk-allowed t))
        ((and (>= (length s) 2)
              (string= (subseq s 0 2) "0X"))
         (parse-integer s :start 2 :radix 16 :junk-allowed t))
        (t (parse-integer s :junk-allowed t)))
    (error () nil)))

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
  script         = <ws> top-form (<ws> top-form)* <ws>
  top-form       = function / macro-decl / config-block / map-decl / probe
  (* `let @m = lruhash(N);' (or `hashmap(N)') at top level declares
     a map with an explicit type / capacity. whistler bpftrace
     infers all of this from usage at first reference; we accept
     the declaration so existing tools parse, but discard it at
     AST time — usage-based inference takes over. *)
  map-decl       = <'let'> !ident-char <ws> <'@'> ident <ws> <'='> <ws> map-type-call <ws> <';'>
  map-type-call  = ident <ws> <'('> <ws> integer <ws> <')'>
  function       = <'fn'> <ws> ident <ws> <'('> <ws> param-list? <ws> <')'> <ws> block
  (* bpftrace `macro NAME(args) { body }' — pure inline expansion
     at every call site. Params accept the same `$var' as `fn' plus
     an `@map' form for map-reference parameters used by helpers
     like `display_map(description, @map)'. *)
  macro-decl     = <'macro'> <ws> ident <ws> <'('> <ws> macro-param-list? <ws> <')'> <ws> block
  macro-param-list = macro-param (<ws> <','> <ws> macro-param)*
  (* Macro params come in three flavours: `@ident' (map ref),
     `$ident' (scalar var), or bare `ident' (also scalar — bpftrace
     tools commonly omit the `$' on macro params and reference the
     param by bare name in the body). *)
  macro-param    = '@' ident / '$' ident / ident
  param-list     = param (<ws> <','> <ws> param)*
  param          = <'$'> ident

  (* bpftrace 0.21+ config block: a top-level `config = { … }' that
     sets runtime knobs (missing_probes, max_strlen, etc.). We
     accept-and-ignore — the contents are skipped at AST time so
     the runtime defaults apply. *)
  config-block   = <'config'> <ws> <'='> <ws> <'{'> config-body <'}'>
  config-body    = #'[^}]*'

  probe          = probe-specs <ws> predicate? <ws> block
  probe-specs    = probe-spec (<ws> <','> <ws> probe-spec)*
  probe-spec     = begin-spec / end-spec / profile-spec / interval-spec /
                   kretfunc-spec / kfunc-spec /
                   kretprobe-spec / kprobe-spec / uretprobe-spec /
                   uprobe-spec / tracepoint-spec
  begin-spec     = 'BEGIN'
  end-spec       = 'END'
  kprobe-spec    = <'kprobe'> <':'> glob-ident
  kretprobe-spec = <'kretprobe'> <':'> glob-ident
  kfunc-spec     = <'kfunc'> <':'> ('vmlinux' <':'>)? ident
  kretfunc-spec  = <'kretfunc'> <':'> ('vmlinux' <':'>)? ident
  uprobe-spec    = <'uprobe'> <':'> upath <':'> ident
  uretprobe-spec = <'uretprobe'> <':'> upath <':'> ident
  upath          = #'[A-Za-z0-9_./-]+'
  tracepoint-spec= <'tracepoint'> <':'> glob-ident <':'> glob-ident
  (* Either form is accepted:
       interval:s:1          -- traditional unit:count
       interval:1s           -- count + unit suffix
     Same for profile:.
  *)
  interval-spec  = <'interval'> <':'> (interval-unit <':'> integer / integer interval-unit)
  profile-spec   = <'profile'> <':'> (interval-unit <':'> integer / integer interval-unit)
  interval-unit  = 'ms' / 'us' / 's' / 'hz'

  predicate      = <'/'> <ws> expr <ws> <'/'>

  block          = <'{'> <ws> statements? <ws> <'}'>
  (* Statements are separated by `;', but bpftrace tools commonly
     elide it after compound statements (if/while/block), so the
     separator is optional. *)
  statements     = statement (<ws> (<';'> <ws>)? statement)* (<ws> <';'>)?
  statement      = if-stmt / while-stmt / let-stmt / return-stmt / assign-stmt / expr-stmt
  return-stmt    = <'return'> !ident-char <ws> expr?
  while-stmt     = <'while'> !ident-char <ws> <'('> <ws> expr <ws> <')'> <ws> block
  (* `let $var;' or `let $var = expr;' — bpftrace's local-var decl.
     For us the bare decl is a no-op (variables are inferred from
     use); the assigning form becomes a regular :assign. *)
  let-stmt       = <'let'> !ident-char <ws> <'$'> ident (<ws> <'='> <ws> expr)?
  if-stmt        = <'if'> <ws> if-cond <ws> block (<ws> <'else'> <ws> block)?
  if-cond        = <'('> <ws> expr <ws> <')'> / expr
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
  (* `*EXPR' is a u64 pointer dereference — common in tools that
     read kernel global symbols, e.g. *kaddr(\"avenrun\"). *)
  unary-op       = '!' / '-' / '~' / '*'

  postfix        = primary postfix-tail*
  postfix-tail   = field-access / arrow-access / index-access
  field-access   = <'.'> ident
  arrow-access   = <'->'> ident
  index-access   = <'['> <ws> expr (<ws> <','> <ws> expr)* <ws> <']'>

  primary        = cast / primitive-cast / parens / func-call / map-access / scalar-var / builtin /
                   constant / string-lit / hex-int / integer
  (* C-style struct-pointer cast: open-paren struct ident asterisk
     close-paren expr. Must precede `parens' in the alternates so the
     open-paren disambiguation tries the cast shape first. The cast
     binds to a full postfix expression so a struct-pointer cast
     followed by `.field' is parsed as `cast(args.field)' (matching
     bpftrace), not `cast(args).field'. *)
  cast           = <'('> <ws> <'struct'> <ws> ident <ws> <'*'> <ws> <')'> <ws> postfix
  (* Primitive C cast: uint64 of expr, int of expr. Treated as a no-op
     since all values are u64 in our IR; preserves bpftrace
     compatibility for scripts that lean on integer narrowing. *)
  primitive-cast = <'('> <ws> int-type-name <ws> <')'> <ws> postfix
  int-type-name  = 'uint64' / 'uint32' / 'uint16' / 'uint8' /
                   'int64' / 'int32' / 'int16' / 'int8' /
                   'uint' / 'int'
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
  builtin-name   = 'ppid' / 'pid' / 'tid' / 'uid' / 'gid' / 'nsecs' / 'elapsed' /
                   'cpu' / 'comm' / 'probe' / 'func' / 'retval' / 'curtask' /
                   'cgroup' / 'rand' / 'args' / 'kstack' / 'ustack' /
                   'arg0' / 'arg1' / 'arg2' / 'arg3' / 'arg4' /
                   'arg5' / 'arg6' / 'arg7' / 'arg8' / 'arg9'

  ident          = #'[A-Za-z_][A-Za-z0-9_]*'
  (* `glob-ident' is `ident' that also accepts `*' and `.' anywhere
     — used for wildcard probe targets like `kprobe:tcp_*' or
     `kprobe:lookup_fast.constprop.*'. *)
  glob-ident     = #'[A-Za-z_*][A-Za-z0-9_*.]*'
  <ident-char>   = #'[A-Za-z0-9_]'
  string-lit     = #'\"([^\"\\\\]|\\\\.)*\"'
  hex-int        = #'0[xX][0-9A-Fa-f]+'
  (* bpftrace accepts shorthand scientific notation as an integer
     literal: \`1e6' → 1000000. We restrict to non-negative exponents
     so the result stays an integer. *)
  integer        = #'[0-9]+([eE][0-9]+)?'
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
  (let* ((preprocessed (cpp-preprocess source))
         (clean (strip-comments preprocessed))
         (result (let ((iparse:*signal-errors* nil))
                   (iparse:parse (ensure-parser) clean))))
    (when (iparse:parse-failure-p result)
      (error 'bpftrace-parse-error :source source :failure result))
    ;; Strip metaobjects (line/column annotations) so the AST walker
    ;; sees plain (:tag …) lists.
    (iparse:transform (make-hash-table :test 'eq) result)))
