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
  top-form       = function / macro-decl / config-block / map-decl / struct-decl / enum-decl / union-decl / import-decl / probe
  (* `import \"stdlib/test\";' — bpftrace 0.22+ module import. We
     accept-and-discard; downstream code only resolves what is
     actually defined in this script, so calls into the imported
     stdlib will still fail at codegen with a clearer message. *)
  import-decl    = <'import'> <ws> string-lit <ws> <';'>
  (* `enum [NAME] { K1 = V1, K2, … };' at script top-level. Parsed
     into named members so bare-ident uses (`print(K1)') resolve to
     the matching integer. *)
  enum-decl      = <'enum'> (<ws> ident)? <ws> <'{'> <ws> enum-members? <ws> <'}'> (<ws> <';'>)?
  enum-members   = enum-member (<ws> <','> <ws> enum-member)* (<ws> <','>)?
  enum-member    = ident (<ws> <'='> <ws> (hex-int / integer))?
  (* `union N { … };' — accept-and-discard, like enum-decl. Codegen
     doesn't resolve union members yet; scripts using them will hit
     the regular `field access' error at use site. *)
  union-decl     = <'union'> <ws> ident <ws> <'{'> #'[^}]*' <'}'> (<ws> <';'>)?
  (* `struct NAME { … }' at script top-level — bpftrace's in-script
     C struct declaration. We accept it so scripts parse, but the
     body is captured as opaque text; codegen reports a clearer
     `in-script struct types not yet supported' error if NAME is
     then used in a struct-pointer cast. Kernel-BTF structs still
     work because they're never declared in the script. *)
  struct-decl    = <'struct'> <ws> ident <ws> <'{'> <ws> struct-field* <ws> <'}'> (<ws> <';'>)?
  (* `int x;', `int x[4];', `const char* ignore;', `struct Bar { int x; } bar;'
     etc. Field-type captures the type tokens loosely (qualifiers, ptr
     stars, embedded structs); field-array-suffix captures `[N]' when
     present. Trailing `;' is required. Nested struct bodies are
     handled by recursion at parse time — the inner `struct N { … }'
     reduces to another struct-field-type which produces a struct-decl
     style branch in field-type. *)
  (* Field-array-suffix repeats so `int y[2][3]', `char m[4][5][6]'
     etc. parse. We capture each dim as its own integer; codegen
     multiplies them into a total element count for sizing. *)
  struct-field   = field-type <ws> ident (<ws> field-array-suffix)* <ws> <';'> <ws>
  field-array-suffix = <'['> <ws> integer <ws> <']'>
  (* A field type is either:
       - a `struct N { … }' embedded def (rare but legal),
       - a `struct N' / `struct N *' name reference,
       - a plain type-name with optional qualifiers + pointer stars. *)
  field-type     = struct-embed / struct-ref / plain-type
  struct-embed   = <'struct'> <ws> ident <ws> <'{'> <ws> struct-field* <ws> <'}'>
  struct-ref     = <'struct'> <ws> ident (<ws> '*')*
  plain-type     = type-qual* type-name (<ws> '*')* type-qual*
  type-qual      = ('const' / 'volatile' / 'unsigned' / 'signed') !ident-char <ws>
  type-name      = ident
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
                   uprobe-spec / tracepoint-spec /
                   bench-spec / rawtracepoint-spec
  (* `bench:NAME { … }' — bpftrace 0.22+ benchmark pseudo-probe. We
     accept the syntax so scripts parse; the body still compiles
     through the normal kernel-prog pipeline. A true `--mode bench'
     runner that loops + times the body is deferred. *)
  bench-spec     = <('bench' / 'b') !ident-char> <':'> ident
  (* `rawtracepoint:NAME' — accepted at parse time; codegen falls
     through to kprobe-style attach which will fail at load time
     because the right BPF prog type isn't wired. Better than a
     parse error. *)
  rawtracepoint-spec = <'rawtracepoint' !ident-char> <':'> ident
  (* `BEGIN' / `END' (classic) and `begin' / `end' (bpftrace 0.22+)
     both legal — same semantics. The !ident-char anchor prevents
     `beginning' / `endpoint' style identifiers from being eaten. *)
  begin-spec     = ('BEGIN' / 'begin') !ident-char
  end-spec       = ('END' / 'end') !ident-char
  (* bpftrace short forms for every probe type — `k:'/`kr:'/`u:'/
     `ur:'/`t:'/`f:'/`fr:'/`i:'/`p:' are accepted alongside the long
     spellings. The !ident-char anchor prevents a script that uses
     `interval' written `interval' from being eaten as `i'-prefix.
     The optional `MODULE:' prefix routes through bpftrace's BTF
     module resolver (`kprobe:vmlinux:vfs_read'). The function name
     may also carry `+OFFSET' to probe at a byte offset past the
     symbol entry. *)
  kprobe-spec    = <('kprobe' / 'k') !ident-char> <':'> (glob-ident <':'>)? glob-ident kprobe-offset?
  kretprobe-spec = <('kretprobe' / 'kr') !ident-char> <':'> (glob-ident <':'>)? glob-ident
  kprobe-offset  = <'+'> integer
  (* `fentry:'/`fexit:' are bpftrace 0.20+ aliases for `kfunc:'/
     `kretfunc:'. Both forms attach BPF_PROG_TYPE_TRACING programs
     to BTF-typed kernel functions; the codegen treats them the same. *)
  (* kfunc/fentry/kretfunc/fexit accept an optional kernel-module
     name prefix: `fentry:kvm:foo' resolves `foo' against the `kvm'
     module's BTF instead of vmlinux's. We accept any ident for the
     module, then a colon, then the function name. *)
  kfunc-spec     = <('kfunc'   / 'fentry' / 'f' )  !ident-char> <':'> (ident <':'>)? ident
  kretfunc-spec  = <('kretfunc' / 'fexit'  / 'fr') !ident-char> <':'> (ident <':'>)? ident
  uprobe-spec    = <('uprobe' / 'u')   !ident-char> <':'> upath <':'> ident
  uretprobe-spec = <('uretprobe' / 'ur') !ident-char> <':'> upath <':'> ident
  upath          = #'[A-Za-z0-9_./-]+'
  tracepoint-spec= <('tracepoint' / 't') !ident-char> <':'> glob-ident <':'> glob-ident
  (* Either form is accepted:
       interval:s:1          -- traditional unit:count
       interval:1s           -- count + unit suffix
     Same for profile:.
  *)
  interval-spec  = <('interval' / 'i') !ident-char> <':'> (interval-unit <':'> integer / integer interval-unit)
  profile-spec   = <('profile'  / 'p') !ident-char> <':'> (interval-unit <':'> integer / integer interval-unit)
  interval-unit  = 'ms' / 'us' / 's' / 'hz'

  predicate      = <'/'> <ws> expr <ws> <'/'>

  block          = <'{'> <ws> statements? <ws> <'}'>
  (* Statements are separated by `;', but bpftrace tools commonly
     elide it after compound statements (if/while/block), so the
     separator is optional. *)
  statements     = statement (<ws> (<';'> <ws>)? statement)* (<ws> <';'>)?
  statement      = if-stmt / while-stmt / for-stmt / unroll-stmt / let-stmt / return-stmt /
                   break-stmt / continue-stmt / assign-stmt / expr-stmt
  (* `unroll(N) { body }' — bpftrace's compile-time loop unroller. N
     must be a literal integer or `$1' positional. Expanded at AST
     time by emitting the body N times in place. *)
  unroll-stmt    = <'unroll'> !ident-char <ws> <'('> <ws> expr <ws> <')'> <ws> block
  return-stmt    = <'return'> !ident-char <ws> expr?
  while-stmt     = <'while'> !ident-char <ws> <'('> <ws> expr <ws> <')'> <ws> block
  (* `for $var : start..end { body }' — range-based for loop, or
     `for $kv : @m { body }' — iterate the keys of a map. Range form
     lowers to a bounded dotimes plus a guard; map form lowers to a
     dotimes over a sidecar key-array maintained per-insert. *)
  for-stmt       = <'for'> !ident-char <ws> (<'('> <ws>)? <'$'> ident <ws> <':'> <ws>
                   for-iter (<ws> <')'>)? <ws> block
  for-iter       = expr <ws> <'..'> <ws> expr / map-access
  break-stmt     = <'break'> !ident-char
  continue-stmt  = <'continue'> !ident-char
  (* `let $var;' or `let $var = expr;' — bpftrace's local-var decl.
     For us the bare decl is a no-op (variables are inferred from
     use); the assigning form becomes a regular :assign. *)
  let-stmt       = <'let'> !ident-char <ws> <'$'> ident (<ws> <'='> <ws> expr)?
  if-stmt        = <'if'> <ws> if-cond <ws> block (<ws> <'else'> <ws> block)?
  if-cond        = <'('> <ws> expr <ws> <')'> / expr
  (* Postfix and prefix `++'/`--' both legal at statement level:
       $x++;   $x--;   ++$x;   --$x;
     We canonicalize the prefix form to a postfix shape at AST time —
     statement-level semantics are identical. *)
  assign-stmt    = lhs <ws> assign-op <ws> expr  /
                   lhs <ws> incdec-op /
                   incdec-op <ws> lhs
  expr-stmt      = expr
  lhs            = wildcard-lhs / map-access / scalar-var
  (* bpftrace's discard wildcard: `_ = expr;' evaluates expr for its
     side effects and throws the result away. Useful as `_ = { …; … };'
     to run a block expression at statement level. *)
  wildcard-lhs   = '_' !ident-char
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
  unary          = unary-op <ws> unary / prefix-incdec <ws> postfix / postfix
  (* `*EXPR' is a u64 pointer dereference — common in tools that
     read kernel global symbols, e.g. *kaddr(\"avenrun\"). *)
  unary-op       = '!' / '-' / '~' / '*'
  prefix-incdec  = '++' / '--'

  postfix        = primary postfix-tail*
  (* postfix-tail covers `.field' / `->field' / `[idx]' / `++' / `--'.
     The incdec forms are side-effecting; codegen wraps the underlying
     map / var update in `prog1' / `progn' so the surrounding expr
     sees the right value. *)
  postfix-tail   = field-access / arrow-access / index-access / postfix-incdec
  postfix-incdec = '++' / '--'
  (* `.ident' is a struct/tuple field; `.N' (digits) is tuple
     component access (`$t.0' / `$t.3.1'). Both shapes flow through
     :field at AST time — tuple-component lookup happens during
     expand-tuple-vars. *)
  field-access   = <'.'> (ident / tuple-index)
  tuple-index    = #'[0-9]+'
  arrow-access   = <'->'> ident
  index-access   = <'['> <ws> expr (<ws> <','> <ws> expr)* <ws> <']'>

  primary        = cast / enum-cast / primitive-pointer-cast / primitive-cast / block-expr / offsetof-expr / sizeof-expr / tuple / parens / func-call / map-access / scalar-var / builtin /
                   duration-literal / constant / string-lit / hex-int / integer
  (* `(enum NAME)EXPR' — cast that turns an integer into its enum
     member name at print time. Compile-time folded when EXPR is a
     literal and the value matches a member; otherwise emits a u64
     payload + enum-id so the userspace decoder can look up. *)
  enum-cast      = <'('> <ws> <'enum'> <ws> ident <ws> <')'> <ws> postfix
  (* bpftrace duration literals: `100ms', `1s', `5us', `1ns'.
     Convert to nanoseconds at parse time (`100ms' → 100_000_000).
     Must precede `constant' so `ms' / `us' / `s' / `ns' don't get
     eaten as bare identifiers. *)
  duration-literal = integer duration-unit
  duration-unit  = 'ms' / 'us' / 'ns' / 's'
  (* `{ stmt; stmt; … expr }' — bpftrace 0.22+ block expression. Each
     statement runs in order; the final unterminated expr is the
     block's value. Distinct from `block' (which produces no value
     and is used as a probe/if/while body). Placed in `primary' so
     a block expression can appear anywhere an expression can. *)
  block-expr     = <'{'> <ws> block-expr-pre* <ws> expr <ws> <'}'>
  block-expr-pre = statement <ws> <';'> <ws>
  (* offsetof(struct NAME, FIELD) — resolved to an integer constant
     at compile time via BTF. *)
  offsetof-expr  = <'offsetof'> <ws> <'('> <ws> <'struct'> <ws> ident <ws> <','> <ws> ident <ws> <')'>
  (* sizeof(struct NAME) or sizeof(TYPE) — compile-time byte size.
     We accept a struct form (BTF lookup), or a primitive-type ident
     resolved via the curated table. The `sizeof-struct' /
     `sizeof-type' alternatives let the AST normalizer dispatch on
     which one matched. *)
  sizeof-expr    = <'sizeof'> <ws> <'('> <ws> (sizeof-struct / sizeof-type / sizeof-value) <ws> <')'>
  sizeof-struct  = <'struct'> <ws> ident
  sizeof-type    = ident !ident-char
  (* sizeof(EXPR) — bpftrace accepts arbitrary expressions inside
     sizeof. Everything is u64 in our IR, so the result is just 8.
     The sub-expression isn't evaluated; we fold to a constant. *)
  sizeof-value   = expr
  (* `(e1, e2, …)' — bpftrace tuple literal. Always 2+ elements so
     it doesn't conflict with the parenthesised single expression
     form. Components must be simple (pure) — biosnoop uses them as
     composite map keys: \$key = (args.dev, args.sector). *)
  tuple          = <'('> <ws> expr (<ws> <','> <ws> expr)+ <ws> <')'>
  (* C-style struct-pointer cast: open-paren struct ident asterisk
     close-paren expr. Must precede `parens' in the alternates so the
     open-paren disambiguation tries the cast shape first. The cast
     binds to a full postfix expression so a struct-pointer cast
     followed by `.field' is parsed as `cast(args.field)' (matching
     bpftrace), not `cast(args).field'. *)
  cast           = <'('> <ws> <'struct'> <ws> ident <ws> <'*'> <ws> <')'> <ws> unary
  (* Primitive C cast: uint64 of expr, int of expr. Treated as a no-op
     since all values are u64 in our IR; preserves bpftrace
     compatibility for scripts that lean on integer narrowing. `unary'
     (not just `postfix') on the right so `(int8) -10' parses as a
     cast of `-10' rather than `(int8) - 10' (binary subtraction). *)
  primitive-cast = <'('> <ws> int-type-name <ws> <')'> <ws> unary
  (* Primitive-pointer cast: int32-star, uint64-star, etc. Distinct
     from primitive-cast because the element type is load-bearing —
     it tells the codegen how many bytes to read per element when the
     result is subscripted (`$a[i]'). *)
  primitive-pointer-cast = <'('> <ws> int-type-name <ws> <'*'> <ws> <')'> <ws> unary
  (* `bool' is a no-op alongside `int' / `uint' for cast purposes —
     all values are u64 in our IR. Accepting it matches bpftrace. *)
  int-type-name  = 'uint64' / 'uint32' / 'uint16' / 'uint8' /
                   'int64' / 'int32' / 'int16' / 'int8' /
                   'uint' / 'int' / 'bool'
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
  (* `$1', `$2', … are positional CLI parameters resolved at compile
     time from argv: `bpftrace -e SCRIPT 0 foo' makes `$1' → 0,
     `$2' → \"foo\" inside the script. We bind these to integer
     literals from the argv list (or 0 when unset). Must precede
     the regular `ident' branch since digits aren't a valid
     `ident' start anyway, but the order makes intent explicit. *)
  scalar-var     = <'$'> (positional-var / ident)
  positional-var = #'[0-9]+'

  builtin        = builtin-name !ident-char
  builtin-name   = 'pcomm' / 'ppid' / 'pid' / 'tid' / 'uid' / 'gid' / 'nsecs' / 'elapsed' /
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
