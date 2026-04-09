# Macros

Whistler uses standard Common Lisp `defmacro` for user-defined macros.
Full CL is available at compile time -- the compiler expands all macros
before lowering to eBPF bytecode.

## How expansion works

The compiler walks each form before compilation. If the head of a form
is a known Whistler builtin (`let`, `if`, `when`, `unless`, `and`, `or`,
`dotimes`, etc.) or a BPF helper name, it is **not** macroexpanded.
Everything else goes through `macroexpand-1` and the result is walked
recursively.

This means:

- **Whistler builtins** (`when`, `unless`, `and`, `or`, `cond`, etc.)
  are compiler primitives, not CL macros. They cannot be redefined with
  `defmacro`.
- **User macros** expand normally into primitive forms.
- **Protocol macros** (from `defheader`, `defstruct`, `deftracepoint`)
  expand normally -- they are regular CL macros.
- **setf expanders** work: `(setf (my-struct-field ptr) val)` expands
  via `defsetf`.

## Example: convenience macro

```lisp
(defmacro with-map-value ((var map key) &body body)
  "Look up a map value and execute body with VAR bound to it.
   Skips body if key is not found."
  `(when-let ((,var (map-lookup ,map ,key)))
     ,@body))

(defprog my-prog (:type :xdp :section "xdp" :license "GPL")
  (with-map-value (p counters 0)
    (atomic-add p 0 1))
  XDP_PASS)
```

## Example: code-generating macro

```lisp
(defmacro define-port-checker (name port action)
  "Generate an XDP program that acts on a specific TCP port."
  `(defprog ,name (:type :xdp :section "xdp" :license "GPL")
     (with-tcp (data data-end tcp)
       (when (= (tcp-dst-port tcp) ,port)
         (return ,action)))
     XDP_PASS))

(define-port-checker drop-9999  9999 XDP_DROP)
(define-port-checker drop-8080  8080 XDP_DROP)
```

Both `define-port-checker` invocations expand at compile time into full
`defprog` forms. The generated programs are compiled independently.

## Compile-time computation

Since macros run in full CL, you can do arbitrary computation:

```lisp
(defconstant +blocked-ports+ '(80 443 8080 9999))

(defmacro blocked-port-p (port)
  `(or ,@(mapcar (lambda (p) `(= ,port ,p)) +blocked-ports+)))

(defprog filter (:type :xdp :section "xdp" :license "GPL")
  (with-tcp (data data-end tcp)
    (when (blocked-port-p (tcp-dst-port tcp))
      (return XDP_DROP)))
  XDP_PASS)
```

The `blocked-port-p` macro generates `(or (= port 80) (= port 443) (= port 8080) (= port 9999))` at compile time. No list data structure exists at runtime.
