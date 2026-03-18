(defsystem "whistler"
  :description "A Lisp that compiles to eBPF"
  :version "0.3.0"
  :author "Anthony Green <green@moxielogic.com>"
  :license "MIT"
  :depends-on ("version-string")
  :build-operation "program-op"
  :build-pathname "../whistler"
  :entry-point "whistler:main"
  :serial t
  :pathname "src/"
  :components ((:file "packages")
               (:file "bpf")
               (:file "elf")
               (:file "btf")
               (:file "compiler")
               (:file "ir")
               (:file "lower")
               (:file "ssa-opt")
               (:file "regalloc")
               (:file "emit")
               (:file "peephole")
               (:file "whistler")
               (:file "protocols")
               (:file "codegen")))
