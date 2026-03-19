(defsystem "whistler"
  :description "A Lisp that compiles to eBPF"
  :version "0.5.2"
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

(defsystem "whistler/tests"
  :description "Whistler test suite"
  :depends-on ("whistler" "fiveam")
  :serial t
  :pathname "tests/"
  :components ((:file "package")
               (:file "suite")
               (:file "test-memory")
               (:file "test-atomics")
               (:file "test-alu")
               (:file "test-branch")
               (:file "test-compile")
               (:file "test-byteswap")
               (:file "test-controlflow")
               (:file "test-protocol")
               (:file "test-optimization")
               (:file "test-maps")
               (:file "test-programs")))
