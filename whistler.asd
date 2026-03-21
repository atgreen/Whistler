(defsystem "whistler"
  :description "A Lisp that compiles to eBPF"
  :version "0.6.0"
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

(defsystem "whistler/loader"
  :description "Pure Common Lisp BPF loader — load .bpf.o into the kernel"
  :version "0.1.0"
  :author "Anthony Green <green@moxielogic.com>"
  :license "MIT"
  :depends-on ("whistler")
  :serial t
  :pathname "src/loader/"
  :components ((:file "packages")
               (:file "syscall")
               (:file "elf-reader")
               (:file "map")
               (:file "program")
               (:file "attach")
               (:file "ringbuf")
               (:file "loader")
               (:file "session")))

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
