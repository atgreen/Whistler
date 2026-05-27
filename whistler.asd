(defsystem "whistler"
  :description "A Lisp that compiles to eBPF"
  :version "1.9.0"
  :author "Anthony Green <green@moxielogic.com>"
  :license "MIT"
  :depends-on ()
  :in-order-to ((test-op (test-op "whistler/tests")))
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
               (:file "sccp")
               (:file "regalloc")
               (:file "emit")
               (:file "peephole")
               (:file "whistler")
               (:file "protocols")
               (:file "vmlinux")
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

(defsystem "whistler/cli"
  :description "CLI binary — bundles whistler + loader + bpftrace into one self-contained executable"
  :version "1.9.0"
  :author "Anthony Green <green@moxielogic.com>"
  :license "MIT"
  :depends-on ("whistler" "whistler/loader"
               "whistler/symbolize" "whistler/bpftrace")
  :build-operation "program-op"
  :build-pathname "whistler"
  :entry-point "whistler:main"
  :components ())

(defsystem "whistler/symbolize"
  :description "Standalone /proc/<pid>/maps + ELF symbolizer for user-stack resolution"
  :version "0.1.0"
  :author "Anthony Green <green@moxielogic.com>"
  :license "MIT"
  :depends-on ()
  :serial t
  :pathname "src/symbolize/"
  :components ((:file "packages")
               (:file "maps")
               (:file "elf")
               (:file "dwarf")
               (:file "cache")
               (:file "symbolize")))

(defsystem "whistler/bpftrace"
  :description "bpftrace frontend — parses bpftrace scripts and compiles them via Whistler"
  :version "0.1.0"
  :author "Anthony Green <green@moxielogic.com>"
  :license "MIT"
  :depends-on ("whistler" "whistler/loader" "whistler/symbolize" "iparse")
  :serial t
  :pathname "src/bpftrace/"
  :components ((:file "packages")
               (:file "grammar")
               (:file "ast")
               (:file "codegen")
               (:file "runtime")
               (:file "bpftrace")))

(defsystem "whistler/tests"
  :description "Whistler test suite"
  :depends-on ("whistler" "whistler/loader" "whistler/symbolize"
               "whistler/bpftrace" "fiveam")
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
               (:file "test-percpu")
               (:file "test-programs")
               (:file "test-regalloc")
               (:file "test-torture")
               (:file "test-bpftrace")
               (:file "test-symbolize")))
