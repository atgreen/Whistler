SBCL ?= sbcl
SBCL_FLAGS = --noinform --non-interactive

.PHONY: all test test-torture check clean examples repl repl-loader

all: whistler

# Build standalone binary. The program-op is on whistler/cli (which
# pulls in whistler + whistler/loader + symbolize + bpftrace); the
# bare "whistler" system has no :build-operation and would just load
# without producing an executable.
whistler: whistler.asd $(wildcard src/*.lisp) $(wildcard src/loader/*.lisp) $(wildcard src/symbolize/*.lisp) $(wildcard src/bpftrace/*.lisp)
	$(SBCL) $(SBCL_FLAGS) \
		--eval '(require :asdf)' \
		--eval '(push #p"./" asdf:*central-registry*)' \
		--eval '(asdf:make "whistler/cli")'

# Compile examples
examples: all
	./whistler compile examples/count-xdp.lisp -o examples/count-xdp.bpf.o

# Run all tests
test:
	$(SBCL) $(SBCL_FLAGS) \
		--eval '(require :asdf)' \
		--eval '(push #p"./" asdf:*central-registry*)' \
		--eval '(asdf:load-system "whistler/tests")' \
		--eval '(unless (whistler/tests:run-tests) (uiop:quit 1))'

# Run torture tests with kernel verification (requires sudo for CAP_BPF)
test-torture:
	sudo env PATH="$(PATH)" $(SBCL) $(SBCL_FLAGS) \
		--eval '(require :asdf)' \
		--eval '(push #p"./" asdf:*central-registry*)' \
		--eval '(asdf:load-system "whistler/tests")' \
		--eval '(unless (fiveam:run! (quote whistler/tests::torture-suite)) (uiop:quit 1))'

check: test

# Interactive REPL with whistler loaded
repl:
	$(SBCL) --noinform \
		--eval '(require :asdf)' \
		--eval '(push #p"./" asdf:*central-registry*)' \
		--eval '(asdf:load-system "whistler")' \
		--eval '(in-package #:whistler-user)'

# Interactive REPL with compiler and loader loaded
repl-loader:
	$(SBCL) --noinform \
		--eval '(require :asdf)' \
		--eval '(push #p"./" asdf:*central-registry*)' \
		--eval '(asdf:load-system "whistler/loader")' \
		--eval '(in-package #:whistler-loader-user)'

clean:
	rm -f whistler
	rm -f examples/*.bpf.o
	rm -f *.fasl
