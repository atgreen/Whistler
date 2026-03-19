SBCL ?= sbcl
SBCL_FLAGS = --noinform --non-interactive

.PHONY: all test test-5am clean examples repl

all: whistler

# Build standalone binary
whistler: whistler.asd $(wildcard src/*.lisp)
	$(SBCL) $(SBCL_FLAGS) \
		--eval '(require :asdf)' \
		--eval '(push #p"./" asdf:*central-registry*)' \
		--eval '(asdf:make "whistler")'

# Compile examples
examples: all
	./whistler compile examples/count-xdp.lisp -o examples/count-xdp.bpf.o

# Run tests
test:
	$(SBCL) $(SBCL_FLAGS) \
		--eval '(require :asdf)' \
		--eval '(push #p"./" asdf:*central-registry*)' \
		--eval '(asdf:load-system "whistler")' \
		--load tests/test.lisp

# Run FiveAM test suite
test-5am:
	$(SBCL) $(SBCL_FLAGS) \
		--eval '(require :asdf)' \
		--eval '(push #p"./" asdf:*central-registry*)' \
		--eval '(asdf:load-system "whistler/tests")' \
		--eval '(unless (whistler/tests:run-tests) (uiop:quit 1))'

# Interactive REPL with whistler loaded
repl:
	$(SBCL) --noinform \
		--eval '(require :asdf)' \
		--eval '(push #p"./" asdf:*central-registry*)' \
		--eval '(asdf:load-system "whistler")' \
		--eval '(in-package #:whistler)'

clean:
	rm -f whistler
	rm -f examples/*.bpf.o
	rm -f *.fasl
