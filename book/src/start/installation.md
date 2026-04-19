# Installation

## Requirements

- **SBCL** (Steel Bank Common Lisp) 2.0 or later.
  Install from [sbcl.org](http://www.sbcl.org/) or your distribution's
  package manager (`dnf install sbcl`, `apt install sbcl`).
- **Linux kernel 5.3+** for bounded loop support in the BPF verifier.
  Kernel 5.8+ is recommended for ring buffer maps and BTF support.
- **FiveAM** is required only for running the test suite.

```admonish info
Whistler has zero non-Lisp dependencies. No LLVM, no libelf, no kernel
headers.
```

## Loading the compiler

Clone the repository and load the system with ASDF:

```bash
git clone https://github.com/atgreen/whistler.git
cd whistler
```

From an SBCL REPL:

```lisp
(require :asdf)
(push #p"/path/to/whistler/" asdf:*central-registry*)
(asdf:load-system "whistler")
(in-package #:whistler-user)
```

Or use the Makefile to start a REPL with Whistler already loaded:

```bash
make repl
```

This drops you into the `whistler-user` package, ready to define maps and
programs.

## Loading the userspace loader

The loader is a separate ASDF system that depends on the compiler:

```lisp
(asdf:load-system "whistler/loader")
(in-package #:whistler-loader-user)
```

This gives you `with-bpf-session`, `with-bpf-object`, ring buffer
consumers, and map accessors -- all in pure Common Lisp.

Or use the Makefile:

```bash
make repl-loader
```

This is the most convenient day-to-day workflow for Lisp development:
compiler, loader, and REPL in one image.

## Building the CLI binary

Whistler can be built as a standalone command-line binary using ASDF's
`program-op`:

```bash
make
```

This produces a `whistler` executable in the repository root. The Makefile
runs:

```bash
sbcl --noinform --non-interactive \
  --eval '(require :asdf)' \
  --eval '(push #p"./" asdf:*central-registry*)' \
  --eval '(asdf:make "whistler")'
```

The `whistler.asd` system definition specifies `:build-operation "program-op"`
and `:entry-point "whistler:main"`, so `asdf:make` produces a self-contained
binary.

Use it to compile BPF source files from the shell:

```bash
./whistler compile examples/count-xdp.lisp -o count.bpf.o
```

Check your local environment before trying to load programs:

```bash
./whistler doctor
```

This reports the local kernel version, tool availability, tracefs/BTF
readability, and any obvious missing capabilities.

## Running the test suite

Tests require [FiveAM](https://github.com/lispci/fiveam):

```bash
make test
```

Or from a REPL:

```lisp
(asdf:test-system "whistler")
```

The test suite covers ALU operations, memory access, branching, control flow,
protocol parsing, map operations, register allocation, and end-to-end
compilation.
