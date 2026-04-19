#!/bin/bash
# Verify cgroup-firewall.lisp passes the kernel BPF verifier.
# Usage: ./examples/verify-cgroup-firewall.sh
#
# Compiles the example, then loads it with sudo to run the BPF verifier.
# Does not attach to any cgroup — safe to run without affecting traffic.

set -e

cd "$(dirname "$0")/.."

BPF_OBJ=$(mktemp --suffix=.bpf.o)
trap 'rm -f "$BPF_OBJ"' EXIT

./whistler compile examples/cgroup-firewall.lisp -o "$BPF_OBJ"

sudo sbcl --noinform --non-interactive \
  --eval '(require :asdf)' \
  --eval "(push #p\"$(pwd)/\" asdf:*central-registry*)" \
  --eval '(asdf:load-system "whistler/loader")' \
  --eval "(whistler/loader:with-bpf-object (obj \"$BPF_OBJ\")
           (format t \"Loaded successfully — verifier passed for all 3 programs~%\"))"
