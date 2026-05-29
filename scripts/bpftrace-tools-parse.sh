#!/usr/bin/env bash
# bpftrace-tools-parse.sh — equivalent of bpftrace's tools-parsing-test.sh.
#
# For each .bt script under BPFTRACE_TOOLS (defaults to ~/git/bpftrace/tools),
# runs `whistler bpftrace --dump SCRIPT' and reports pass/fail/skip.
#
# Skips scripts that fail because the tracepoint format files under
# /sys/kernel/tracing aren't readable (typical when not running as root) —
# those need the actual kernel to verify and are out of scope for a
# parse-only check.
#
# Exit 0 if every non-skipped script parses; non-zero otherwise.

set -u

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
WHISTLER="${WHISTLER:-$DIR/../whistler}"
TOOLS="${BPFTRACE_TOOLS:-$HOME/git/bpftrace/tools}"

if [[ ! -x "$WHISTLER" ]]; then
  echo "whistler binary not found at $WHISTLER (set WHISTLER=path or run 'make' first)" >&2
  exit 2
fi
if [[ ! -d "$TOOLS" ]]; then
  echo "bpftrace tools dir not found at $TOOLS (set BPFTRACE_TOOLS=path)" >&2
  exit 2
fi

pass=0
fail=0
skip=0
failed_names=()

while IFS= read -r -d '' script; do
  name="$(basename "$script")"
  if out=$("$WHISTLER" bpftrace --dump "$script" 2>&1); then
    printf '  ok   %s\n' "$name"
    pass=$((pass + 1))
  else
    if [[ "$out" == *"tracepoint format not found"* || \
          "$out" == *"Can't find the TRUENAME"* ]]; then
      printf '  skip %s (tracefs not readable)\n' "$name"
      skip=$((skip + 1))
    else
      printf '  FAIL %s\n' "$name"
      printf '       %s\n' "$out" | head -3
      fail=$((fail + 1))
      failed_names+=("$name")
    fi
  fi
done < <(find "$TOOLS" -maxdepth 1 -name '*.bt' -print0 | sort -z)

echo
echo "== summary: $pass passed, $fail failed, $skip skipped =="
if ((fail > 0)); then
  echo "failed: ${failed_names[*]}"
  exit 1
fi
