#!/usr/bin/env bash
# bench.sh — compare Whistler vs clang -O2 BPF instruction counts.
#
# For each benchmark in benchmarks/manifest.txt, compile the Whistler .lisp and
# the equivalent clang .c, count instructions in the program's ELF section
# (each BPF insn is 8 bytes), print a table, and compare the Whistler count to
# its committed baseline. Exits non-zero on a Whistler regression (count above
# baseline), so `make bench` guards the clang-parity goal.
#
# clang is optional: if absent, the clang column shows "-" and only the
# Whistler-vs-baseline check runs. Env: SBCL (default /usr/bin/sbcl), CLANG.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SBCL="${SBCL:-/usr/bin/sbcl}"
CLANG="${CLANG:-clang}"
MANIFEST="${MANIFEST:-$ROOT/benchmarks/manifest.txt}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Pick a readelf that groks BPF objects.
READELF=""
for c in llvm-readelf readelf; do command -v "$c" >/dev/null 2>&1 && { READELF="$c"; break; }; done
[ -n "$READELF" ] || { echo "error: need llvm-readelf or readelf on PATH" >&2; exit 2; }

have_clang=1
command -v "$CLANG" >/dev/null 2>&1 || have_clang=0

# section_bytes <obj> <section-name> → size in bytes (0 if absent).
# In `readelf -S`, a one-token section name sits in field 3 and its size
# (hex) in field 7:  [ 3] xdp  PROGBITS  <addr> <off> <size> ...
section_bytes() {
  local hex
  hex="$("$READELF" -S "$1" 2>/dev/null | awk -v s="$2" '$3==s {print $7; exit}')"
  [ -n "$hex" ] && printf '%d\n' "$((16#$hex))" || echo 0
}

# whistler_count <name> <section>
whistler_count() {
  local name="$1" section="$2" obj="$TMP/$1.w.o"
  "$SBCL" --noinform --non-interactive \
    --eval '(require :asdf)' \
    --eval "(push #P\"$ROOT/\" asdf:*central-registry*)" \
    --eval '(asdf:load-system "whistler")' \
    --eval "(whistler::compile-file* \"$ROOT/examples/$name.lisp\" \"$obj\")" \
    >/dev/null 2>&1
  local bytes; bytes="$(section_bytes "$obj" "$section")"
  echo $(( bytes / 8 ))
}

# clang_count <name> <section>
clang_count() {
  local name="$1" section="$2" obj="$TMP/$1.c.o"
  "$CLANG" -O2 -target bpf -c "$ROOT/examples/$name.c" -o "$obj" >/dev/null 2>&1 || { echo "-"; return; }
  local bytes; bytes="$(section_bytes "$obj" "$section")"
  echo $(( bytes / 8 ))
}

printf '%-16s %10s %10s %8s %8s   %s\n' "benchmark" "whistler" "clang" "delta" "base" "status"
printf '%-16s %10s %10s %8s %8s   %s\n' "---------" "--------" "-----" "-----" "----" "------"

fail=0
while read -r name section wbase cbase; do
  case "$name" in ''|\#*) continue;; esac

  w="$(whistler_count "$name" "$section")"
  if [ "$have_clang" -eq 1 ] && [ -f "$ROOT/examples/$name.c" ]; then
    c="$(clang_count "$name" "$section")"
  else
    c="-"
  fi

  # delta vs clang (informational), status vs Whistler baseline (gating).
  if [ "$c" != "-" ]; then delta=$(( w - c )); else delta="-"; fi

  status="ok"
  if [ "$w" -gt "$wbase" ]; then status="REGRESSION (>$wbase)"; fail=1
  elif [ "$w" -lt "$wbase" ]; then status="improved (<$wbase — update baseline)"; fi

  printf '%-16s %10s %10s %8s %8s   %s\n' "$name" "$w" "$c" "$delta" "$wbase" "$status"
done < "$MANIFEST"

echo
if [ "$fail" -ne 0 ]; then
  echo "FAIL: a Whistler instruction count regressed above its baseline." >&2
  exit 1
fi
echo "OK: all Whistler counts within baseline."
