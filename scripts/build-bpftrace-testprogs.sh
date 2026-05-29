#!/usr/bin/env bash
# build-bpftrace-testprogs.sh — compile bpftrace's tests/testprogs/ C
# binaries without going through bpftrace's full CMake build.
#
# bpftrace's runtime tests spawn small C "victim" binaries via `-c
# ./testprogs/NAME' so the script under test has something real to
# attach uprobes to. The bpftrace CMake target builds them; we don't
# want to pull in LLVM/libbpf just to get these, so we compile them
# directly with gcc/g++.
#
# Built in-place under $BPFTRACE_SRC/tests/testprogs/ (matching where
# the engine expects them via the test's relative `-c' path). Each
# program is built non-PIE and PIE (-pie suffix), mirroring the CMake
# build's testprog_compile(FALSE) / testprog_compile(TRUE) pair.
#
# Skipped (would need extra toolchains/recipes — corresponding tests
# will fail individually if relied on):
#   * .go / .rs sources           (no go/rustc assumed)
#   * false.bin                   (llvm-objcopy flat binary)
#   * archive.zip                 (zip of `true' binary)
#   * uprobe_test-stripped, etc.  (objcopy --strip-debug)
#   * *-split{,.dwp}              (split DWARF)
#
# Per-testprog failures don't abort the script — we want as many
# binaries in place as possible so the engine can run the maximum
# number of tests.

set -u

BPFTRACE_SRC="${BPFTRACE_SRC:-$HOME/git/bpftrace}"
TP_DIR="$BPFTRACE_SRC/tests/testprogs"
LIB_DIR="$BPFTRACE_SRC/tests/testlibs"
INC_DIR="$BPFTRACE_SRC/tests/include"

if [[ ! -d "$TP_DIR" ]]; then
  echo "testprogs dir not found: $TP_DIR" >&2
  echo "set BPFTRACE_SRC=path-to-bpftrace-checkout" >&2
  exit 2
fi

# Idempotency check: if uprobe_test (and its -pie pair) already exist
# and are newer than every source, every Makefile invocation would
# otherwise re-compile 108 binaries. Skip the whole script in that
# case. This matters most under `sudo make bpftrace-runtime-test',
# where the unprivileged build was already done — we don't want to
# rebuild as root and leave root-owned binaries in $TP_DIR.
newest_src=$(ls -t "$TP_DIR"/*.c "$TP_DIR"/*.cpp 2>/dev/null | head -1)
if [[ -x "$TP_DIR/uprobe_test" && -x "$TP_DIR/uprobe_test-pie" \
      && -n "$newest_src" && "$TP_DIR/uprobe_test" -nt "$newest_src" ]]; then
  echo "== testprogs: already built (newer than sources), skipping =="
  exit 0
fi

CC="${CC:-gcc}"
CXX="${CXX:-g++}"
# -pthread + -D_GNU_SOURCE are globally safe and required by the few
# testprogs (multi_threads, watchpoint_threaded) that pull in pthread
# and use the GNU pthread_setname_np extension. Adding everywhere
# spares us per-file detection.
COMMON_CFLAGS=(-g -O0 -fno-omit-frame-pointer -D_GNU_SOURCE -I"$INC_DIR")
COMMON_LDFLAGS=(-pthread)
# Match the special-case from bpftrace's CMake: uprobe_nofp validates
# DWARF-based unwinding without frame pointers.
NOFP_CFLAGS=(-g -O1 -fomit-frame-pointer -fno-optimize-sibling-calls -D_GNU_SOURCE -I"$INC_DIR")

built=0
skipped=0
failed=0

# Step 1: testlibs (shared objects used by usdt_lib etc).
if [[ -d "$LIB_DIR" ]]; then
  for src in "$LIB_DIR"/*.c "$LIB_DIR"/*.cpp; do
    [[ -e "$src" ]] || continue
    base="$(basename "$src")"
    name="${base%.*}"
    out="$TP_DIR/lib${name}.so"
    if [[ "$src" == *.cpp ]]; then
      compiler="$CXX"
    else
      compiler="$CC"
    fi
    if "$compiler" -shared -fPIC "${COMMON_CFLAGS[@]}" "$src" -o "$out" 2>/dev/null; then
      chmod -x "$out"
      built=$((built + 1))
    else
      printf '  fail lib%s.so\n' "$name" >&2
      failed=$((failed + 1))
    fi
  done
fi

compile_one() {
  local src="$1" out="$2" pie="$3"
  local base
  base="$(basename "$src")"
  local cflags=("${COMMON_CFLAGS[@]}")
  if [[ "$base" == "uprobe_nofp.c" ]]; then
    cflags=("${NOFP_CFLAGS[@]}")
  fi
  local pieflag=(-no-pie)
  if [[ "$pie" == "1" ]]; then
    pieflag=(-fpie -pie)
  fi
  local compiler="$CC"
  [[ "$src" == *.cpp ]] && compiler="$CXX"

  # usdt_lib links against testlibs/usdt_tp; that's a shared lib we
  # already built into $TP_DIR.
  local extra_ld=()
  if [[ "$base" == usdt_lib* ]]; then
    extra_ld=(-L"$TP_DIR" -Wl,-rpath,"$TP_DIR" -lusdt_tp -fPIC -I"$LIB_DIR")
  fi

  if "$compiler" "${cflags[@]}" "${pieflag[@]}" "$src" "${extra_ld[@]}" "${COMMON_LDFLAGS[@]}" -o "$out" 2>/dev/null; then
    return 0
  fi
  return 1
}

# Step 2: testprogs (non-PIE + PIE pair per source).
for src in "$TP_DIR"/*.c "$TP_DIR"/*.cpp; do
  [[ -e "$src" ]] || continue
  base="$(basename "$src")"
  name="${base%.*}"

  if compile_one "$src" "$TP_DIR/$name" 0; then
    built=$((built + 1))
  else
    printf '  fail %s\n' "$name" >&2
    failed=$((failed + 1))
  fi
  if compile_one "$src" "$TP_DIR/${name}-pie" 1; then
    built=$((built + 1))
  else
    printf '  fail %s-pie\n' "$name" >&2
    failed=$((failed + 1))
  fi
done

# Step 3: skipped — log what runtime tests using these will fail on.
for special in hello_go.go hello_rust.rs; do
  [[ -e "$TP_DIR/$special" ]] && skipped=$((skipped + 1))
done
for special in false.bin archive.zip uprobe_test-stripped uprobe_separate_debug-stripped; do
  skipped=$((skipped + 1))
done

echo "== testprogs: $built built, $failed failed, $skipped skipped (special recipes) =="
exit 0
