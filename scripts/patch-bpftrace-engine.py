#!/usr/bin/env python3
"""Patch the staged bpftrace runtime-test engine to skip-and-continue
when a `-c` testprog binary is missing on disk, instead of letting
FileNotFoundError bubble out of subprocess.Popen and crash the whole
suite at the first unbuilt testprog. We compile most testprogs in
build-bpftrace-testprogs.sh, but a handful (split DWARF, llvm-objcopy
flat binaries, Go/Rust sources) aren't trivial to reproduce — those
tests should skip cleanly rather than abort the run.

Run after staging the engine into BUILD_DIR via cp; this file is a
no-op if the marker is already present (idempotent for repeated
make invocations)."""

import sys
from pathlib import Path

MARKER = "# WHISTLER-PATCH: skip FileNotFoundError"
NEEDLE = "status = Runner.run_test(test)"
REPLACEMENT = """try:
                status = Runner.run_test(test)
            except FileNotFoundError as exc:
                # WHISTLER-PATCH: skip FileNotFoundError
                missing = exc.filename or str(exc)
                print("\\033[33m[   SKIP   ]\\033[0m %s.%s (testprog not built: %s)" %
                      (fname, test.name, missing))
                continue"""


def main(build_dir):
    main_py = Path(build_dir) / "main.py"
    src = main_py.read_text()
    if MARKER in src:
        return 0
    if NEEDLE not in src:
        print(f"patch-bpftrace-engine: needle not found in {main_py}", file=sys.stderr)
        return 1
    main_py.write_text(src.replace(NEEDLE, REPLACEMENT, 1))
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: patch-bpftrace-engine.py BUILD_DIR", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
