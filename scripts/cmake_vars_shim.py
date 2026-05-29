# Minimal cmake_vars shim for bpftrace's runtime test engine.
#
# bpftrace's engine imports `cmake_vars' (the CMake-rendered version of
# tests/runtime/engine/cmake_vars.py). When testing whistler we don't
# build bpftrace, so we drop this file on PYTHONPATH to satisfy the
# import without forcing a full bpftrace build first.
#
# Defaults match a generic Linux build; flip if you need to exercise
# AOT or libbpf-specific paths.

LIBBCC_BPF_CONTAINS_RUNTIME = False
HAVE_BFD_DISASM = False
BUILD_FUZZ = False
CMAKE_BUILD_TYPE = "Release"
LIBBPF_INCLUDE_DIRS = ""
HAVE_LIBPCAP = False
