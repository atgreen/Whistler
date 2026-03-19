# Whistler 0.4.1 Release Notes

## Improvements

- **Restore map FD caching with control-flow safety.** Map file
  descriptor caching in callee-saved registers is re-enabled, replacing
  2-instruction `ld_pseudo` sequences with 1-instruction `mov` for
  repeated map references. The cache now uses dominator analysis to
  ensure a cached register is only reused when the caching block
  dominates the current block, preventing use of uninitialized
  registers on paths that bypass the first map reference.
