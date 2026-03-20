# Whistler 0.5.4 Release Notes

## Bug fixes

- **Fix ctx-load reading from uninitialized stack spill.** When the register
  allocator spilled the ctx vreg to the stack, `emit-ctx-load-insn` loaded
  from the uninitialized spill slot instead of using R6 (where ctx was
  saved). Now uses R6 directly for all ctx-loads. (Fixes #10)

- **Prevent register allocator from evicting ctx out of R6.** The spill
  candidate selection could evict the ctx interval and reassign R6 to another
  variable. The ctx interval now has infinite lifetime and is excluded from
  spill candidates. (Fixes #10)

- **Fix jump offset corruption in peephole self-move elimination.** The
  `eliminate-redundant-movs` pass used `remove-if` to delete `mov rX, rX`
  instructions without adjusting jump offsets, causing "jump out of range"
  verifier failures in large programs. Now uses `reindex-after-deletion`.
  (Fixes #11)

- **Fix peephole coalesce-copy setting register fields on JA instructions.**
  The register rename phase replaced dst/src fields on unconditional jump
  instructions which don't use them. The BPF verifier rejects non-zero
  reserved fields with "BPF_JA uses reserved fields". (Fixes #11)
