# Inline Assembly

The `asm` form emits a single raw BPF instruction. It is an escape hatch
for cases where Whistler does not yet have a dedicated form for a
particular BPF operation.

## Syntax

```lisp
(asm opcode dst-reg src-reg offset immediate)
```

All arguments are integer constants corresponding to BPF instruction
fields:

| Field | Size | Description |
|-------|------|-------------|
| `opcode` | 8-bit | BPF opcode (e.g., `#x85` for call) |
| `dst-reg` | 4-bit | Destination register (0--10) |
| `src-reg` | 4-bit | Source register (0--10) |
| `offset` | 16-bit signed | Offset field |
| `immediate` | 32-bit signed | Immediate value |

## Example

```lisp
;; Emit a raw BPF_CALL instruction for helper #5 (ktime_get_ns)
(asm #x85 0 0 0 5)
```

Use this sparingly. Prefer Whistler's typed forms (`load`, `store`,
helper calls by name) whenever possible -- they provide type safety,
register allocation, and verifier-friendly patterns that raw assembly
does not.
