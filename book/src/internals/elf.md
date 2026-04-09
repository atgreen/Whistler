# ELF Output

Whistler produces standard ELF64 little-endian relocatable object files
(`ET_REL`) with `e_machine = EM_BPF (247)`. These are compatible with
libbpf, bpftool, and the Whistler loader.

## Section layout

A typical Whistler-generated `.bpf.o` contains these sections:

| Section           | Type         | Description                        |
|-------------------|--------------|------------------------------------|
| Program sections  | `SHT_PROGBITS` | BPF bytecode (one per `defprog`)  |
| `.maps`           | `SHT_PROGBITS` | Map definitions (32 bytes each)   |
| `license`         | `SHT_PROGBITS` | License string (null-terminated)  |
| `.BTF`            | `SHT_PROGBITS` | BTF type information (if present) |
| `.BTF.ext`        | `SHT_PROGBITS` | BTF ext info (if present)         |
| `.strtab`         | `SHT_STRTAB`   | String table for symbols          |
| `.symtab`         | `SHT_SYMTAB`   | Symbol table                      |
| `.rel<section>`   | `SHT_REL`      | Relocations (one per program)     |
| `.shstrtab`       | `SHT_STRTAB`   | Section header string table       |

## Program sections

Each `defprog` produces a section named after its `:section` option (e.g.,
`xdp`, `kprobe/__x64_sys_execve`, `tracepoint/sched/sched_process_fork`).
The section contains raw BPF instructions (8 bytes each), marked
`SHF_ALLOC | SHF_EXECINSTR`.

For multi-program ELF files (e.g., tail call dispatch), each program gets
its own section and a `STT_FUNC` symbol.

## Maps section

The `.maps` section contains 32-byte entries:

| Offset | Size | Field        |
|--------|------|--------------|
| 0      | 4    | map_type     |
| 4      | 4    | key_size     |
| 8      | 4    | value_size   |
| 12     | 4    | max_entries  |
| 16     | 4    | map_flags    |
| 20     | 12   | reserved     |

Each map has a corresponding `STT_OBJECT` global symbol in `.symtab`.

## Relocations

Map references in BPF instructions use `R_BPF_64_64` relocations. Each
relocation entry is 16 bytes (`SHT_REL`, not `RELA`):

```
r_offset (8 bytes) -- byte offset of the ld_imm64 instruction
r_info   (8 bytes) -- ELF64_R_INFO(symbol_index, R_BPF_64_64)
```

The loader resolves these by patching the `ld_imm64` instruction's
`src_reg` to `BPF_PSEUDO_MAP_FD` and setting the immediate to the map FD.

## Symbol table

The symbol table contains:

1. Null symbol (index 0)
2. Section symbols (`STT_SECTION`, `STB_LOCAL`) -- one per program section
3. Map symbols (`STT_OBJECT`, `STB_GLOBAL`) -- one per map, pointing
   into `.maps`
4. Function symbols (`STT_FUNC`, `STB_GLOBAL`) -- one per program,
   named after the `defprog` name (underscored)
