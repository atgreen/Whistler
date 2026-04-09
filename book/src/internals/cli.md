# CLI Reference

Whistler ships as a standalone binary (a saved SBCL image).

## Commands

### Version

```
whistler --version
```

Print the Whistler version string.

### Help

```
whistler --help
```

Show usage information and available commands.

### Compile

```
whistler compile INPUT [-o OUTPUT] [--gen LANG...]
```

Compile a Whistler source file to a BPF ELF object.

| Option       | Description                                    |
|--------------|------------------------------------------------|
| `INPUT`      | Path to `.lisp` source file                    |
| `-o OUTPUT`  | Output path (default: input with `.bpf.o` ext) |
| `--gen LANG` | Generate shared headers: `c`, `go`, `rust`, `python`, `lisp`, `all` |

Examples:

```bash
# Compile to BPF object
whistler compile my-prog.lisp -o my-prog.bpf.o

# Compile and generate C + Go headers
whistler compile my-prog.lisp -o my-prog.bpf.o --gen c go

# Compile and generate all language bindings
whistler compile my-prog.lisp --gen all
```

### Disassemble

```
whistler disasm INPUT
```

Disassemble a compiled BPF ELF object file, printing the BPF instructions
in human-readable form.

```bash
whistler disasm my-prog.bpf.o
```
