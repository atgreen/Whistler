# Shared Header Generation

When compiling BPF programs, you often need matching struct definitions on
both sides: the BPF program (Whistler) and the userspace consumer (C, Go,
Rust, Python, or Common Lisp). Whistler generates these automatically.

## CLI usage

```
whistler compile input.lisp -o output.bpf.o --gen c
whistler compile input.lisp -o output.bpf.o --gen go
whistler compile input.lisp -o output.bpf.o --gen rust
whistler compile input.lisp -o output.bpf.o --gen python
whistler compile input.lisp -o output.bpf.o --gen lisp
whistler compile input.lisp -o output.bpf.o --gen all
```

The `--gen` flag accepts one or more target languages. `all` generates
every supported format.

## Output files

Given output base name `foo`, Whistler produces:

| Flag     | File              | Contents                           |
|----------|-------------------|------------------------------------|
| `c`      | `foo.h`           | C header with `#include <stdint.h>` |
| `go`     | `foo_types.go`    | Go struct and const definitions     |
| `rust`   | `foo_types.rs`    | Rust `#[repr(C)]` structs           |
| `python` | `foo_types.py`    | Python ctypes structures             |
| `lisp`   | `foo_types.lisp`  | CL defstruct + byte codec           |

## What gets generated

### Struct definitions

Every `defstruct` in the source file produces a matching struct in each
target language. Array fields use the language's native array syntax:

```lisp
;; Whistler source
(defstruct conn-event
  (src-addr u32)
  (dst-addr u32)
  (port     u16)
  (comm     (array u8 16)))
```

```c
// C output
struct conn_event {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t port;
    uint8_t comm[16];
};
```

```go
// Go output
type ConnEvent struct {
	SrcAddr uint32
	DstAddr uint32
	Port    uint16
	Comm    [16]uint8
}
```

```rust
// Rust output
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ConnEvent {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub port: u16,
    pub comm: [u8; 16],
}
unsafe impl aya::Pod for ConnEvent {}
```

```python
# Python output
class ConnEvent(ctypes.LittleEndianStructure):
    _fields_ = [
        ("src_addr", ctypes.c_uint32),
        ("dst_addr", ctypes.c_uint32),
        ("port", ctypes.c_uint16),
        ("comm", ctypes.c_uint8 * 16)
    ]
```

### Constants

`defconstant` values defined in the source file are included in the
generated headers:

```lisp
(defconstant +event-type-tcp+ 1)
```

```c
#define EVENT_TYPE_TCP 1
```

### CL codec

The Common Lisp output includes `defstruct` with typed slots plus
`NAME-from-bytes` and `NAME-to-bytes` functions for BPF map interop.
These decode/encode structs from/to raw byte arrays.

## Layout guarantee

All generated structs are guaranteed to match the BPF-side memory layout.
Whistler computes field offsets at compile time and generates code that
uses the same byte positions, so there is no alignment mismatch between
the kernel and userspace sides.
