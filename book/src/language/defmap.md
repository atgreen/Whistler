# defmap

`defmap` declares a BPF map that can be shared between BPF programs and
userspace.

## Syntax

```lisp
(defmap name :type TYPE
  [:key-size N] [:value-size N]
  :max-entries N
  [:map-flags FLAGS])
```

**Required** arguments are `:type` and `:max-entries`. The `:key-size` and
`:value-size` arguments are required for most map types but omitted for ring
buffers. `:map-flags` is optional and defaults to 0.

## Map Types

Whistler supports the following map types:

| Keyword | BPF Map Type | Notes |
|---------|-------------|-------|
| `:hash` | `BPF_MAP_TYPE_HASH` | Generic hash table |
| `:array` | `BPF_MAP_TYPE_ARRAY` | Fixed-size array, integer keys |
| `:percpu-hash` | `BPF_MAP_TYPE_PERCPU_HASH` | Per-CPU hash table |
| `:percpu-array` | `BPF_MAP_TYPE_PERCPU_ARRAY` | Per-CPU array |
| `:ringbuf` | `BPF_MAP_TYPE_RINGBUF` | Ring buffer (key/value sizes omitted) |
| `:prog-array` | `BPF_MAP_TYPE_PROG_ARRAY` | Array of program file descriptors for tail calls |
| `:lpm-trie` | `BPF_MAP_TYPE_LPM_TRIE` | Longest-prefix-match trie |
| `:lru-hash` | `BPF_MAP_TYPE_LRU_HASH` | LRU-evicting hash table |

## Examples

### Hash map

```lisp
(defmap connection-table :type :hash
  :key-size 16
  :value-size 8
  :max-entries 1024)
```

### Array map

```lisp
(defmap counters :type :array
  :key-size 4
  :value-size 8
  :max-entries 256)
```

### Per-CPU hash

```lisp
(defmap per-cpu-cache :type :percpu-hash
  :key-size 4
  :value-size 64
  :max-entries 512)
```

### Per-CPU array

```lisp
(defmap per-cpu-stats :type :percpu-array
  :key-size 4
  :value-size 32
  :max-entries 16)
```

### Ring buffer

Ring buffer maps only require `:type` and `:max-entries`. The
`:max-entries` value must be a power of two and specifies the buffer size in
bytes.

```lisp
(defmap events :type :ringbuf
  :max-entries (* 256 1024))
```

### Program array (for tail calls)

```lisp
(defmap dispatch :type :prog-array
  :key-size 4
  :value-size 4
  :max-entries 8)
```

### LPM trie

LPM trie maps require the `BPF_F_NO_PREALLOC` flag (value 1).

```lisp
(defmap routes :type :lpm-trie
  :key-size 8
  :value-size 4
  :max-entries 1024
  :map-flags 1)
```

### LRU hash

```lisp
(defmap recent-flows :type :lru-hash
  :key-size 16
  :value-size 8
  :max-entries 4096)
```
