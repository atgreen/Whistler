# Map Operations

The loader provides userspace access to BPF maps via the bpf(2) syscall.
The low-level API works with raw byte arrays, with integer helpers for the
common scalar case.

## Core operations

```lisp
(map-lookup map-info key-bytes)
(map-lookup-int map-info key)
```

Returns the value as a byte array, or `nil` if the key is not found. For
percpu maps, returns a vector of per-CPU byte arrays. `map-lookup-int`
encodes the key and decodes the value as little-endian integers.

```lisp
(map-update map-info key-bytes value-bytes)
(map-update map-info key-bytes value-bytes :flags +bpf-noexist+)
(map-update-int map-info key value)
(map-update-struct map-info key-bytes record 'my-struct)
(map-update-struct-int map-info key record 'my-struct)
```

Insert or update a key/value pair. For percpu maps, `value-bytes` can be
a single byte array (replicated to all CPUs) or a vector of per-CPU arrays.
`map-update-int` does the integer encoding for fixed-size scalar maps.

```lisp
(map-delete map-info key-bytes)
(map-delete-int map-info key)
(map-delete-struct map-info record 'my-struct)
```

Delete a key from the map.

```lisp
(map-get-next-key map-info key-bytes)
(map-get-next-key-int map-info &optional key)
(map-get-next-key-struct map-info 'my-struct &optional key-record)
```

Returns the next key after `key-bytes`, or `nil` when iteration is
complete. Pass `nil` as the key to get the first key. The typed variants
decode integer and struct keys for you.

## Encoding helpers

```lisp
(encode-int-key 42 4)       ;; -> #(42 0 0 0)  (4-byte LE)
(decode-int-value #(10 0 0 0 0 0 0 0))  ;; -> 10
```

`encode-int-key` encodes an integer as a little-endian byte array of the
given size. `decode-int-value` decodes a little-endian byte array back
to an integer.

## Struct-valued maps

When a map value matches a `defstruct` layout, use the generated codecs
through the typed helpers:

```lisp
(defstruct stats-entry
  (packets u64)
  (drops   u64))

(let ((rec (make-stats-entry-record :packets 10 :drops 2)))
  (map-update-struct-int stats-map 0 rec 'stats-entry))

(let ((rec (map-lookup-struct-int stats-map 0 'stats-entry)))
  (when rec
    (format t "packets=~d drops=~d~%"
            (stats-entry-record-packets rec)
            (stats-entry-record-drops rec))))
```

The struct symbol determines which `encode-*` / `decode-*` functions are used.

The same approach works for struct keys:

```lisp
(defstruct flow-key
  (src u32)
  (dst u32))

(let ((key (make-flow-key-record :src #x0a000001 :dst #x0a000002)))
  (map-delete-struct flows key 'flow-key))
```

## Iteration example

Walk all entries in a hash map:

```lisp
(let ((key nil))
  (loop
    (let ((next (map-get-next-key my-map key)))
      (unless next (return))
      (let ((val (map-lookup my-map next)))
        (when val
          (format t "~d -> ~d~%"
                  (decode-int-value next)
                  (decode-int-value val))))
      (setf key next))))
```

Typed key iteration is simpler when the key is scalar or structured:

```lisp
(let ((key nil))
  (loop
    (setf key (map-get-next-key-int stats-map key))
    (unless key (return))
    (format t "next key: ~d~%" key)))

(let ((key nil))
  (loop
    (setf key (map-get-next-key-struct flows 'flow-key key))
    (unless key (return))
    (format t "~x -> ~x~%"
            (flow-key-record-src key)
            (flow-key-record-dst key))))
```

## Percpu maps

For `percpu-hash` and `percpu-array` maps, `map-lookup` returns a vector
of byte arrays (one per possible CPU). Each slot is 8-byte aligned as
required by the kernel:

```lisp
(let ((values (map-lookup percpu-map (encode-int-key 0 4))))
  (when values
    (dotimes (cpu (length values))
      (format t "CPU ~d: ~d~%" cpu (decode-int-value (aref values cpu))))))
```
