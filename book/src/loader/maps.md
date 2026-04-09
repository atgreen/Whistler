# Map Operations

The loader provides userspace access to BPF maps via the bpf(2) syscall.
All operations work with raw byte arrays.

## Core operations

```lisp
(map-lookup map-info key-bytes)
```

Returns the value as a byte array, or `nil` if the key is not found. For
percpu maps, returns a vector of per-CPU byte arrays.

```lisp
(map-update map-info key-bytes value-bytes)
(map-update map-info key-bytes value-bytes :flags +bpf-noexist+)
```

Insert or update a key/value pair. For percpu maps, `value-bytes` can be
a single byte array (replicated to all CPUs) or a vector of per-CPU arrays.

```lisp
(map-delete map-info key-bytes)
```

Delete a key from the map.

```lisp
(map-get-next-key map-info key-bytes)
```

Returns the next key after `key-bytes`, or `nil` when iteration is
complete. Pass `nil` as the key to get the first key.

## Encoding helpers

```lisp
(encode-int-key 42 4)       ;; -> #(42 0 0 0)  (4-byte LE)
(decode-int-value #(10 0 0 0 0 0 0 0))  ;; -> 10
```

`encode-int-key` encodes an integer as a little-endian byte array of the
given size. `decode-int-value` decodes a little-endian byte array back
to an integer.

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
