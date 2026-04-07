;;; map.lisp — BPF map creation and operations
;;;
;;; SPDX-License-Identifier: MIT

(in-package #:whistler/loader)

;;; ========== Map info ==========

(defstruct map-info
  name type key-size value-size max-entries flags (fd -1))

;;; ========== Map creation ==========

(defun create-map (info)
  "Create a BPF map. Stores the fd in the map-info and returns it."
  (let ((buf (make-attr-buf)))
    (put-u32 buf 0 (map-info-type info))
    (put-u32 buf 4 (map-info-key-size info))
    (put-u32 buf 8 (map-info-value-size info))
    (put-u32 buf 12 (map-info-max-entries info))
    (put-u32 buf 16 (map-info-flags info))
    (let ((fd (%bpf +bpf-map-create+ buf 72
                     (format nil "map-create ~a" (map-info-name info)))))
      (setf (map-info-fd info) fd)
      fd)))

;;; ========== Percpu helpers ==========

(defun percpu-map-p (info)
  "Return true if INFO describes a percpu map type."
  (member (map-info-type info)
          (list +bpf-map-type-percpu-hash+ +bpf-map-type-percpu-array+)))

(defun percpu-value-size (info)
  "Return the total value buffer size needed for a map lookup.
   For percpu maps, this is value-size * num_possible_cpus (rounded up to 8-byte
   alignment per CPU slot, as the kernel requires). For regular maps, just value-size."
  (if (percpu-map-p info)
      (let ((aligned (logand (+ (map-info-value-size info) 7) (lognot 7))))
        (* aligned (possible-cpu-count)))
      (map-info-value-size info)))

(defun split-percpu-values (buf value-size num-cpus)
  "Split a percpu lookup buffer into a vector of per-CPU values."
  (let ((aligned (logand (+ value-size 7) (lognot 7)))
        (result (make-array num-cpus)))
    (dotimes (i num-cpus result)
      (let ((v (make-array value-size :element-type '(unsigned-byte 8))))
        (replace v buf :start2 (* i aligned) :end2 (+ (* i aligned) value-size))
        (setf (aref result i) v)))))

;;; ========== Map operations ==========

(defun map-lookup (info key-bytes)
  "Look up a key in a BPF map. Returns value bytes or nil if not found.
   For percpu maps, returns a vector of per-CPU value byte arrays."
  (let* ((buf (make-attr-buf))
         (total-size (percpu-value-size info))
         (value (make-array total-size
                            :element-type '(unsigned-byte 8)
                            :initial-element 0)))
    (put-u32 buf 0 (map-info-fd info))
    (sb-sys:with-pinned-objects (key-bytes value)
      (put-ptr buf 8 (sb-sys:vector-sap key-bytes))
      (put-ptr buf 16 (sb-sys:vector-sap value))
      (handler-case
          (progn (%bpf +bpf-map-lookup-elem+ buf 40 "map-lookup")
                 (if (percpu-map-p info)
                     (split-percpu-values value (map-info-value-size info)
                                          (possible-cpu-count))
                     value))
        (bpf-error (e)
          (if (= (bpf-error-errno e) 2)  ; ENOENT
              nil
              (error e)))))))

(defun map-update (info key-bytes value-bytes &key (flags 0))
  "Update a key/value pair in a BPF map.
   For percpu maps, VALUE-BYTES must be a vector of per-CPU value byte arrays
   (one per possible CPU), or a single byte array to set the same value on all CPUs."
  (let ((buf (make-attr-buf))
        (actual-value
          (if (percpu-map-p info)
              ;; Build the percpu value buffer
              (let* ((vsize (map-info-value-size info))
                     (aligned (logand (+ vsize 7) (lognot 7)))
                     (ncpus (possible-cpu-count))
                     (total (* aligned ncpus))
                     (vbuf (make-array total :element-type '(unsigned-byte 8)
                                             :initial-element 0)))
                (etypecase value-bytes
                  ;; Vector of per-CPU arrays
                  (vector
                   (if (and (plusp (length value-bytes))
                            (typep (aref value-bytes 0) '(simple-array (unsigned-byte 8) (*))))
                       (dotimes (i (min (length value-bytes) ncpus))
                         (replace vbuf (aref value-bytes i)
                                  :start1 (* i aligned)
                                  :end1 (+ (* i aligned) vsize)))
                       ;; Single flat byte array — replicate to all CPUs
                       (dotimes (i ncpus)
                         (replace vbuf value-bytes
                                  :start1 (* i aligned)
                                  :end1 (+ (* i aligned)
                                           (min vsize (length value-bytes))))))))
                vbuf)
              value-bytes)))
    (put-u32 buf 0 (map-info-fd info))
    (sb-sys:with-pinned-objects (key-bytes actual-value)
      (put-ptr buf 8 (sb-sys:vector-sap key-bytes))
      (put-ptr buf 16 (sb-sys:vector-sap actual-value))
      (put-u64 buf 24 flags)
      (%bpf +bpf-map-update-elem+ buf 40 "map-update"))))

(defun map-delete (info key-bytes)
  "Delete a key from a BPF map."
  (let ((buf (make-attr-buf)))
    (put-u32 buf 0 (map-info-fd info))
    (sb-sys:with-pinned-objects (key-bytes)
      (put-ptr buf 8 (sb-sys:vector-sap key-bytes))
      (%bpf +bpf-map-delete-elem+ buf 40 "map-delete"))))

(defun map-get-next-key (info key-bytes)
  "Get the next key after KEY-BYTES. If KEY-BYTES is nil, returns the first key.
   Returns nil when there are no more keys."
  (let ((buf (make-attr-buf))
        (next-key (make-array (map-info-key-size info)
                              :element-type '(unsigned-byte 8)
                              :initial-element 0)))
    (put-u32 buf 0 (map-info-fd info))
    (sb-sys:with-pinned-objects (key-bytes next-key)
      (when key-bytes
        (put-ptr buf 8 (sb-sys:vector-sap key-bytes)))
      (put-ptr buf 16 (sb-sys:vector-sap next-key))
      (handler-case
          (progn (%bpf +bpf-map-get-next-key+ buf 40 "map-get-next-key")
                 next-key)
        (bpf-error (e)
          (if (= (bpf-error-errno e) 2)  ; ENOENT
              nil
              (error e)))))))

;;; ========== Extract map definitions from ELF ==========

(defun extract-map-defs (elf)
  "Extract map definitions from a parsed BPF ELF. Returns a list of map-info."
  (let ((map-sec (bpf-elf-map-section elf))
        (symtab (bpf-elf-symtab elf)))
    (when map-sec
      (let ((sec-idx (car map-sec))
            (data (elf-section-data (cdr map-sec))))
        ;; Find OBJECT symbols in the maps section
        (loop for sym in symtab
              when (and (= (elf-sym-shndx sym) sec-idx)
                        (= (logand (elf-sym-info sym) #xf) +stt-object+))
              collect (let ((off (elf-sym-value sym)))
                        ;; Each map def is 32 bytes in .maps:
                        ;; type(4) key_size(4) value_size(4) max_entries(4) flags(4) ...
                        (make-map-info
                         :name (elf-sym-name sym)
                         :type (elf-u32 data off)
                         :key-size (elf-u32 data (+ off 4))
                         :value-size (elf-u32 data (+ off 8))
                         :max-entries (elf-u32 data (+ off 12))
                         :flags (elf-u32 data (+ off 16)))))))))
