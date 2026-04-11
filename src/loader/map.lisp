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

(defun map-lookup-int (info key)
  "Look up integer KEY in INFO and decode the value as a little-endian integer."
  (let ((result (map-lookup info (encode-int-key key (map-info-key-size info)))))
    (when result
      (decode-int-value result))))

(defun struct-codec-function (prefix struct-name)
  "Resolve PREFIX-STRUCT-NAME in the same package as STRUCT-NAME."
  (let* ((pkg (or (and (symbolp struct-name) (symbol-package struct-name))
                  *package*))
         (sym-name (if (symbolp struct-name)
                       (symbol-name struct-name)
                       (string-upcase (string struct-name))))
         (codec-name (format nil "~a-~a" prefix sym-name))
         (sym (find-symbol codec-name pkg)))
    (unless (and sym (fboundp sym))
      (error "No ~a function found for ~a in package ~a"
             prefix struct-name (package-name pkg)))
    (symbol-function sym)))

(defun map-lookup-struct (info key-bytes struct-name)
  "Look up KEY-BYTES in INFO and decode the value using STRUCT-NAME's decoder."
  (let ((result (map-lookup info key-bytes)))
    (when result
      (funcall (struct-codec-function "DECODE" struct-name) result))))

(defun map-lookup-struct-int (info key struct-name)
  "Look up integer KEY in INFO and decode the value using STRUCT-NAME's decoder."
  (map-lookup-struct info
                     (encode-int-key key (map-info-key-size info))
                     struct-name))

(defun map-update-int (info key value &key (flags 0))
  "Update integer KEY with integer VALUE using INFO's declared sizes."
  (map-update info
              (encode-int-key key (map-info-key-size info))
              (encode-int-key value (map-info-value-size info))
              :flags flags))

(defun map-update-struct (info key-bytes record struct-name &key (flags 0))
  "Update KEY-BYTES in INFO with RECORD encoded via STRUCT-NAME's encoder."
  (map-update info key-bytes
              (funcall (struct-codec-function "ENCODE" struct-name) record)
              :flags flags))

(defun map-update-struct-int (info key record struct-name &key (flags 0))
  "Update integer KEY in INFO with RECORD encoded via STRUCT-NAME's encoder."
  (map-update-struct info
                     (encode-int-key key (map-info-key-size info))
                     record struct-name
                     :flags flags))

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

(defun map-delete-int (info key)
  "Delete integer KEY from INFO."
  (map-delete info (encode-int-key key (map-info-key-size info))))

(defun map-delete-struct (info record struct-name)
  "Delete RECORD encoded as a key using STRUCT-NAME's encoder."
  (map-delete info
              (funcall (struct-codec-function "ENCODE" struct-name) record)))

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

(defun map-get-next-key-int (info &optional key)
  "Return the next integer key after KEY, or the first key if KEY is nil."
  (let ((next (map-get-next-key info
                                (when key
                                  (encode-int-key key (map-info-key-size info))))))
    (when next
      (decode-int-value next))))

(defun map-get-next-key-struct (info struct-name &optional key-record)
  "Return the next struct key after KEY-RECORD decoded via STRUCT-NAME."
  (let ((next (map-get-next-key info
                                (when key-record
                                  (funcall (struct-codec-function "ENCODE" struct-name)
                                           key-record)))))
    (when next
      (funcall (struct-codec-function "DECODE" struct-name) next))))

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
