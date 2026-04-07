(in-package #:whistler/tests)

(in-suite maps-suite)

;;; ========== Percpu map detection ==========

(test percpu-map-p-detects-percpu-hash
  "percpu-map-p returns true for percpu-hash maps"
  (let ((info (whistler/loader::make-map-info
               :name "test" :type whistler/loader::+bpf-map-type-percpu-hash+
               :key-size 4 :value-size 8 :max-entries 256 :flags 0)))
    (is-true (whistler/loader::percpu-map-p info))))

(test percpu-map-p-detects-percpu-array
  "percpu-map-p returns true for percpu-array maps"
  (let ((info (whistler/loader::make-map-info
               :name "test" :type whistler/loader::+bpf-map-type-percpu-array+
               :key-size 4 :value-size 8 :max-entries 4 :flags 0)))
    (is-true (whistler/loader::percpu-map-p info))))

(test percpu-map-p-false-for-regular-hash
  "percpu-map-p returns nil for regular hash maps"
  (let ((info (whistler/loader::make-map-info
               :name "test" :type whistler/loader::+bpf-map-type-hash+
               :key-size 4 :value-size 8 :max-entries 256 :flags 0)))
    (is-false (whistler/loader::percpu-map-p info))))

(test percpu-map-p-false-for-regular-array
  "percpu-map-p returns nil for regular array maps"
  (let ((info (whistler/loader::make-map-info
               :name "test" :type whistler/loader::+bpf-map-type-array+
               :key-size 4 :value-size 8 :max-entries 4 :flags 0)))
    (is-false (whistler/loader::percpu-map-p info))))

;;; ========== Percpu value size calculation ==========

(test percpu-value-size-regular-map
  "percpu-value-size returns plain value-size for regular maps"
  (let ((info (whistler/loader::make-map-info
               :name "test" :type whistler/loader::+bpf-map-type-hash+
               :key-size 4 :value-size 8 :max-entries 256 :flags 0)))
    (is (= 8 (whistler/loader::percpu-value-size info)))))

(test percpu-value-size-aligned-8
  "percpu-value-size for 8-byte values: 8 * num_cpus (already aligned)"
  (let ((info (whistler/loader::make-map-info
               :name "test" :type whistler/loader::+bpf-map-type-percpu-hash+
               :key-size 4 :value-size 8 :max-entries 256 :flags 0))
        (ncpus (whistler/loader::possible-cpu-count)))
    (is (= (* 8 ncpus) (whistler/loader::percpu-value-size info)))))

(test percpu-value-size-rounds-up
  "percpu-value-size rounds non-8-byte values up to 8-byte alignment per slot"
  (let ((info (whistler/loader::make-map-info
               :name "test" :type whistler/loader::+bpf-map-type-percpu-hash+
               :key-size 4 :value-size 5 :max-entries 256 :flags 0))
        (ncpus (whistler/loader::possible-cpu-count)))
    ;; 5 bytes rounds up to 8 per slot
    (is (= (* 8 ncpus) (whistler/loader::percpu-value-size info)))))

(test percpu-value-size-16-byte-value
  "percpu-value-size with 16-byte value (already 8-aligned)"
  (let ((info (whistler/loader::make-map-info
               :name "test" :type whistler/loader::+bpf-map-type-percpu-array+
               :key-size 4 :value-size 16 :max-entries 4 :flags 0))
        (ncpus (whistler/loader::possible-cpu-count)))
    (is (= (* 16 ncpus) (whistler/loader::percpu-value-size info)))))

(test percpu-value-size-1-byte-value
  "percpu-value-size with 1-byte value rounds up to 8"
  (let ((info (whistler/loader::make-map-info
               :name "test" :type whistler/loader::+bpf-map-type-percpu-hash+
               :key-size 4 :value-size 1 :max-entries 256 :flags 0))
        (ncpus (whistler/loader::possible-cpu-count)))
    (is (= (* 8 ncpus) (whistler/loader::percpu-value-size info)))))

;;; ========== Split percpu values ==========

(test split-percpu-values-basic
  "split-percpu-values splits flat buffer into per-CPU arrays"
  (let* ((ncpus 4)
         (vsize 8)
         ;; Build a buffer with distinct values per CPU
         (buf (make-array (* 8 ncpus) :element-type '(unsigned-byte 8)
                                       :initial-element 0)))
    ;; CPU 0: value 10, CPU 1: value 20, CPU 2: value 30, CPU 3: value 40
    (setf (aref buf 0) 10)
    (setf (aref buf 8) 20)
    (setf (aref buf 16) 30)
    (setf (aref buf 24) 40)
    (let ((result (whistler/loader::split-percpu-values buf vsize ncpus)))
      (is (= ncpus (length result)))
      (is (= 10 (aref (aref result 0) 0)))
      (is (= 20 (aref (aref result 1) 0)))
      (is (= 30 (aref (aref result 2) 0)))
      (is (= 40 (aref (aref result 3) 0))))))

(test split-percpu-values-with-padding
  "split-percpu-values handles non-8-aligned values with padding"
  (let* ((ncpus 3)
         (vsize 5)
         (aligned 8)  ; 5 rounds up to 8
         ;; Build padded buffer
         (buf (make-array (* aligned ncpus) :element-type '(unsigned-byte 8)
                                             :initial-element 0)))
    ;; CPU 0: bytes [1,2,3,4,5], CPU 1: bytes [6,7,8,9,10], CPU 2: bytes [11,12,13,14,15]
    (loop for cpu below ncpus
          do (loop for b below vsize
                   do (setf (aref buf (+ (* cpu aligned) b))
                            (+ 1 b (* cpu vsize)))))
    (let ((result (whistler/loader::split-percpu-values buf vsize ncpus)))
      (is (= ncpus (length result)))
      ;; Each result should be exactly vsize bytes
      (is (= vsize (length (aref result 0))))
      (is (= vsize (length (aref result 1))))
      (is (= vsize (length (aref result 2))))
      ;; Check values
      (is (= 1 (aref (aref result 0) 0)))
      (is (= 5 (aref (aref result 0) 4)))
      (is (= 6 (aref (aref result 1) 0)))
      (is (= 11 (aref (aref result 2) 0))))))

(test split-percpu-values-single-cpu
  "split-percpu-values works with a single CPU"
  (let* ((buf (make-array 8 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref buf 0) 42)
    (let ((result (whistler/loader::split-percpu-values buf 8 1)))
      (is (= 1 (length result)))
      (is (= 42 (aref (aref result 0) 0))))))

;;; ========== Possible CPU count ==========

(test possible-cpu-count-positive
  "possible-cpu-count returns a positive integer"
  (let ((n (whistler/loader::possible-cpu-count)))
    (is (integerp n))
    (is (plusp n))))

(test possible-cpu-count-gte-online
  "possible-cpu-count >= online-cpu-count"
  (is (>= (whistler/loader::possible-cpu-count)
           (whistler/loader::online-cpu-count))))
