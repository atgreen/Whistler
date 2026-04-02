;;; attach.lisp — BPF program attachment (kprobe, uprobe, XDP)
;;;
;;; SPDX-License-Identifier: MIT

(in-package #:whistler/loader)

;;; ========== Attachment tracking ==========

(defstruct attachment
  type perf-fds prog-fd (cleanup nil))

(defun detach (att)
  "Detach a BPF program and close all associated FDs."
  (when (attachment-cleanup att)
    (funcall (attachment-cleanup att)))
  (dolist (fd (attachment-perf-fds att))
    (sb-posix:close fd)))

;;; ========== CPU count ==========

(defun parse-cpu-range (s)
  "Parse a CPU range string like '0-3,8-11' into a count of CPUs."
  (let ((count 0))
    (dolist (part (split-string s #\,))
      (let ((dash (position #\- part)))
        (if dash
            (let ((lo (parse-integer (subseq part 0 dash) :junk-allowed t))
                  (hi (parse-integer (subseq part (1+ dash)) :junk-allowed t)))
              (when (and lo hi)
                (cl:incf count (1+ (- hi lo)))))
            (when (parse-integer part :junk-allowed t)
              (cl:incf count)))))
    count))

(defun split-string (s char)
  "Split string S by CHAR."
  (loop for start = 0 then (1+ end)
        for end = (position char s :start start)
        collect (subseq s start (or end (length s)))
        while end))

(defun online-cpu-count ()
  "Return the number of online CPUs."
  (or (let ((s (read-file-string "/sys/devices/system/cpu/online")))
        (when s
          (let ((n (parse-cpu-range s)))
            (when (plusp n) n))))
      1))

;;; ========== Perf event helpers ==========

(defun make-perf-attr (type config)
  "Build a perf_event_attr buffer."
  (let ((buf (make-array 128 :element-type '(unsigned-byte 8) :initial-element 0)))
    (put-u32 buf 0 type)          ; type (offset 0)
    (put-u32 buf 4 128)           ; size (offset 4)
    (put-u64 buf 8 config)        ; config (offset 8)
    buf))

(defun attach-perf-bpf (perf-attr prog-fd &key per-cpu)
  "Open perf events, attach BPF prog, and enable.
   When PER-CPU is true, opens one event per online CPU (for tracepoints).
   Otherwise opens a single event on CPU 0 (for kprobe/uprobe PMU attachment).
   Returns list of perf event FDs."
  (let ((cpus (if per-cpu (online-cpu-count) 1))
        (fds '()))
    (dotimes (cpu cpus)
      (let ((fd (%perf-event-open perf-attr -1 cpu -1 +perf-flag-fd-cloexec+)))
        (push fd fds)
        (%ioctl fd +perf-event-ioc-set-bpf+ prog-fd)
        (%ioctl fd +perf-event-ioc-enable+ 0)))
    (nreverse fds)))

;;; ========== Kprobe attachment ==========

(defun attach-kprobe (prog-fd function-name &key retprobe)
  "Attach a BPF program to a kprobe on FUNCTION-NAME.
   If RETPROBE is true, attaches to the return point instead.
   Returns an attachment that can be passed to detach."
  (let* ((pmu-type (read-file-int "/sys/bus/event_source/devices/kprobe/type"))
         (config (if retprobe 1 0))  ; bit 0 = retprobe
         (attr (make-perf-attr (or pmu-type +perf-type-tracepoint+) config))
         (name-bytes (sb-ext:string-to-octets function-name :null-terminate t)))
    (sb-sys:with-pinned-objects (name-bytes)
      ;; config1 = function name pointer at offset 56
      (put-ptr attr 56 (sb-sys:vector-sap name-bytes))
      (let ((fds (attach-perf-bpf attr prog-fd)))
        (make-attachment :type :kprobe :perf-fds fds :prog-fd prog-fd)))))

;;; ========== Tracepoint attachment ==========

(defun resolve-tracepoint-id (tracepoint-name)
  "Resolve a tracepoint name like \"tracepoint/sched/sched-process-fork\"
   or \"sched/sched-process-fork\" to its numeric event ID from tracefs.
   Converts hyphens to underscores for the filesystem lookup."
  (let* ((name (if (and (>= (length tracepoint-name) 11)
                        (string= (subseq tracepoint-name 0 11) "tracepoint/"))
                   (subseq tracepoint-name 11)
                   tracepoint-name))
         ;; Convert hyphens to underscores for tracefs paths
         (fs-name (substitute #\_ #\- name))
         (path (format nil "/sys/kernel/tracing/events/~a/id" fs-name))
         (id (read-file-int path)))
    (unless id
      ;; Try debugfs fallback
      (let ((alt-path (format nil "/sys/kernel/debug/tracing/events/~a/id" fs-name)))
        (setf id (read-file-int alt-path))))
    (unless id
      (error "Cannot resolve tracepoint ID for ~a (tried ~a)" tracepoint-name path))
    id))

(defun attach-tracepoint (prog-fd tracepoint-name)
  "Attach a BPF program to a tracepoint.
   TRACEPOINT-NAME is e.g. \"tracepoint/sched/sched_process_fork\"
   or \"sched/sched_process_fork\".
   Returns an attachment that can be passed to detach."
  (let* ((tp-id (resolve-tracepoint-id tracepoint-name))
         (attr (make-perf-attr +perf-type-tracepoint+ tp-id))
         (fds (attach-perf-bpf attr prog-fd :per-cpu t)))
    (make-attachment :type :tracepoint :perf-fds fds :prog-fd prog-fd)))

;;; ========== Uprobe attachment ==========

(defun vaddr-to-file-offset (bytes vaddr)
  "Convert a virtual address to a file offset using PT_LOAD segments.
   Finds the PT_LOAD segment containing VADDR and computes
   p_offset + (vaddr - p_vaddr)."
  (let ((e-phoff (elf-u64 bytes 32))
        (e-phentsize (elf-u16 bytes 54))
        (e-phnum (elf-u16 bytes 56)))
    (loop for i below e-phnum
          for ph-off = (+ e-phoff (* i e-phentsize))
          for p-type = (elf-u32 bytes ph-off)
          when (= p-type 1)  ; PT_LOAD
          do (let ((p-offset (elf-u64 bytes (+ ph-off 8)))
                   (p-vaddr (elf-u64 bytes (+ ph-off 16)))
                   (p-memsz (elf-u64 bytes (+ ph-off 40))))
               (when (and (>= vaddr p-vaddr)
                          (< vaddr (+ p-vaddr p-memsz)))
                 (return (+ p-offset (- vaddr p-vaddr))))))
    ;; Fallback: return vaddr unchanged (best effort)
    vaddr))

(defun resolve-elf-symbol-offset (binary-path symbol-name)
  "Find the file offset of a symbol in an ELF binary.
   Looks up st_value in symtab/dynsym, then converts the virtual address
   to a file offset via PT_LOAD segment mapping."
  (let* ((bytes (read-elf-bytes binary-path))
         (e-shoff (elf-u64 bytes 40))
         (e-shentsize (elf-u16 bytes 58))
         (e-shnum (elf-u16 bytes 60)))
    (loop for i below e-shnum
          for hdr-off = (+ e-shoff (* i e-shentsize))
          for sh-type = (elf-u32 bytes (+ hdr-off 4))
          for sh-link = (elf-u32 bytes (+ hdr-off 40))
          when (or (= sh-type 2) (= sh-type 11))  ; SHT_SYMTAB or SHT_DYNSYM
          do (let* ((sym-off (elf-u64 bytes (+ hdr-off 24)))
                    (sym-size (elf-u64 bytes (+ hdr-off 32)))
                    (str-hdr-off (+ e-shoff (* sh-link e-shentsize)))
                    (str-off (elf-u64 bytes (+ str-hdr-off 24)))
                    (str-size (elf-u64 bytes (+ str-hdr-off 32)))
                    (strtab (subseq bytes str-off (+ str-off str-size))))
               (loop for off from 0 below sym-size by 24
                     for name = (elf-string strtab (elf-u32 bytes (+ sym-off off)))
                     for value = (elf-u64 bytes (+ sym-off off 8))
                     when (string= name symbol-name)
                     do (return-from resolve-elf-symbol-offset
                          (vaddr-to-file-offset bytes value)))))
    (error "Symbol ~a not found in ~a" symbol-name binary-path)))

(defun attach-uprobe (prog-fd binary-path symbol-name &key retprobe)
  "Attach a BPF program to a uprobe on SYMBOL-NAME in BINARY-PATH.
   Returns an attachment that can be passed to detach."
  (let* ((offset (resolve-elf-symbol-offset binary-path symbol-name))
         (pmu-type (read-file-int "/sys/bus/event_source/devices/uprobe/type"))
         (config (if retprobe 1 0))  ; bit 0 = retprobe
         (attr (make-perf-attr (or pmu-type 8) config))
         (path-bytes (sb-ext:string-to-octets binary-path :null-terminate t)))
    (sb-sys:with-pinned-objects (path-bytes)
      ;; config1 = path pointer at offset 56, config2 = symbol offset at offset 64
      (put-ptr attr 56 (sb-sys:vector-sap path-bytes))
      (put-u64 attr 64 offset)
      (let ((fds (attach-perf-bpf attr prog-fd)))
        (make-attachment :type :uprobe :perf-fds fds :prog-fd prog-fd)))))

;;; ========== TC (traffic control) attachment ==========

(defun attach-tc (prog-fd interface-name &key (direction "ingress"))
  "Attach a BPF program as a TC filter on INTERFACE-NAME.
   DIRECTION is \"ingress\" or \"egress\".
   Uses bpffs pin + tc command. Returns an attachment that can be passed to detach."
  (let* ((ifindex (read-file-int
                   (format nil "/sys/class/net/~a/ifindex" interface-name)))
         (pin-path (format nil "/sys/fs/bpf/kinsight_tc_~a_~a" interface-name direction)))
    (unless ifindex
      (error "Interface not found: ~a" interface-name))
    ;; Pin the program to bpffs
    ;; BPF_OBJ_PIN attr: pathname (ptr) at offset 0, bpf_fd (u32) at offset 8
    (let ((buf (make-attr-buf)))
      (let ((path-bytes (sb-ext:string-to-octets pin-path :null-terminate t)))
        (sb-sys:with-pinned-objects (path-bytes)
          (put-ptr buf 0 (sb-sys:vector-sap path-bytes))
          (put-u32 buf 8 prog-fd)
          ;; Remove stale pin if it exists
          (when (probe-file pin-path)
            (handler-case (delete-file pin-path)
              (error () nil)))
          (%bpf +bpf-obj-pin+ buf 32 "bpf-pin"))))
    ;; Set up clsact qdisc (idempotent)
    (sb-ext:run-program "tc" (list "qdisc" "add" "dev" interface-name "clsact")
                        :search t :wait t)
    ;; Attach as tc filter
    (let ((ret (sb-ext:run-program
                "tc" (list "filter" "replace" "dev" interface-name
                           direction "bpf" "da" "pinned" pin-path)
                :search t :wait t)))
      (unless (zerop (sb-ext:process-exit-code ret))
        (handler-case (delete-file pin-path) (error () nil))
        (error "Failed to attach TC (~a) to ~a" direction interface-name)))
    (make-attachment :type :tc :perf-fds nil :prog-fd prog-fd
                     :cleanup (lambda ()
                                (sb-ext:run-program
                                 "tc" (list "filter" "del" "dev" interface-name direction)
                                 :search t :wait t)
                                (handler-case (delete-file pin-path)
                                  (error () nil))))))

;;; ========== XDP attachment ==========

(defun attach-xdp (prog-fd interface-name &key (mode "xdp"))
  "Attach a BPF program as XDP on INTERFACE-NAME.
   MODE is one of \"xdp\" (auto), \"xdpdrv\" (driver), \"xdpgeneric\" (skb),
   or \"xdpoffload\" (hardware). Returns an attachment that can be passed to detach."
  (let ((ifindex (read-file-int
                  (format nil "/sys/class/net/~a/ifindex" interface-name))))
    (unless ifindex
      (error "Interface not found: ~a" interface-name))
    (let ((ret (sb-ext:run-program "ip"
                                   (list "link" "set" "dev" interface-name
                                         mode "fd" (format nil "~d" prog-fd))
                                   :search t :wait t)))
      (unless (zerop (sb-ext:process-exit-code ret))
        (error "Failed to attach XDP (~a) to ~a" mode interface-name)))
    (make-attachment :type :xdp :perf-fds nil :prog-fd prog-fd
                     :cleanup (lambda ()
                                (sb-ext:run-program "ip"
                                                    (list "link" "set" "dev"
                                                          interface-name mode "off")
                                                    :search t :wait t)))))
