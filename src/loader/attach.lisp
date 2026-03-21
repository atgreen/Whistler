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

(defun online-cpu-count ()
  "Return the number of online CPUs."
  (or (let ((s (read-file-string "/sys/devices/system/cpu/online")))
        ;; Format: "0-N" or "0,1,2,..."
        (when s
          (let ((dash (position #\- s)))
            (when dash
              (1+ (parse-integer (subseq s (1+ dash)) :junk-allowed t))))))
      1))

;;; ========== Perf event helpers ==========

(defun make-perf-attr (type config)
  "Build a perf_event_attr buffer."
  (let ((buf (make-array 128 :element-type '(unsigned-byte 8) :initial-element 0)))
    (put-u32 buf 0 type)          ; type
    (put-u32 buf 4 128)           ; size
    (put-u64 buf 8 config)        ; config
    (put-u64 buf 40 +perf-sample-raw+)  ; sample_type
    buf))

(defun attach-perf-bpf (perf-attr prog-fd)
  "Open perf events on all CPUs, attach BPF prog, and enable.
   Returns list of perf event FDs."
  (let ((ncpus (online-cpu-count))
        (fds '()))
    (dotimes (cpu ncpus)
      (let ((fd (%perf-event-open perf-attr -1 cpu -1 +perf-flag-fd-cloexec+)))
        (push fd fds)
        (%ioctl fd +perf-event-ioc-set-bpf+ prog-fd)
        (%ioctl fd +perf-event-ioc-enable+ 0)))
    (nreverse fds)))

;;; ========== Kprobe attachment ==========

(defun attach-kprobe (prog-fd function-name &key retprobe)
  "Attach a BPF program to a kprobe on FUNCTION-NAME.
   Returns an attachment that can be passed to detach."
  (declare (ignore retprobe))  ; TODO: retprobe support
  (let* ((pmu-type (read-file-int "/sys/bus/event_source/devices/kprobe/type"))
         (attr (make-perf-attr (or pmu-type +perf-type-tracepoint+) 0))
         (name-bytes (sb-ext:string-to-octets function-name :null-terminate t)))
    (sb-sys:with-pinned-objects (name-bytes)
      ;; config1 = function name pointer (for PMU-based kprobe)
      (put-ptr attr 72 (sb-sys:vector-sap name-bytes))
      (let ((fds (attach-perf-bpf attr prog-fd)))
        (make-attachment :type :kprobe :perf-fds fds :prog-fd prog-fd)))))

;;; ========== Uprobe attachment ==========

(defun resolve-elf-symbol-offset (binary-path symbol-name)
  "Find the file offset of a symbol in an ELF binary."
  ;; Simple approach: parse the ELF to find the symbol.
  ;; For shared libs, we need the symbol's virtual address.
  (let* ((bytes (read-elf-bytes binary-path))
         (e-shoff (elf-u64 bytes 40))
         (e-shentsize (elf-u16 bytes 58))
         (e-shnum (elf-u16 bytes 60))
         (e-shstrndx (elf-u16 bytes 62)))
    ;; Find .dynsym or .symtab
    (loop for i below e-shnum
          for hdr-off = (+ e-shoff (* i e-shentsize))
          for sh-type = (elf-u32 bytes (+ hdr-off 4))
          for sh-link = (elf-u32 bytes (+ hdr-off 40))
          when (or (= sh-type 2) (= sh-type 11))  ; SHT_SYMTAB or SHT_DYNSYM
          do (let* ((sym-off (elf-u64 bytes (+ hdr-off 24)))
                    (sym-size (elf-u64 bytes (+ hdr-off 32)))
                    ;; Get linked string table
                    (str-hdr-off (+ e-shoff (* sh-link e-shentsize)))
                    (str-off (elf-u64 bytes (+ str-hdr-off 24)))
                    (str-size (elf-u64 bytes (+ str-hdr-off 32)))
                    (strtab (subseq bytes str-off (+ str-off str-size))))
               (loop for off from 0 below sym-size by 24
                     for name = (elf-string strtab (elf-u32 bytes (+ sym-off off)))
                     for value = (elf-u64 bytes (+ sym-off off 8))
                     when (string= name symbol-name)
                     do (return-from resolve-elf-symbol-offset value))))
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
      ;; config1 = path pointer, config2 = symbol offset
      (put-ptr attr 72 (sb-sys:vector-sap path-bytes))
      (put-u64 attr 80 offset)
      (let ((fds (attach-perf-bpf attr prog-fd)))
        (make-attachment :type :uprobe :perf-fds fds :prog-fd prog-fd)))))

;;; ========== XDP attachment ==========

(defun attach-xdp (prog-fd interface-name &key (flags 0))
  "Attach a BPF program as XDP on INTERFACE-NAME.
   Returns an attachment that can be passed to detach."
  (let ((ifindex (read-file-int
                  (format nil "/sys/class/net/~a/ifindex" interface-name))))
    (unless ifindex
      (error "Interface not found: ~a" interface-name))
    ;; Use ip link for MVP — netlink is complex
    (let ((ret (sb-ext:run-program "/sbin/ip"
                                   (list "link" "set" "dev" interface-name
                                         "xdp" "fd" (format nil "~d" prog-fd))
                                   :search t :wait t)))
      (unless (zerop (sb-ext:process-exit-code ret))
        (error "Failed to attach XDP to ~a" interface-name)))
    (make-attachment :type :xdp :perf-fds nil :prog-fd prog-fd
                     :cleanup (lambda ()
                                (sb-ext:run-program "/sbin/ip"
                                                    (list "link" "set" "dev"
                                                          interface-name "xdp" "off")
                                                    :search t :wait t)))))
