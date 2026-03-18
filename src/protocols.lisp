;;; -*- Mode: Lisp -*-
;;;
;;; Copyright (c) 2026 Anthony Green <green@moxielogic.com>
;;;
;;; SPDX-License-Identifier: MIT

(in-package #:whistler)

;;; ================================================================
;;; Surface language macros
;;; ================================================================
;;;
;;; These macros make Whistler programs more declarative by hiding
;;; BPF-shaped details behind Lisp-idiomatic forms. They all expand
;;; to primitive Whistler forms at compile time — zero runtime cost.

;;; ---- pt_regs access (x86-64) ----
;;;
;;; These match the C macros PT_REGS_PARM1() etc. from bpf_tracing.h.
;;; x86-64 System V ABI: rdi, rsi, rdx, rcx, r8, r9

(defmacro pt-regs-parm1 () "First function arg (rdi)."  '(ctx-load u64 112))
(defmacro pt-regs-parm2 () "Second function arg (rsi)." '(ctx-load u64 104))
(defmacro pt-regs-parm3 () "Third function arg (rdx)."  '(ctx-load u64 96))
(defmacro pt-regs-parm4 () "Fourth function arg (rcx)." '(ctx-load u64 88))
(defmacro pt-regs-parm5 () "Fifth function arg (r8)."   '(ctx-load u64 72))
(defmacro pt-regs-parm6 () "Sixth function arg (r9)."   '(ctx-load u64 64))
(defmacro pt-regs-ret ()   "Return value (rax)."        '(ctx-load u64 80))

;;; ---- Control flow ----

(defmacro when-let (bindings &body body)
  "Bind variables and execute body only if all bound values are non-nil.
   Each binding is (var init) or (var type init). If any init evaluates
   to 0/nil, the rest of the bindings and the body are skipped.
   Returns 0 when skipped."
  (if (null bindings)
      `(progn ,@body)
      (let ((b (first bindings)))
        (if (cddr b)
            ;; 3-element: (var type init)
            (cl:destructuring-bind (var type init) b
              `(let ((,var ,type ,init))
                 (when ,var
                   (when-let ,(rest bindings) ,@body))))
            ;; 2-element: (var init)
            (cl:destructuring-bind (var init) b
              `(let ((,var ,init))
                 (when ,var
                   (when-let ,(rest bindings) ,@body))))))))

(defmacro if-let (binding then &optional else)
  "Bind a variable and branch on its value.
   BINDING is (var init) or (var type init). If init is non-nil,
   execute THEN with var bound; otherwise execute ELSE."
  (if (cddr binding)
      ;; 3-element: (var type init)
      (cl:destructuring-bind (var type init) binding
        `(let ((,var ,type ,init))
           (if ,var ,then ,else)))
      ;; 2-element: (var init)
      (cl:destructuring-bind (var init) binding
        `(let ((,var ,init))
           (if ,var ,then ,else)))))

(defmacro case (keyform &body clauses)
  "Multi-way dispatch on a value. Each clause is (value body...) or
   ((v1 v2 ...) body...). The final clause may use T or OTHERWISE
   as a catch-all. Compiles to BPF cond chains."
  (let ((key-var (gensym "CASE")))
    `(let ((,key-var u64 ,keyform))
       (cond
         ,@(mapcar (lambda (clause)
                     (let ((test (first clause))
                           (body (rest clause)))
                       (cond
                         ((or (eq test t) (eq test 'otherwise))
                          `(t ,@body))
                         ((listp test)
                          `((or ,@(mapcar (lambda (v) `(= ,key-var ,v)) test))
                            ,@body))
                         (t `((= ,key-var ,test) ,@body)))))
                   clauses)))))

;;; ---- incf / decf ----

(defmacro incf (place &optional (delta 1))
  "Increment PLACE by DELTA. For map places, uses atomic increment.
   (incf (getmap map key))       → atomic map increment
   (incf (getmap map key) 5)     → atomic map increment by 5
   (incf var)                    → (setf var (+ var 1))"
  (if (and (consp place) (cl:eq (car place) 'getmap))
      `(incf-map ,(second place) ,(third place) ,delta)
      `(setf ,place (+ ,place ,delta))))

(defmacro decf (place &optional (delta 1))
  "Decrement PLACE by DELTA.
   (decf var)   → (setf var (- var 1))"
  `(setf ,place (- ,place ,delta)))

;;; ---- Map operations ----

(defun array-map-p (map-name)
  "Check if MAP-NAME refers to an array-type map in the current compilation."
  (let ((spec (find (symbol-name map-name) *maps*
                    :key (lambda (s) (symbol-name (first s)))
                    :test #'string=)))
    (and spec
         (member (getf (rest spec) :type) '(:array :percpu-array)))))

(defmacro incf-map (map key-form &optional (delta 1))
  "Atomically increment a map value. For array maps where the key always exists,
   this is just a lookup + atomic-add. For hash maps, initializes to DELTA if
   the key is new."
  (if (array-map-p map)
      ;; Array maps: entries are pre-allocated, lookup always succeeds
      (let ((k (gensym "K"))
            (p (gensym "P")))
        `(let ((,k u32 ,key-form))
           (when-let ((,p u64 (map-lookup ,map ,k)))
             (atomic-add ,p 0 ,delta))))
      ;; Hash maps: create entry if not found
      (let ((k (gensym "K"))
            (p (gensym "P"))
            (init (gensym "INIT")))
        `(let ((,k u32 ,key-form)
               (,p u64 (map-lookup ,map ,k)))
           (if ,p
               (atomic-add ,p 0 ,delta)
               (let ((,init u64 ,delta))
                 (map-update ,map ,k ,init 0)))))))

(defmacro getmap (map key-form)
  "Look up a map value and dereference the pointer. Returns the u64 value,
   or 0 if the key is not found."
  (let ((p (gensym "P")))
    `(let ((,p u64 (map-lookup ,map ,key-form)))
       (if ,p (load u64 ,p 0) 0))))

(defmacro set-getmap! (map key-form val-form)
  "Writer macro for (setf (getmap map key) val)."
  (let ((v (gensym "V")))
    `(let ((,v u64 ,val-form))
       (map-update ,map ,key-form ,v 0))))

(cl:defsetf getmap set-getmap!)

(defmacro setmap (map key-form val-form &optional (flags 0))
  "Update a map entry. Prefer (setf (getmap ...) ...) for the common case."
  (let ((v (gensym "V")))
    `(let ((,v u64 ,val-form))
       (map-update ,map ,key-form ,v ,flags))))

(defmacro remmap (map key-form)
  "Delete a map entry. CL-style name (cf. remhash)."
  `(map-delete ,map ,key-form))

(defmacro delmap (map key-form)
  "Delete a map entry. Alias for remmap."
  `(map-delete ,map ,key-form))

;;; ================================================================
;;; Protocol header definitions
;;; ================================================================
;;;
;;; These are compile-time macros that expand to (load TYPE ptr OFFSET).
;;; No runtime cost — they are just named constants for byte offsets.
;;; The "struct" is a purely compile-time abstraction.

;;; ---- Struct definition macro ----

(defmacro defheader (name &body fields)
  "Define a protocol header with named field accessors.
   Each field is (field-name :offset N :type TYPE [:net-order BOOL]).
   Generates macros: (NAME-FIELD-NAME ptr) → (load TYPE ptr OFFSET)
   and optionally wraps in ntohs/ntohl for network byte order."
  (let ((forms '()))
    (dolist (field fields)
      (destructuring-bind (field-name &key offset type (net-order nil)) field
        (let ((accessor-name (intern (format nil "~a-~a" name field-name)
                                     (symbol-package name))))
          (if net-order
              (let ((swap-fn (cl:case type
                               ((u16 i16) 'ntohs)
                               ((u32 i32) 'ntohl)
                               (t nil))))
                (if swap-fn
                    (push `(defmacro ,accessor-name (ptr)
                             (list ',swap-fn (list 'load ',type ptr ,offset)))
                          forms)
                    (push `(defmacro ,accessor-name (ptr)
                             (list 'load ',type ptr ,offset))
                          forms)))
              (push `(defmacro ,accessor-name (ptr)
                       (list 'load ',type ptr ,offset))
                    forms)))))
    `(progn ,@(nreverse forms))))

;;; ---- Standard protocol headers ----

;; Ethernet header (14 bytes)
(defheader eth
  (dst-mac-hi  :offset 0  :type u32)
  (dst-mac-lo  :offset 4  :type u16)
  (src-mac-hi  :offset 6  :type u32)
  (src-mac-lo  :offset 10 :type u16)
  (type        :offset 12 :type u16 :net-order t))

(defconstant +ethertype-ipv4+  #x0800)
(defconstant +ethertype-ipv6+  #x86dd)
(defconstant +ethertype-arp+   #x0806)
(defconstant +ethertype-vlan+  #x8100)

(defconstant +eth-hdr-len+ 14)

;; IPv4 header (20 bytes minimum, without options)
(defheader ipv4
  (ver-ihl     :offset 0  :type u8)
  (tos         :offset 1  :type u8)
  (total-len   :offset 2  :type u16 :net-order t)
  (id          :offset 4  :type u16 :net-order t)
  (frag-off    :offset 6  :type u16 :net-order t)
  (ttl         :offset 8  :type u8)
  (protocol    :offset 9  :type u8)
  (checksum    :offset 10 :type u16)
  (src-addr    :offset 12 :type u32)
  (dst-addr    :offset 16 :type u32))

(defconstant +ipv4-hdr-len+ 20)
(defconstant +ip-proto-icmp+  1)
(defconstant +ip-proto-tcp+   6)
(defconstant +ip-proto-udp+  17)

;; TCP header (20 bytes minimum)
(defheader tcp
  (src-port    :offset 0  :type u16 :net-order t)
  (dst-port    :offset 2  :type u16 :net-order t)
  (seq         :offset 4  :type u32 :net-order t)
  (ack-seq     :offset 8  :type u32 :net-order t)
  (data-off    :offset 12 :type u8)
  (flags       :offset 13 :type u8)
  (window      :offset 14 :type u16 :net-order t)
  (checksum    :offset 16 :type u16)
  (urgent      :offset 18 :type u16 :net-order t))

(defconstant +tcp-hdr-len+ 20)
(defconstant +tcp-fin+ #x01)
(defconstant +tcp-syn+ #x02)
(defconstant +tcp-rst+ #x04)
(defconstant +tcp-psh+ #x08)
(defconstant +tcp-ack+ #x10)
(defconstant +tcp-urg+ #x20)

;; UDP header (8 bytes)
(defheader udp
  (src-port    :offset 0 :type u16 :net-order t)
  (dst-port    :offset 2 :type u16 :net-order t)
  (length      :offset 4 :type u16 :net-order t)
  (checksum    :offset 6 :type u16))

(defconstant +udp-hdr-len+ 8)

;;; ---- Packet parsing helpers (statement-oriented, with early return) ----

(defmacro with-packet ((data data-end &key (min-len 0)) &body body)
  "Bind DATA and DATA-END from the XDP context, then check minimum length."
  `(let ((,data     u64 (ctx-load u32 0))
         (,data-end u64 (ctx-load u32 4)))
     (if (> (+ ,data ,min-len) ,data-end)
         (return XDP_PASS)
         (progn ,@body))))

(defmacro with-eth ((data data-end) &body body)
  "Parse ethernet header with bounds check. Binds DATA and DATA-END."
  `(with-packet (,data ,data-end :min-len ,+eth-hdr-len+)
     ,@body))

(defmacro with-ipv4 ((data data-end ip-off) &body body)
  "Parse IPv4 header with bounds check. Binds DATA, DATA-END, and IP-OFF."
  `(with-packet (,data ,data-end :min-len ,(+ +eth-hdr-len+ +ipv4-hdr-len+))
     (when (= (eth-type ,data) ,+ethertype-ipv4+)
       (let ((,ip-off u64 (+ ,data ,+eth-hdr-len+)))
         ,@body))))

(defmacro with-tcp ((data data-end tcp-off) &body body)
  "Parse TCP header with bounds check. Binds DATA, DATA-END, TCP-OFF."
  (let ((ip-off (gensym "IP")))
    `(with-packet (,data ,data-end
                   :min-len ,(+ +eth-hdr-len+ +ipv4-hdr-len+ +tcp-hdr-len+))
       (when (= (eth-type ,data) ,+ethertype-ipv4+)
         (let ((,ip-off u64 (+ ,data ,+eth-hdr-len+)))
           (when (= (ipv4-protocol ,ip-off) ,+ip-proto-tcp+)
             (let ((,tcp-off u64 (+ ,ip-off ,+ipv4-hdr-len+)))
               ,@body)))))))

(defmacro with-udp ((data data-end udp-off) &body body)
  "Parse UDP header with bounds check. Binds DATA, DATA-END, UDP-OFF."
  (let ((ip-off (gensym "IP")))
    `(with-packet (,data ,data-end
                   :min-len ,(+ +eth-hdr-len+ +ipv4-hdr-len+ +udp-hdr-len+))
       (when (= (eth-type ,data) ,+ethertype-ipv4+)
         (let ((,ip-off u64 (+ ,data ,+eth-hdr-len+)))
           (when (= (ipv4-protocol ,ip-off) ,+ip-proto-udp+)
             (let ((,udp-off u64 (+ ,ip-off ,+ipv4-hdr-len+)))
               ,@body)))))))

;;; ---- Expression-oriented packet parsing ----
;;;
;;; Unlike with-tcp etc., these return a pointer (or 0 on failure)
;;; and can be used in when-let bindings for pipeline-style parsing.

(defmacro parse-eth (data data-end)
  "Check Ethernet header bounds. Returns DATA (the eth pointer) or 0."
  `(if (> (+ ,data ,+eth-hdr-len+) ,data-end) 0 ,data))

(defmacro parse-ipv4 (data data-end)
  "Check IPv4 bounds and EtherType. Returns pointer to IP header or 0."
  (let ((d (gensym "D")) (de (gensym "DE")))
    `(let ((,d ,data) (,de ,data-end))
       (if (> (+ ,d ,(+ +eth-hdr-len+ +ipv4-hdr-len+)) ,de)
           0
           (if (/= (eth-type ,d) ,+ethertype-ipv4+)
               0
               (+ ,d ,+eth-hdr-len+))))))

(defmacro parse-tcp (data data-end)
  "Check TCP bounds, EtherType, and IP protocol. Returns pointer to TCP header or 0."
  (let ((d (gensym "D")) (de (gensym "DE")) (ip (gensym "IP")))
    `(let ((,d ,data) (,de ,data-end))
       (if (> (+ ,d ,(+ +eth-hdr-len+ +ipv4-hdr-len+ +tcp-hdr-len+)) ,de)
           0
           (if (/= (eth-type ,d) ,+ethertype-ipv4+)
               0
               (let ((,ip (+ ,d ,+eth-hdr-len+)))
                 (if (/= (ipv4-protocol ,ip) ,+ip-proto-tcp+)
                     0
                     (+ ,ip ,+ipv4-hdr-len+))))))))

(defmacro parse-udp (data data-end)
  "Check UDP bounds, EtherType, and IP protocol. Returns pointer to UDP header or 0."
  (let ((d (gensym "D")) (de (gensym "DE")) (ip (gensym "IP")))
    `(let ((,d ,data) (,de ,data-end))
       (if (> (+ ,d ,(+ +eth-hdr-len+ +ipv4-hdr-len+ +udp-hdr-len+)) ,de)
           0
           (if (/= (eth-type ,d) ,+ethertype-ipv4+)
               0
               (let ((,ip (+ ,d ,+eth-hdr-len+)))
                 (if (/= (ipv4-protocol ,ip) ,+ip-proto-udp+)
                     0
                     (+ ,ip ,+ipv4-hdr-len+))))))))

(defmacro xdp-data ()
  "Load XDP context data pointer."
  `(core-ctx-load u32 0 xdp-md data))

(defmacro xdp-data-end ()
  "Load XDP context data-end pointer."
  `(core-ctx-load u32 4 xdp-md data-end))
