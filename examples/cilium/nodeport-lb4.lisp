;;; Cilium-style simplified NodePort Load Balancer (IPv4)
;;;
;;; Reimplements the core NodePort LB4 path from Cilium's bpf_xdp.c:
;;; service lookup -> backend selection -> DNAT.
;;;
;;; Simplified vs. Cilium: no conntrack, no SNAT, no DSR, no session
;;; affinity, no tail calls. Just the essential load-balancing datapath.
;;;
;;; Flow:
;;; 1. Parse Ethernet + IPv4 + TCP/UDP headers
;;; 2. Build service key: (dst-ip, dst-port, slot=0, proto)
;;; 3. Lookup service in services map (slot 0 = frontend entry)
;;; 4. Read backend count, pick random slot: (mod (get-prandom-u32) count) + 1
;;; 5. Lookup backend slot in services map -> get backend_id
;;; 6. Lookup backend in backends map -> get backend IP + port
;;; 7. Rewrite IPv4 dst-addr and L4 dst-port (DNAT)
;;; 8. Recompute IPv4 checksum (incremental)
;;; 9. Pass packet

(in-package #:whistler)

;;; Struct definitions

(defstruct lb4-svc-key
  (addr   u32)    ; offset 0  — virtual IP (network byte order)
  (dport  u16)    ; offset 4  — destination port (network byte order)
  (slot   u16)    ; offset 6  — 0 = frontend entry, 1..N = backend slots
  (proto  u8)     ; offset 8  — IP protocol
  (scope  u8)     ; offset 9  — scope (0 for external)
  (pad    u16))   ; offset 10 — padding (total: 12 bytes)

;;; Maps

;; Service table — maps (addr, port, slot, proto) -> service/backend info
;; Key: lb4-svc-key (12 bytes)
;; Value: 16 bytes
;;   backend_id  u32  (offset 0)
;;   count       u16  (offset 4)  — number of backends (only in slot 0)
;;   rev_nat_id  u16  (offset 6)
;;   flags       u8   (offset 8)
;;   pad         7 bytes
(defmap lb4-services
  :type :hash
  :key-size 12
  :value-size 16
  :max-entries 65536)

;; Backend table — maps backend_id -> backend address/port
;; Key: 4 bytes (backend_id u32)
;; Value: 12 bytes
;;   addr     u32  (offset 0)  — backend IP (network byte order)
;;   port     u16  (offset 4)  — backend port (network byte order)
;;   proto    u8   (offset 6)
;;   flags    u8   (offset 7)
;;   cluster  u16  (offset 8)
;;   pad      u16  (offset 10)
(defmap lb4-backends
  :type :hash
  :key-size 4
  :value-size 12
  :max-entries 65536)

;;; Helpers

;; Incremental IPv4 checksum update for a 32-bit field change.
;; ~(~old_csum + ~old_val + new_val)  (one's complement arithmetic)
;; We do this in a simplified way: subtract old, add new, fold carries.
(defmacro ipv4-csum-update-u32 (ip-ptr old-val new-val)
  "Update IPv4 checksum after changing a u32 field."
  (let ((csum (gensym "CSUM"))
        (old-lo (gensym "OLD-LO"))
        (old-hi (gensym "OLD-HI"))
        (new-lo (gensym "NEW-LO"))
        (new-hi (gensym "NEW-HI")))
    `(let ((,csum (load u16 ,ip-ptr 10)))    ; current checksum
       ;; Invert (one's complement negate)
       (setf ,csum (logand (logxor ,csum #xffff) #xffff))
       ;; Subtract old value halves, add new value halves
       (let ((,old-lo (logand ,old-val #xffff))
             (,old-hi (logand (>> ,old-val 16) #xffff))
             (,new-lo (logand ,new-val #xffff))
             (,new-hi (logand (>> ,new-val 16) #xffff)))
         (setf ,csum (- ,csum ,old-lo))
         (setf ,csum (- ,csum ,old-hi))
         (setf ,csum (+ ,csum ,new-lo))
         (setf ,csum (+ ,csum ,new-hi))
         ;; Fold 32-bit to 16-bit with carry
         (setf ,csum (+ (logand ,csum #xffff) (>> ,csum 16)))
         (setf ,csum (+ (logand ,csum #xffff) (>> ,csum 16)))
         ;; Invert back
         (setf ,csum (logand (logxor ,csum #xffff) #xffff))
         ;; Store updated checksum
         (store u16 ,ip-ptr 10 ,csum)))))

;;; Program

(defprog nodeport-lb4 (:type :xdp :section "xdp" :license "GPL")
  (let ((data     (xdp-data))
        (data-end (xdp-data-end)))
    ;; Bounds check: Eth + IPv4 + at least 4 bytes of L4 (src-port + dst-port)
    (when (> (+ data 38) data-end)              ; 14 + 20 + 4 = 38
      (return XDP_PASS))
    ;; Check EtherType is IPv4
    (when (/= (eth-type data) +ethertype-ipv4+)
      (return XDP_PASS))
    (let ((ip    (+ data +eth-hdr-len+))
          (proto (ipv4-protocol (+ data +eth-hdr-len+))))
      ;; Only handle TCP and UDP
      (when (and (/= proto +ip-proto-tcp+) (/= proto +ip-proto-udp+))
        (return XDP_PASS))
      (let ((l4       (+ ip +ipv4-hdr-len+))
            (dst-addr (ipv4-dst-addr ip))
            (dst-port (load u16 (+ ip +ipv4-hdr-len+) 2)))  ; L4 dst-port at offset 2
        ;; Build service lookup key on stack (12 bytes, contiguous)
        (let ((key (make-lb4-svc-key)))
          (setf (lb4-svc-key-addr key) dst-addr)
          (setf (lb4-svc-key-dport key) dst-port)
          (setf (lb4-svc-key-proto key) proto)

          ;; Lookup service (slot 0 = frontend entry)
          (when-let ((svc-val (map-lookup-ptr lb4-services key)))
            ;; Read backend count from service value (offset 4, u16)
            (let ((count (load u16 svc-val 4)))
              (when (> count 0)
                ;; Pick random backend slot: (mod random count) + 1
                (let ((slot (+ (cast u16 (mod (get-prandom-u32) count)) 1)))
                  (declare (type u16 slot))
                  ;; Update key with selected slot
                  (setf (lb4-svc-key-slot key) slot)
                  ;; Lookup backend slot in services map
                  (when-let ((slot-val (map-lookup-ptr lb4-services key)))
                    ;; Read backend_id from slot value (offset 0, u32)
                    (let ((backend-id (load u32 slot-val 0)))
                      ;; Lookup backend by ID
                      (when-let ((be-val (map-lookup lb4-backends backend-id)))
                        ;; Read backend IP and port
                        (let ((be-addr (load u32 be-val 0))
                              (be-port (load u16 be-val 4)))
                          ;; DNAT: rewrite destination IP
                          (let ((old-dst dst-addr))
                            (store u32 ip 16 be-addr)           ; ipv4 dst-addr at offset 16
                            ;; Update IPv4 checksum for IP change
                            (ipv4-csum-update-u32 ip old-dst be-addr))
                          ;; DNAT: rewrite L4 destination port
                          (store u16 l4 2 be-port)              ; L4 dst-port at offset 2
                          ))))))))))))
  XDP_PASS)
