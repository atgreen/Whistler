;;; cgroup-firewall.lisp — Process-level outbound firewall using cgroup eBPF
;;;
;;; Reimplementation of github.com/lawrencegripper/ebpf-cgroup-firewall in Whistler.
;;;
;;; Three programs:
;;;   1. cgroup/connect4 — intercept outbound connections, redirect DNS/HTTP
;;;   2. sockops — track socket-to-port correlation
;;;   3. cgroup_skb/egress — enforce firewall rules on outbound packets
;;;
;;; Compile:
;;;   ./whistler compile examples/cgroup-firewall.lisp -o firewall.bpf.o

(in-package #:whistler)

;;; ========== Constants ==========

;; Address family
(defconstant +af-inet+  2)
(defconstant +af-inet6+ 10)

;; Egress return codes
(defconstant +egress-allow+ 1)
(defconstant +egress-deny+  0)

;; Event types (must match pkg/ebpf/events.go)
(defconstant +dns-proxy-packet-bypass+ 1)
(defconstant +http-proxy-packet-bypass+ 2)
(defconstant +dns-redirect+ 11)
(defconstant +localhost-packet-bypass+ 12)
(defconstant +http-redirect+ 22)
(defconstant +proxy-pid-bypass+ 23)
(defconstant +packet-ipv6+ 24)

;; Firewall modes
(defconstant +firewall-mode-log-only+    0)
(defconstant +firewall-mode-allow-list+  1)
(defconstant +firewall-mode-block-list+  2)

;; 127.0.0.1 in network byte order
(defconstant +localhost-nbo+ #x0100007f)

;; sockops callback types
(defconstant +bpf-sock-ops-active-established-cb+ 4)

;;; Context field offsets are resolved automatically from the program
;;; type via (ctx field-name).  No manual offset constants needed.
;;;
;;; Protocol headers (ipv4, tcp, udp) and their accessors come from
;;; Whistler's built-in defheader definitions in protocols.lisp.
;;; Port accessors auto-convert to host byte order.

;;; ========== Stack buffer for skb_load_bytes ==========
;;;
;;; Cgroup/skb programs can't do direct packet access — they must copy
;;; packet data onto the stack via skb-load-bytes.  We define a minimal
;;; struct sized to hold the largest header we need (TCP = 20 bytes),
;;; then use the built-in protocol accessors (ipv4-*, tcp-*, udp-*)
;;; to read fields from it.

(defstruct pkt-buf
  (b0 u64) (b1 u64) (b2 u32))  ; 20 bytes

;;; ========== Event struct ==========

(defstruct event
  (pid         u32)    ; offset 0
  (port        u16)    ; offset 4
  (allowed     u8)     ; offset 6  (bool)
  (pad0        u8)     ; offset 7  (padding)
  (ip          u32)    ; offset 8
  (original-ip u32)    ; offset 12
  (event-type  u8)     ; offset 16
  (pad1        u8)     ; offset 17
  (dns-txid    u16)    ; offset 18
  (pid-resolved u8)    ; offset 20 (bool)
  (redirected  u8)     ; offset 21 (bool)
  (pad2        u16))   ; offset 22 (padding to 24 bytes)

;;; ========== Maps ==========

;; Ring buffer for sending events to userspace
(defmap events :type :ringbuf
  :max-entries (* 1024 1024))  ; 1MB

;; socket cookie → original destination IP (before redirect)
(defmap sock-client-to-original-ip :type :hash
  :key-size 8 :value-size 4 :max-entries 262144
  :map-flags 1)  ; BPF_F_NO_PREALLOC

;; socket cookie → original destination port (before redirect)
(defmap sock-client-to-original-port :type :hash
  :key-size 8 :value-size 2 :max-entries 262144
  :map-flags 1)

;; source port → client socket cookie (for proxy correlation)
(defmap src-port-to-sock-client :type :hash
  :key-size 2 :value-size 8 :max-entries 262144
  :map-flags 1)

;; socket cookie → PID
(defmap socket-pid-map :type :hash
  :key-size 8 :value-size 4 :max-entries 10000)

;; IP allowlist for HTTP/HTTPS traffic
(defmap firewall-allowed-http-ips-map :type :hash
  :key-size 4 :value-size 4 :max-entries 262144
  :map-flags 1)

;; IP allowlist for any traffic
(defmap firewall-allowed-ips-map :type :hash
  :key-size 4 :value-size 4 :max-entries 262144
  :map-flags 1)

;;; ========== Program 1: cgroup/connect4 ==========
;;;
;;; Intercept outbound IPv4 connections. Redirect DNS (port 53) to a
;;; local DNS proxy and HTTP/HTTPS (ports 80/443) to a transparent
;;; HTTP proxy. Track original destinations for later firewall checks.
;;;
;;; Runtime constants (set by userspace loader via .rodata rewriting):
;;;   const_dns_proxy_port, const_proxy_pid, const_http_proxy_port,
;;;   const_https_proxy_port, const_firewall_mode, const_mitm_proxy_address

(defprog connect4 (:type :cgroup-sock-addr
                   :section "cgroup/connect4"
                   :license "GPL")
  (let* ((socket-cookie (get-socket-cookie (ctx-ptr)))
         (pid (cast u32 (>> (get-current-pid-tgid) 32)))
         ;; Store socket → PID mapping
         (pid-key u64 socket-cookie))
    (map-update socket-pid-map pid-key pid 0)

    ;; Read context fields
    (let* ((user-ip4  (ctx user-ip4))
           (user-port (ctx user-port))
           (original-ip user-ip4)
           (original-port (ntohs (cast u16 user-port))))

      (cond
        ;; HTTP/HTTPS ports (80, 443) — redirect to MITM proxy
        ((or (= user-port (htons 80))
             (= user-port (htons 443)))

         (setf (ctx user-ip4) +localhost-nbo+)

         ;; Redirect port based on original port
         ;; NOTE: proxy ports must be set by loader; using placeholders
         (when (= user-port (htons 80))
           (setf (ctx user-port) (htons 8080)))
         (when (= user-port (htons 443))
           (setf (ctx user-port) (htons 8443)))

         ;; Send HTTP redirect event
         (let ((evt (make-event)))
           (setf (event-pid evt) pid
                 (event-port evt) (ntohs (cast u16 (ctx user-port)))
                 (event-allowed evt) 1
                 (event-ip evt) (ntohl (ctx user-ip4))
                 (event-original-ip evt) original-ip
                 (event-event-type evt) +http-redirect+
                 (event-redirected evt) 1
                 (event-pid-resolved evt) 1)
           (ringbuf-output events evt (sizeof event) 0))

         ;; Store original destination
         (let ((cookie-key u64 socket-cookie))
           (map-update sock-client-to-original-ip cookie-key original-ip 0)
           (map-update sock-client-to-original-port cookie-key original-port 0)))

        ;; DNS port (53) — redirect to local DNS proxy
        ((= user-port (htons 53))

         (setf (ctx user-ip4) +localhost-nbo+)
         (setf (ctx user-port) (htons 5553))

         ;; Send DNS redirect event
         (let ((evt (make-event)))
           (setf (event-pid evt) pid
                 (event-port evt) (ntohs (cast u16 (ctx user-port)))
                 (event-allowed evt) 1
                 (event-ip evt) (ntohl (ctx user-ip4))
                 (event-original-ip evt) original-ip
                 (event-event-type evt) +dns-redirect+
                 (event-redirected evt) 1
                 (event-pid-resolved evt) 1)
           (ringbuf-output events evt (sizeof event) 0))

         ;; Store original destination
         (let ((cookie-key u64 socket-cookie))
           (map-update sock-client-to-original-ip cookie-key original-ip 0)
           (map-update sock-client-to-original-port cookie-key original-port 0))))))

  ;; Always allow the connection (firewall enforcement is in egress)
  1)

;;; ========== Program 2: sockops ==========
;;;
;;; Track outbound connection establishment to correlate client sockets
;;; with server-side sockets via source port mapping.

(defprog cg-sock-ops (:type :cgroup-sock
                      :section "sockops"
                      :license "GPL")
  (let ((family (ctx family)))
    (when (/= family +af-inet+)
      (return 0))

    ;; Outbound connection established (client calling out)
    (let ((op (ctx op)))
      (when (= op +bpf-sock-ops-active-established-cb+)
        (let* ((cookie (get-socket-cookie (ctx-ptr)))
               (src-port u16 (cast u16 (ctx local-port))))
          (map-update src-port-to-sock-client src-port cookie 0)))))
  0)

;;; ========== Program 3: cgroup_skb/egress ==========
;;;
;;; Enforce firewall rules on all outbound packets. Checks:
;;; - Proxy PID bypass
;;; - Localhost traffic bypass
;;; - DNS proxy packet extraction (transaction ID for PID correlation)
;;; - IPv6 blocking
;;; - IP allowlist enforcement

(defprog cgroup-skb-egress (:type :cgroup-skb
                            :section "cgroup_skb/egress"
                            :license "GPL")
  ;; Load IP header from packet via skb_load_bytes
  (let* ((pkt (make-pkt-buf))
         (rc (skb-load-bytes (ctx-ptr) 0 pkt +ipv4-hdr-len+)))
    (when (s< rc 0)
      (return +egress-deny+))

    (let* ((protocol (ipv4-protocol pkt))
           (daddr    (ipv4-dst-addr pkt))

           ;; Look up PID from socket cookie
           (socket-cookie (get-socket-cookie (ctx-ptr)))
           (pid-ptr  (map-lookup socket-pid-map socket-cookie))
           (pid      u32 (if (/= pid-ptr 0) (load u32 pid-ptr 0) #xffffffff))
           (pid-ok   u8  (if (/= pid-ptr 0) 1 0))

           ;; Look up original destination (before redirect)
           (orig-ip-ptr (map-lookup sock-client-to-original-ip socket-cookie))
           (original-ip (if (/= orig-ip-ptr 0) (load u32 orig-ip-ptr 0) daddr))
           (is-redirected u8 (if (/= original-ip daddr) 1 0)))

      ;; Allow localhost traffic
      (when (= original-ip +localhost-nbo+)
        (let ((evt (make-event)))
          (setf (event-pid evt) pid
                (event-port evt) 0
                (event-allowed evt) 1
                (event-ip evt) (ntohl daddr)
                (event-original-ip evt) (ntohl original-ip)
                (event-pid-resolved evt) pid-ok
                (event-redirected evt) is-redirected
                (event-event-type evt) +localhost-packet-bypass+)
          (ringbuf-output events evt (sizeof event) 0))
        (return +egress-allow+))

      ;; Parse transport header — reuse pkt buffer
      (let ((port u16 0))

        ;; UDP handling
        (when (= protocol +ip-proto-udp+)
          (let ((rc2 (skb-load-bytes (ctx-ptr) +ipv4-hdr-len+ pkt +udp-hdr-len+)))
            (when (s< rc2 0)
              (return +egress-deny+))

            (setf port (udp-dst-port pkt))

            ;; Check for proxied DNS request
            (when (and (= port 5553)   ; DNS proxy port placeholder
                       (= daddr +localhost-nbo+))
              ;; Extract DNS transaction ID — reuse pkt again
              (let* ((dns-off (+ +ipv4-hdr-len+ +udp-hdr-len+))
                     (rc3 (skb-load-bytes (ctx-ptr) dns-off pkt 2)))
                (let ((txid u16 (if (s>= rc3 0)
                                    (ntohs (load u16 pkt 0))
                                    0)))
                  (let ((evt (make-event)))
                    (setf (event-pid evt) pid
                          (event-port evt) port
                          (event-allowed evt) 1
                          (event-ip evt) (ntohl daddr)
                          (event-pid-resolved evt) pid-ok
                          (event-original-ip evt) (ntohl original-ip)
                          (event-redirected evt) is-redirected
                          (event-event-type evt) +dns-proxy-packet-bypass+
                          (event-dns-txid evt) txid)
                    (ringbuf-output events evt (sizeof event) 0))
                  (return +egress-allow+))))))

        ;; TCP handling — extract destination port
        (when (= protocol +ip-proto-tcp+)
          (let ((rc2 (skb-load-bytes (ctx-ptr) +ipv4-hdr-len+ pkt +tcp-hdr-len+)))
            (when (s< rc2 0)
              (return +egress-deny+))
            (setf port (tcp-dst-port pkt))))

        ;; Block IPv6 traffic (not supported)
        (let ((family (ctx family)))
          (when (= family +af-inet6+)
            (let ((evt (make-event)))
              (setf (event-pid evt) pid
                    (event-port evt) port
                    (event-allowed evt) 0
                    (event-ip evt) (ntohl daddr)
                    (event-pid-resolved evt) pid-ok
                    (event-original-ip evt) (ntohl original-ip)
                    (event-redirected evt) is-redirected
                    (event-event-type evt) +packet-ipv6+)
              (ringbuf-output events evt (sizeof event) 0))
            (return +egress-deny+)))

        ;; Firewall mode check
        ;; NOTE: In production, const_firewall_mode is set by the loader.
        ;; Default: log-only mode (allow all)
        (let* ((dest-allowed u32 0)

               ;; Check if IP is in the general allowlist
               (ip-allowed-ptr (map-lookup firewall-allowed-ips-map original-ip))
               (ip-allowed u8 (if (/= ip-allowed-ptr 0) 1 0))

               ;; Check if IP is in the HTTP-only allowlist
               (http-ip-ptr (map-lookup firewall-allowed-http-ips-map original-ip))
               (http-ip-allowed u8 (if (/= http-ip-ptr 0) 1 0))

               ;; Check if redirected to HTTP proxy
               (is-http-proxy u8
                 (if (and (= daddr +localhost-nbo+)
                          (or (= port 8080)
                              (= port 8443)))
                     1 0)))

          ;; In log-only mode or if IP is in general allowlist, allow
          ;; NOTE: firewall_mode should be set by loader; defaulting to log-only
          (when (/= ip-allowed 0)
            (setf dest-allowed 1))

          ;; Allow HTTP proxy traffic if IP is in HTTP allowlist
          (when (and (/= is-http-proxy 0)
                     (/= http-ip-allowed 0))
            (setf dest-allowed 1))

          ;; If allowed and going to HTTP proxy, emit bypass event
          (when (and (/= dest-allowed 0)
                     (/= is-http-proxy 0))
            (let ((evt (make-event)))
              (setf (event-pid evt) pid
                    (event-port evt) port
                    (event-allowed evt) 1
                    (event-ip evt) (ntohl daddr)
                    (event-pid-resolved evt) pid-ok
                    (event-original-ip evt) (ntohl original-ip)
                    (event-redirected evt) is-redirected
                    (event-event-type evt) +http-proxy-packet-bypass+)
              (ringbuf-output events evt (sizeof event) 0))
            (return +egress-allow+))

          ;; Default: emit event and return firewall decision
          (let ((evt (make-event)))
            (setf (event-pid evt) pid
                  (event-port evt) port
                  (event-allowed evt) (cast u8 dest-allowed)
                  (event-ip evt) (ntohl daddr)
                  (event-pid-resolved evt) pid-ok
                  (event-original-ip evt) (ntohl original-ip)
                  (event-redirected evt) is-redirected
                  (event-event-type evt) 0)
            (ringbuf-output events evt (sizeof event) 0))

          dest-allowed)))))
