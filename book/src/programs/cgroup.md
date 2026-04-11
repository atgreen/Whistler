# Cgroup

Cgroup BPF programs enforce per-cgroup network and socket policies. The
kernel automatically sets `expected_attach_type` based on the section name,
so the loader does not require extra configuration.

## Program Subtypes

### cgroup_skb

Per-cgroup packet filtering at the SKB level. Return 1 to allow, 0 to
drop.

| Section | Direction |
|---------|-----------|
| `"cgroup_skb/ingress"` | Inbound packets |
| `"cgroup_skb/egress"` | Outbound packets |

```lisp
(defprog count-egress (:type :cgroup-skb
                     :section "cgroup_skb/egress")
  ;; allow all, but could inspect and drop
  1)
```

### cgroup_sock

Socket lifecycle hooks. Return 1 to allow, 0 to deny.

| Section | Event |
|---------|-------|
| `"cgroup/sock_create"` | Socket creation |
| `"cgroup/sock_release"` | Socket close |

```lisp
(defprog audit-sock (:type :cgroup-sock
                     :section "cgroup/sock_create")
  ;; allow all socket creation
  1)
```

### cgroup_sock_addr

Connection and message authorization. Return 1 to allow, 0 to block.

| Section | Operation |
|---------|-----------|
| `"cgroup/connect4"` | IPv4 connect |
| `"cgroup/connect6"` | IPv6 connect |
| `"cgroup/sendmsg4"` | IPv4 UDP sendmsg |
| `"cgroup/sendmsg6"` | IPv6 UDP sendmsg |

```lisp
(defprog filter-connect (:type :cgroup-sock-addr
                         :section "cgroup/connect4")
  ;; allow all IPv4 connections
  1)
```

## BPF Helpers

The following helpers are available in cgroup programs:

| Helper | ID | Description |
|--------|----|-------------|
| `get-socket-cookie` | 47 | Unique cookie identifying the socket |
| `get-current-pid-tgid` | 14 | PID and TGID of current task |
| `get-current-uid-gid` | 15 | UID and GID of current task |
| `ktime-get-coarse-ns` | 161 | Coarse monotonic timestamp |

## Attachment

### Standalone

Use `attach-cgroup` with the cgroup filesystem path and the appropriate
attach type constant:

```lisp
(attach-cgroup prog "/sys/fs/cgroup"
               :attach-type +bpf-cgroup-inet-egress+)
```

Attach type constants:

| Constant | Subtype |
|----------|---------|
| `+bpf-cgroup-inet-ingress+` | cgroup_skb ingress |
| `+bpf-cgroup-inet-egress+` | cgroup_skb egress |
| `+bpf-cgroup-inet-sock-create+` | cgroup_sock create |
| `+bpf-cgroup-inet-sock-release+` | cgroup_sock release |
| `+bpf-cgroup-inet4-connect+` | cgroup_sock_addr connect4 |
| `+bpf-cgroup-inet6-connect+` | cgroup_sock_addr connect6 |
| `+bpf-cgroup-udp4-sendmsg+` | cgroup_sock_addr sendmsg4 |
| `+bpf-cgroup-udp6-sendmsg+` | cgroup_sock_addr sendmsg6 |

### with-bpf-session

Inside a `with-bpf-session`, `bpf:attach` auto-detects the attach type
from the program's section name:

```lisp
(with-bpf-session (session "count-egress.o")
  (bpf:attach session "count-egress"
              :cgroup-path "/sys/fs/cgroup"))
```

## Example: Count Egress Packets

A complete program that counts outbound packets for the root cgroup.

### BPF program

```lisp
(defmap pkt-count :type :array
  :key-size 4
  :value-size 8
  :max-entries 1)

(defprog count-egress (:type :cgroup-skb
                     :section "cgroup_skb/egress")
  (let ((key (u32 0))
        (val (map-lookup pkt-count key)))
    (when val
      (atomic-add val 1)))
  1)
```

### Standalone loader

```lisp
(let* ((obj (bpf:open-object "count-egress.o"))
       (prog (bpf:find-program obj "count-egress"))
       (loaded (bpf:load-program prog)))
  (attach-cgroup loaded "/sys/fs/cgroup"
                 :attach-type +bpf-cgroup-inet-egress+)
  ;; read the counter
  (let ((map (bpf:find-map obj "pkt-count")))
    (format t "packets: ~a~%" (bpf:map-lookup map 0))))
```

### with-bpf-session loader

```lisp
(with-bpf-session (session "count-egress.o")
  (bpf:attach session "count-egress"
              :cgroup-path "/sys/fs/cgroup")
  ;; session auto-detaches on scope exit
  (let ((map (bpf:find-map session "pkt-count")))
    (loop
      (sleep 1)
      (format t "packets: ~a~%" (bpf:map-lookup map 0)))))
```
