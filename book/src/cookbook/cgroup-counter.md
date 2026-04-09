# Cgroup Packet Counter

Count egress packets for all processes in a cgroup using
`cgroup_skb/egress`. Two approaches: standalone (compile to ELF) and
inline (`with-bpf-session`).

## Approach 1: Inline session

The simplest approach -- compile and load in one form:

```lisp
(require :asdf)
(asdf:load-system "whistler/loader")
(use-package :whistler/loader)

(with-bpf-session ()
  (bpf:map pkt-count :type :array :key-size 4 :value-size 8 :max-entries 1)

  (bpf:prog count-egress
      (:type :cgroup-skb :section "cgroup_skb/egress" :license "GPL")
    (incf (getmap pkt-count 0))
    1)  ;; 1 = allow (SK_PASS for cgroup_skb)

  (bpf:attach count-egress "/sys/fs/cgroup")
  (format t "Counting egress packets on /sys/fs/cgroup...~%")
  (loop repeat 10
        do (sleep 1)
           (format t "  packets: ~d~%" (or (bpf:map-ref pkt-count 0) 0))))
```

The `bpf:attach` macro detects the `cgroup_skb/egress` section name and
automatically calls `attach-cgroup` with `+bpf-cgroup-inet-egress+`.

## Approach 2: Standalone ELF

Compile to an ELF file first, then load and attach separately.

### BPF source

```lisp
(in-package #:whistler)

(defmap pkt-count :type :array
  :key-size 4 :value-size 8 :max-entries 1)

(defprog count-egress
    (:type :cgroup-skb :section "cgroup_skb/egress" :license "GPL")
  (incf (getmap pkt-count 0))
  1)

(compile-to-elf "/tmp/cgroup-count.bpf.o")
```

### Userspace loader

```lisp
(asdf:load-system "whistler/loader")

(whistler/loader:with-bpf-object (obj "/tmp/cgroup-count.bpf.o")
  (let ((map (whistler/loader:bpf-object-map obj "pkt_count")))
    (whistler/loader:attach-obj-cgroup
     obj "count_egress" "/sys/fs/cgroup"
     whistler/loader:+bpf-cgroup-inet-egress+)

    (format t "Counting egress packets on /sys/fs/cgroup...~%")
    (loop repeat 10
          do (sleep 1)
             (let ((val (whistler/loader:map-lookup
                         map
                         (whistler/loader:encode-int-key 0 4))))
               (format t "  packets: ~d~%"
                       (if val (whistler/loader:decode-int-value val) 0))))))
```

## Key points

- **Return value**: `cgroup_skb` programs return `1` to allow the packet
  (SK_PASS) or `0` to drop it. This counter always returns `1`, so it
  observes without blocking traffic.

- **Cgroup path**: `/sys/fs/cgroup` is the root cgroup on cgroup2
  systems, affecting all processes. Use a more specific path (e.g.,
  `/sys/fs/cgroup/user.slice/...`) to monitor only certain processes.

- **Auto-detection**: The loader infers `expected_attach_type`
  automatically from the ELF section name (`cgroup_skb/egress` maps to
  `+bpf-cgroup-inet-egress+`). In the inline session, `bpf:attach` does
  this too -- no explicit constant needed.

- **Cleanup**: Both `with-bpf-session` and `with-bpf-object` detach the
  program and close file descriptors automatically on exit.

## Running

Requires root (or `CAP_BPF` + `CAP_NET_ADMIN`):

```bash
sudo sbcl --load cgroup-counter.lisp
```

Expected output:

```
Counting egress packets on /sys/fs/cgroup...
  packets: 42
  packets: 97
  packets: 158
  ...
```
