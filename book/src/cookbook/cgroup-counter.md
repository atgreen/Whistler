# Cgroup Packet Counter

Count egress packets for all processes in a cgroup using `cgroup_skb/egress`.

## Inline session

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
    1)  ; 1 = allow (SK_PASS)

  (bpf:attach count-egress "/sys/fs/cgroup")
  (format t "Counting egress packets...~%")
  (loop repeat 10
        do (sleep 1)
           (format t "  packets: ~d~%" (or (bpf:map-ref pkt-count 0) 0))))
```

Run with root:

```sh
sudo sbcl --load cgroup-counter.lisp
```

The `bpf:attach` macro detects the `cgroup_skb/egress` section name and
automatically calls `attach-cgroup` with `+bpf-cgroup-inet-egress+`.

## Standalone ELF

Compile to an ELF file first, then load and attach separately:

```lisp
(in-package #:whistler)

(defmap pkt-count :type :array
  :key-size 4 :value-size 8 :max-entries 1)

(defprog count-egress
    (:type :cgroup-skb :section "cgroup_skb/egress" :license "GPL")
  (incf (getmap pkt-count 0))
  1)

(compile-to-elf "cgroup-count.bpf.o")
```

Then load and attach:

```lisp
(whistler/loader:with-bpf-object (obj "cgroup-count.bpf.o")
  (whistler/loader:attach-obj-cgroup
   obj "count_egress" "/sys/fs/cgroup"
   whistler/loader:+bpf-cgroup-inet-egress+)
  (let ((map (whistler/loader:bpf-object-map obj "pkt_count")))
    (loop repeat 10
          do (sleep 1)
             (let ((val (whistler/loader:map-lookup
                         map (whistler/loader:encode-int-key 0 4))))
               (format t "  packets: ~d~%"
                       (if val (whistler/loader:decode-int-value val) 0))))))
```

## Key points

- `cgroup_skb` programs return `1` to allow or `0` to drop. This counter
  always returns `1`, so it observes without blocking.
- The cgroup path `/sys/fs/cgroup` is the root cgroup on cgroup2 systems.
  Use a more specific path to monitor only certain processes.
- The loader sets `expected_attach_type` automatically from the ELF section
  name -- no manual configuration needed.
- Cleanup is automatic: `with-bpf-session` and `with-bpf-object` both
  detach the program and close file descriptors on exit.
