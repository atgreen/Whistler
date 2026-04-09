# Protocol Library

Whistler includes a compile-time protocol header library in `protocols.lisp`.
All macros expand to `(load TYPE ptr OFFSET)` at compile time -- zero
runtime cost.

## defheader

Define custom protocol headers:

```lisp
(defheader my-proto
  (field-a :offset 0 :type u32)
  (field-b :offset 4 :type u16 :net-order t))
```

Each field generates an accessor macro `(my-proto-FIELD ptr)`. When
`:net-order t`, the accessor wraps the load in `ntohs` / `ntohl` as
appropriate for the field size.

## Built-in headers

### Ethernet (14 bytes)

| Accessor        | Offset | Type | Net-order |
|-----------------|--------|------|-----------|
| `eth-dst-mac-hi` | 0    | u32  | no        |
| `eth-dst-mac-lo` | 4    | u16  | no        |
| `eth-src-mac-hi` | 6    | u32  | no        |
| `eth-src-mac-lo` | 10   | u16  | no        |
| `eth-type`       | 12   | u16  | yes       |

### IPv4 (20 bytes)

| Accessor           | Offset | Type | Net-order |
|--------------------|--------|------|-----------|
| `ipv4-ver-ihl`     | 0      | u8   | no        |
| `ipv4-tos`         | 1      | u8   | no        |
| `ipv4-total-len`   | 2      | u16  | yes       |
| `ipv4-ttl`         | 8      | u8   | no        |
| `ipv4-protocol`    | 9      | u8   | no        |
| `ipv4-src-addr`    | 12     | u32  | no        |
| `ipv4-dst-addr`    | 16     | u32  | no        |

### IPv6 (40 bytes)

Accessors: `ipv6-ver-tc-flow`, `ipv6-payload-len`, `ipv6-nexthdr`,
`ipv6-hop-limit`, `ipv6-src-addr-hi/lo`, `ipv6-dst-addr-hi/lo`.

### TCP (20 bytes)

| Accessor        | Offset | Type | Net-order |
|-----------------|--------|------|-----------|
| `tcp-src-port`  | 0      | u16  | yes       |
| `tcp-dst-port`  | 2      | u16  | yes       |
| `tcp-seq`       | 4      | u32  | yes       |
| `tcp-ack-seq`   | 8      | u32  | yes       |
| `tcp-data-off`  | 12     | u8   | no        |
| `tcp-flags`     | 13     | u8   | no        |
| `tcp-window`    | 14     | u16  | yes       |

### UDP (8 bytes)

Accessors: `udp-src-port`, `udp-dst-port`, `udp-length`, `udp-checksum`.

### ICMP (8 bytes)

Accessors: `icmp-type`, `icmp-code`, `icmp-checksum`, `icmp-rest`.

## XDP context access

CO-RE-aware context loads for XDP programs:

```lisp
(xdp-data)      ;; -> (core-ctx-load u32 0 xdp-md data)
(xdp-data-end)  ;; -> (core-ctx-load u32 4 xdp-md data-end)
```

## Statement-oriented parsing (with-*)

These macros bind packet pointers, perform bounds checks, and
early-return `XDP_PASS` on failure. They use flat guard structure
(no nesting of success paths), which is optimal for the BPF verifier.

```lisp
(with-packet (data data-end :min-len 34) ...)
(with-eth (data data-end) ...)
(with-ipv4 (data data-end ip) ...)
(with-tcp (data data-end tcp) ...)
(with-udp (data data-end udp) ...)
```

Example:

```lisp
(defprog my-xdp (:type :xdp :section "xdp" :license "GPL")
  (with-tcp (data data-end tcp)
    ;; tcp is bound to the TCP header pointer
    ;; data, data-end are bound from XDP context
    (when (= (tcp-dst-port tcp) 80)
      (return XDP_DROP)))
  XDP_PASS)
```

## Expression-oriented parsing (parse-*)

Return a pointer on success or 0 on failure. Use with `when-let` for
pipeline-style composition:

```lisp
(parse-eth data data-end)   ;; returns data or 0
(parse-ipv4 data data-end)  ;; returns IP header ptr or 0
(parse-tcp data data-end)   ;; returns TCP header ptr or 0
(parse-udp data data-end)   ;; returns UDP header ptr or 0
```

Example:

```lisp
(let ((data (xdp-data))
      (data-end (xdp-data-end)))
  (when-let ((tcp (parse-tcp data data-end)))
    (incf (getmap stats (tcp-dst-port tcp)))))
```

## TC variants

Traffic Control programs use `__sk_buff` context (data at offset 76,
data_end at offset 80) and return `TC_ACT_OK` on early exit:

```lisp
(tc-data)       ;; -> (ctx-load u32 76)
(tc-data-end)   ;; -> (ctx-load u32 80)

(with-tc-packet (data data-end :min-len N) ...)
(with-tc-eth (data data-end) ...)
(with-tc-ipv4 (data data-end ip) ...)
(with-tc-tcp (data data-end tcp) ...)
(with-tc-udp (data data-end udp) ...)
```

## Constants

| Constant             | Value  | Category     |
|----------------------|--------|--------------|
| `+ethertype-ipv4+`  | #x0800 | EtherType    |
| `+ethertype-ipv6+`  | #x86dd | EtherType    |
| `+ethertype-arp+`   | #x0806 | EtherType    |
| `+ethertype-vlan+`  | #x8100 | EtherType    |
| `+eth-hdr-len+`     | 14     | Header size  |
| `+ipv4-hdr-len+`    | 20     | Header size  |
| `+ipv6-hdr-len+`    | 40     | Header size  |
| `+tcp-hdr-len+`     | 20     | Header size  |
| `+udp-hdr-len+`     | 8      | Header size  |
| `+icmp-hdr-len+`    | 8      | Header size  |
| `+ip-proto-icmp+`   | 1      | IP protocol  |
| `+ip-proto-tcp+`    | 6      | IP protocol  |
| `+ip-proto-udp+`    | 17     | IP protocol  |
| `+tcp-fin+`         | #x01   | TCP flag     |
| `+tcp-syn+`         | #x02   | TCP flag     |
| `+tcp-rst+`         | #x04   | TCP flag     |
| `+tcp-psh+`         | #x08   | TCP flag     |
| `+tcp-ack+`         | #x10   | TCP flag     |
| `+tcp-urg+`         | #x20   | TCP flag     |
