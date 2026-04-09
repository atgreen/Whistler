# Traffic Control (TC)

TC programs attach to the Linux traffic control layer via the clsact qdisc.
They can filter packets on both ingress and egress, making them useful for
policies that XDP cannot cover (XDP only sees inbound packets).

## Section Name

Use `"tc"` or `"tc/name"`:

```lisp
(defprog my-tc-filter (&key (type :socket-filter)
                            (section "tc/my_filter"))
  TC_ACT_OK)
```

## Return Codes

| Constant | Value | Effect |
|----------|-------|--------|
| `TC_ACT_OK` | 0 | Accept the packet |
| `TC_ACT_SHOT` | 2 | Drop the packet |

## Packet Parsing

TC programs operate on `__sk_buff` instead of `xdp_md`, so packet data
offsets differ from XDP. Whistler provides `with-tc-packet`, `with-tc-tcp`,
and `with-tc-udp` macros that mirror the XDP API but handle the `__sk_buff`
layout:

```lisp
(with-tc-packet ctx (eth-proto ip-src ip-dst ip-proto)
  (with-tc-tcp ctx (src-port dst-port)
    ;; same field names as the XDP macros
    ...))
```

## Attachment

TC programs are attached to an interface's ingress or egress path through a
clsact qdisc. The typical steps from userspace:

```lisp
;; Add a clsact qdisc (idempotent)
(tc-add-clsact "eth0")

;; Attach to egress
(tc-attach prog "eth0" :direction :egress)
```

## Example: Block Outbound Traffic to Port 4444

```lisp
(defprog block-4444 (&key (type :socket-filter)
                          (section "tc/block_4444"))
  (with-tc-packet ctx (eth-proto ip-src ip-dst ip-proto)
    (when (= ip-proto 6)  ;; IPPROTO_TCP
      (with-tc-tcp ctx (src-port dst-port)
        (when (= dst-port 4444)
          TC_ACT_SHOT))))
  TC_ACT_OK)
```
