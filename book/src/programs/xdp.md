# XDP

XDP (eXpress Data Path) programs run at the earliest possible point in the
network receive path, before the kernel allocates an `sk_buff`. This makes
them the fastest option for packet processing.

## Section Name

Use `"xdp"` for a single program or `"xdp/name"` to distinguish multiple
XDP programs in the same ELF:

```lisp
(defprog my-filter (:type :xdp :section "xdp/my_filter")
  XDP_PASS)
```

## Return Codes

| Constant | Value | Effect |
|----------|-------|--------|
| `XDP_ABORTED` | 0 | Error path, triggers tracepoint |
| `XDP_DROP` | 1 | Silently drop the packet |
| `XDP_PASS` | 2 | Pass to the normal network stack |
| `XDP_TX` | 3 | Bounce the packet back out the same interface |
| `XDP_REDIRECT` | 4 | Redirect to another interface or CPU |

## Packet Context

The program receives an `xdp_md` pointer implicitly. Use the zero-argument
macros `xdp-data` and `xdp-data-end` to get the packet boundaries:

```lisp
(defprog check-len (:type :xdp)
  (let ((data (xdp-data))
        (data-end (xdp-data-end)))
    (if (< (- data-end data) 14)
        XDP_DROP
        XDP_PASS)))
```

## Packet Parsing Macros

Whistler provides `with-packet`, `with-tcp`, and `with-udp` to safely
parse protocol headers with automatic bounds checking.

`with-packet` binds `data` and `data-end` from the XDP context and
checks a minimum packet length:

```lisp
(with-packet (data data-end :min-len 14)
  ;; headers are bounds-checked; body only runs if valid
  ...)
```

`with-tcp` and `with-udp` build on `with-packet` to also parse
transport layer headers:

```lisp
(with-tcp (data data-end tcp)
  ;; Ethernet, IP, and TCP headers are bounds-checked
  (tcp-dst-port tcp)
  ...)
```

## Example: Drop TCP Port 9999

```lisp
(defprog drop-9999 (:type :xdp :section "xdp/drop_9999")
  (with-tcp (data data-end tcp)
    (when (= (tcp-dst-port tcp) 9999)
      (return XDP_DROP)))
  XDP_PASS)
```

## Attachment

From userspace, attach with `attach-xdp`:

```lisp
(attach-xdp prog "eth0" :mode "xdpgeneric")
```

| Mode | Description |
|------|-------------|
| `"xdp"` | Let the kernel choose driver or generic |
| `"xdpdrv"` | Native driver mode (fastest, requires driver support) |
| `"xdpgeneric"` | Generic mode (works on any interface, slower) |
| `"xdpoffload"` | Offload to NIC hardware |
