# Whistler 0.2.0

## Bug fixes

- **Fixed peephole store-load forwarding bug** that caused incorrect code
  generation when a spilled register was overwritten between the store and
  reload. The BPF verifier would reject programs with "R1 type=scalar
  expected=fp". This affected programs using `probe-read-user` with
  struct-alloc destinations.

## New features

- **BTF-defined maps** — Maps now use the modern `.maps` section with full
  BTF type information (BTF_KIND_VAR, BTF_KIND_DATASEC, struct with
  type/key_size/value_size/max_entries fields). Compatible with current libbpf.
