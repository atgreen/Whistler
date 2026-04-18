# Whistler 1.6.2 Release Notes

## Bug Fixes

- **TC detach scoped to our filter**: Previously, detaching a TC program
  removed all filters in the direction. Now only the specific pinned
  filter is cleaned up.

- **cgroup bind/post_bind support**: `cgroup/bind4`, `cgroup/bind6`,
  `cgroup/post_bind4`, and `cgroup/post_bind6` sections now correctly
  map to their expected attach types, fixing kernel load failures.

- **Tracepoint per-CPU attachment**: Tracepoint perf events are now
  opened on all online CPUs instead of only CPU 0. CPU enumeration
  uses actual IDs from sysfs, fixing attachment on sparse CPU
  topologies.

- **Removed dead `map-lookup-delete` code** that referenced a constant
  no longer present.
