# Whistler 1.4.0 Release Notes

## New Features

- Add LRU hash map type support (`:lru-hash` in `defmap`). LRU hash maps
  automatically evict least-recently-used entries when full.

## Bug Fixes

- Fix helper call argument clobbering with parallel-move resolution (issue #31).
