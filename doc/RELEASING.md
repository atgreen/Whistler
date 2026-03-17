# Release Process for Whistler

This document describes how to create a new release of Whistler.

## Prerequisites

- Push access to the Whistler repository
- Git configured with your credentials

## Release Steps

### 1. Update Version Number

Update the version in `whistler.asd`:

```lisp
:version "X.Y.Z"
```

### 2. Verify All Examples Compile

```bash
make clean && make
for f in examples/*.lisp; do
  ./whistler compile "$f" -o /tmp/$(basename "$f" .lisp).bpf.o
done
```

### 3. Create Release Notes

Document:
- Summary of changes
- New features
- Bug fixes
- Breaking changes (if any)

### 4. Commit Changes

```bash
git add whistler.asd
git commit -m "Boost version to X.Y.Z"
```

### 5. Create and Push Tag

```bash
git tag vX.Y.Z
git push origin main
git push origin vX.Y.Z
```

### 6. Build Binary

```bash
make clean && make
./whistler --version   # verify: whistler X.Y.Z
```

### 7. Create GitHub Release

Create a release at `https://github.com/atgreen/Whistler/releases/tag/vX.Y.Z`
and attach the `whistler` binary.

### 8. Test

```bash
./whistler compile examples/count-xdp.lisp
./whistler compile examples/ringbuf-events.lisp --gen c
./whistler --version
```

## Build Details

Whistler is built using ASDF's `program-op`:

```bash
sbcl --eval '(require :asdf)' \
     --eval '(push #p"./" asdf:*central-registry*)' \
     --eval '(asdf:make "whistler")'
```

This produces a standalone binary with the `cl-version-string` library
embedding the git hash in the version string (e.g., `0.1.0-gabcdef`).

### Dependencies

- **Build:** SBCL 2.0+, cl-version-string (via ocicl)
- **Runtime:** None (standalone binary)
- **Optional:** clang (for compiling C reference programs), bpftool/readelf (for inspecting output)
