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

Create `doc/release-notes/RELEASE-NOTES-X.Y.Z.md`. Include only
user-facing changes:
- Bug fixes
- New features
- Breaking changes (if any)

Do NOT include internal changes (refactors, lint fixes, doc updates,
CI changes, directory reorganization). Those are visible in the git
log for anyone who needs them.

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

### 6. GitHub Release (Automated)

Pushing a tag triggers GitHub Actions, which automatically builds the
binary, creates the GitHub release, and attaches the artifact. No
manual steps required.

## Build Details

Whistler is built using ASDF's `program-op`:

```bash
sbcl --eval '(require :asdf)' \
     --eval '(push #p"./" asdf:*central-registry*)' \
     --eval '(asdf:make "whistler")'
```

This produces a standalone binary. The version comes from `:version` in
`whistler.asd`.

### Dependencies

- **Build:** SBCL 2.0+ (no external CL libraries required)
- **Runtime:** None (standalone binary)
- **Optional:** clang (for compiling C reference programs), bpftool/readelf (for inspecting output)
