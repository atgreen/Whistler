---
name: make-release
description: Cut a new Whistler release. Bumps the version in whistler.asd, verifies all examples compile, generates release notes, commits, tags, and pushes. Use when asked to "release", "cut a release", "bump version", or "tag a new version".
argument-hint: "[version]"
disable-model-invocation: true
allowed-tools: Bash Read Edit Write Grep Glob
---

# Release Whistler

Follow these steps exactly, stopping on any failure.

## 1. Determine version

If the user provided a version (`$ARGUMENTS`), validate that it matches `MAJOR.MINOR.PATCH` where each component is a non-negative integer (e.g. `1.7.0`). If it doesn't, stop and tell the user.

If no version was provided, suggest one:

1. Read the current version from `:version` in `whistler.asd`.
2. Review commits since the last tag:
   ```bash
   git log $(git describe --tags --abbrev=0)..HEAD --oneline
   ```
3. Apply semver rules:
   - **MAJOR** bump: commits contain breaking changes (removed features, changed APIs, incompatible behavior)
   - **MINOR** bump: commits add new features, new surface-language forms, new loader capabilities
   - **PATCH** bump: commits are only bug fixes, documentation, or internal improvements
4. Present the suggested version with a one-line rationale and ask the user to confirm or override.

Use the confirmed version as VERSION for all subsequent steps.

**Check the tag doesn't already exist:**
```bash
git tag -l "vVERSION"
```
If output is non-empty, stop — this version has already been released.

**Ensure clean working tree:**
```bash
git status --porcelain
```
If there are staged or unstaged changes to **tracked** files, stop and ask the user to commit or stash first.

Then check untracked files. If any look like they don't belong in the repo (log files, binaries, build artifacts, temp files, editor backups, etc.), list them and ask the user whether to clean up, add to `.gitignore`, or proceed anyway. Benign untracked files (e.g. `.claude/`, local config) are fine to ignore silently.

**Verify git identity:**
```bash
git config user.email
```
If the result is not `green@moxielogic.com`, stop and tell the user their git email is misconfigured for this repository.

**Ensure we're on main and synced with remote:**
```bash
git branch --show-current
git fetch origin main
git rev-list HEAD..origin/main --count
```
If the branch is not `main`, or there are upstream commits not yet pulled, stop and tell the user.

**Check CI is green on HEAD:**
```bash
gh run list --branch main --limit 1 --json conclusion --jq '.[0].conclusion'
```
If the result is not `success`, stop and warn the user that CI is failing on main. Ask whether to proceed anyway.

## 2. Update version

Edit `whistler.asd` and set `:version` to `VERSION`.

## 3. Verify all examples compile

```!
make clean && make 2>&1 | tail -3
```

Run each example through the compiler:

```bash
for f in examples/*.lisp; do
  echo "Compiling $f ..."
  sbcl --noinform --non-interactive \
    --eval '(require :asdf)' \
    --eval '(push #P"." asdf:*central-registry*)' \
    --eval '(asdf:load-system "whistler")' \
    --eval "(whistler::compile-file* \"$f\" \"/tmp/$(basename "$f" .lisp).bpf.o\")" \
    2>&1
done
```

If any example fails to compile, stop and report the failure. Do NOT continue.

## 4. Run the test suite

```bash
XDG_CACHE_HOME=/tmp/.cache make test
```

If any tests fail, stop and report the failure. Do NOT continue.

## 5. Generate release notes

Create `doc/release-notes/RELEASE-NOTES-VERSION.md`.

To decide what goes in the notes, diff against the most recent tag:

```bash
git log $(git describe --tags --abbrev=0)..HEAD --oneline
```

Include ONLY user-facing changes:
- Bug fixes
- New features
- Breaking changes (if any)

Do NOT include internal changes (refactors, lint fixes, doc updates, CI changes, directory reorganization). Those are visible in the git log for anyone who needs them.

Match the voice and format of previous release notes in `doc/release-notes/`.

## 6. Commit

```bash
git add whistler.asd doc/release-notes/RELEASE-NOTES-VERSION.md
git commit -m "Bump version to VERSION"
```

## 7. Tag and push

Ask the user for confirmation before pushing, then:

```bash
git tag -s vVERSION -m "Release VERSION"
git push origin main
git push origin vVERSION
```

Pushing the tag triggers GitHub Actions which automatically builds the binary, creates the GitHub release, and attaches the artifact.
