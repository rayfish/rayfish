<!--
Keep the title as a conventional commit subject (feat/fix/docs/style/ci/chore/...),
since release notes are generated from commit subjects by git-cliff.
Example: fix(ssh): reuse the host's OpenSSH ed25519 key for mesh SSH
-->

## What this does

<!-- A short description of the change from the user's perspective. -->

## Why

<!-- The motivation, or a linked issue (Closes #123). -->

## How it was tested

<!-- Commands you ran and what you observed. -->

```
cargo -q build
cargo -q test
cargo -q clippy
```

## Checklist

- [ ] Title is a conventional commit subject (`feat`/`fix`/`docs`/`style`/`ci`/...).
- [ ] `cargo -q build`, `cargo -q test`, and `cargo -q clippy` pass.
- [ ] Docs updated (`README.md` / `CLAUDE.md`) if behavior changed.
- [ ] `CHANGELOG.md` updated under `## [Unreleased]` if the change is user-visible.
- [ ] Bumped the relevant ALPN version if a wire protocol changed incompatibly.
