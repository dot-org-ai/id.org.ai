# Phase 0 · Preflight

> **For agentic workers:** run this phase from `../autopilot.md`. Don't write product code in this phase.

**Goal:** Start from a known-good baseline. Confirm the branch, the toolchain and the existing test suite, and set up progress tracking, so every later phase measures against something real.

**Depends on:** nothing.

**Read first:** `../README.md`, `../DECISIONS.md`, `../autopilot.md`. Skim every file in `../spec/`.

## Tasks

### Task 1 · Branch
- [ ] Confirm `git branch --show-current` is `product-update`.
- [ ] Confirm it contains `origin/release/main-with-security-fixes`: `git merge-base --is-ancestor origin/release/main-with-security-fixes HEAD`.
- [ ] If the branch has no upstream yet, run `git push -u origin product-update`. Then `git pull --rebase`.
- [ ] If the release branch moved, merge it into `product-update` (`git merge origin/release/main-with-security-fixes`), run the tests, and push.
- [ ] Record the base commit in `../PROGRESS.md`.

### Task 2 · In-flight branches
- [ ] For `origin/feat/upstream-microsoft-federation`, `origin/feat/mcp-authorization-server-2`, `origin/hotfix/login-state-binding`, `origin/fix/relying-party-live` and `origin/cli/refresh-issuing-client`, run `git log HEAD..origin/<b> --format='%h %s'`.
- [ ] Record in PROGRESS which commits are not on this branch. Most were cherry-picked into the release branch under different hashes, so compare subjects.
- [ ] **Do not merge them.** `worker/views/email-code.ts` and `/federation/*` on the federation branch are superseded by phase 7. If a later phase touches the same files, note the expected conflict in PROGRESS.

### Task 3 · Toolchain and baseline
- [ ] `pnpm install`.
- [ ] `pnpm typecheck` and `pnpm test`. Record the pass and fail counts in PROGRESS.
- [ ] Record pre-existing failures by name. A pre-existing failure never blocks a phase, but a new failure always does.
- [ ] `cd worker && npx wrangler deploy --dry-run --outdir /tmp/idorg-dry`. Record the outcome. This is the bundle check every phase repeats.

### Task 4 · Tracking
- [ ] If `bd` is installed, create an epic "Auth UI redesign (product-update)" with one issue per phase (titles from `../PROGRESS.md`). Otherwise use PROGRESS.md alone.
- [ ] Fill in the PROGRESS header: base commit, date, toolchain versions (node, pnpm, wrangler).

## Acceptance
- PROGRESS.md has the base commit, the baseline test counts, any pre-existing failures, the in-flight branch notes, and the dry-run result.
- Nothing outside `docs/product-update/PROGRESS.md` (and `.beads/` if bd is used) has changed since the commit that added this docs package.

## Commit
`chore(product-update): preflight baseline` → push.
