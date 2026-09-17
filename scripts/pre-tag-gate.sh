#!/usr/bin/env bash
# ── PRE-TAG GATE — the required step before any release tag ──────────────────────────────────────
#
# Runs what CI's "Build and Test" job runs — build, typecheck, lint, the FULL test suite — against
# the exact commit about to be tagged, and records that commit only if every step passes.
#
# The publish guard hook (trustless-cello/.claude/hooks/cello-publish-guard.sh) refuses to create or
# push a `v*` tag unless the tag's commit is the one recorded here. So a tag cannot be pushed on the
# strength of:
#   - another session's test report (v0.0.316, 2026-09-17: three suites green, the claims scanner in
#     `connect` never run, CI failed after the tag),
#   - a run of only the packages you think you changed,
#   - a green run on an earlier commit.
#
# Usage (from anywhere):  cello-client/scripts/pre-tag-gate.sh
set -euo pipefail

cd "$(dirname "$0")/.."
marker="$HOME/.cache/.cello-pre-tag-gate"
rm -f "$marker"   # a failed run must never leave an earlier pass standing

# A dirty tree means the thing tested is not the thing tagged. Untracked files count: vitest and
# tsc read them, and the tag does not carry them.
dirty="$(git status --porcelain)"
if [ -n "$dirty" ]; then
  echo "PRE-TAG GATE: FAILED — the working tree is not clean, so what gets tested is not what gets tagged:" >&2
  echo "$dirty" >&2
  echo "Commit or remove these, then run the gate again." >&2
  exit 1
fi

sha="$(git rev-parse HEAD)"
echo "PRE-TAG GATE: testing $sha"

step () { echo; echo "── $1"; shift; "$@" || { echo "PRE-TAG GATE: FAILED at '$*' on $sha. Nothing recorded — the tag stays blocked." >&2; exit 1; }; }

step "install (frozen lockfile, as CI)" pnpm install --frozen-lockfile
step "build"                            pnpm run build
step "typecheck"                        pnpm run typecheck
step "lint"                             pnpm run lint
step "test — the WHOLE suite, every package" pnpm run test

# The tree must still be the one that was tested: a step that rewrote a file would otherwise be
# recorded as passing on a commit that no longer describes the tree.
if [ -n "$(git status --porcelain)" ] || [ "$(git rev-parse HEAD)" != "$sha" ]; then
  echo "PRE-TAG GATE: FAILED — the tree or HEAD changed while the gate ran. Nothing recorded." >&2
  exit 1
fi

mkdir -p "$(dirname "$marker")"
printf '%s\n' "$sha" > "$marker"
echo
echo "PRE-TAG GATE: PASSED on $sha. You may tag THIS commit. Any later commit needs the gate again."
