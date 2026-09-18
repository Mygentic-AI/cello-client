#!/usr/bin/env bash
# ── KEEP BUILD OUTPUT OUT OF iCLOUD ──────────────────────────────────────────────────────────────
#
# This repo lives under ~/Documents, which is iCloud-synced on an account that is full. A clean
# rebuild writes several thousand files into `core/*/dist`, iCloud queues every one of them, and
# `iCloudDriveCore` then pins a core at ~99% for many minutes. Measured 2026-09-18: load average
# 22.5, and three consecutive full test runs failed with 36-42 TIMEOUTS and zero assertion failures
# — a green suite reported as broken, with a different failing set each run. That is the worst kind
# of red, because it looks like a defect in whatever was last touched.
#
# macOS excludes any path whose name ends in `.nosync`. `node_modules` in this repo has been a
# `node_modules -> node_modules.nosync` symlink since 2026-08-18 for exactly this reason; this does
# the same for build output. tsc writes through the symlink without knowing it is one.
#
# THIS RUNS AS `prebuild`, not once by hand, because `pnpm run clean` and any `rm -rf core/*/dist`
# deletes the SYMLINK — after which tsc recreates a real, synced directory and the problem is back.
# Re-establishing it before every build is what makes the fix survive.
#
# Idempotent and safe to run at any time: an existing real `dist` is moved into place rather than
# deleted, so nothing that was built is lost.
#
# ⚠️ macOS ONLY, AND THAT GUARD IS LOAD-BEARING — it was missing for one release and broke it.
# `pnpm publish` packs `dist/`, and packing a SYMLINKED directory drops its contents: v0.0.320
# shipped a `protocol-types` tarball holding ONE file where the previous version held 128. The
# packages were structurally empty. Nothing reached an operator only because `latest` had not moved
# — which is exactly why promotion is a separate step from publishing.
#
# CI runs on Linux, where there is no iCloud and nothing to exclude, so the fix is to do nothing
# there. `CI` is checked as well as the platform, so a macOS runner could not reintroduce it either.
set -euo pipefail

if [ "$(uname)" != "Darwin" ] || [ "${CI:-}" = "true" ]; then
  exit 0
fi

cd "$(dirname "$0")/.."

for dir in core/*/; do
  target="${dir}dist"
  nosync="${dir}dist.nosync"

  # Already a symlink: make sure it points where we think, and move on.
  if [ -L "$target" ]; then
    [ -d "$nosync" ] || mkdir -p "$nosync"
    continue
  fi

  # A real directory: move its contents into the .nosync twin, then replace it with the link.
  if [ -d "$target" ]; then
    mkdir -p "$nosync"
    # `mv` of the directory itself would fail when the twin exists, so move the contents.
    if [ -n "$(ls -A "$target" 2>/dev/null)" ]; then
      mv "$target"/* "$nosync"/ 2>/dev/null || true
      mv "$target"/.[!.]* "$nosync"/ 2>/dev/null || true
    fi
    rmdir "$target"
  fi

  mkdir -p "$nosync"
  ln -s "dist.nosync" "$target"
done
