#!/usr/bin/env bash
# Promote every published @cello-protocol package from `beta` to `latest`.
#
# 🚨 OPERATOR-RUN ONLY. Andre runs this, never an agent — see /cello-publish step 6. An agent may
#    prepare it, dry-run it, and verify the result, but must not execute the promotion itself.
#
# WE PROMOTE, WE DO NOT PIN. Operators install @latest; nobody should ever pin an exact version.
#
# Only packages whose `latest` actually differs are re-tagged. Re-tagging one that is already
# current just emits `npm warn dist-tag add latest is already set to version X` — pure noise.
#
# Versions are read from the repo's package.json files — never hardcoded, because a hardcoded list
# silently re-points `latest` at a stale version the moment a cascade bumps something. The script
# refuses to promote anything whose `beta` on npm does not already equal the local version, which
# is exactly the "CI hasn't finished publishing yet" case.
#
# Run from the cello-client repo root, after `smoke-tag` is green:
#     ./scripts/promote-latest.sh            # verify + promote
#     ./scripts/promote-latest.sh --dry-run  # print what it would do, touch nothing
set -uo pipefail

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

# name:directory. `connect` lives in core/adapter-claude-code. `gateway` is a real workspace dep of
# daemon (it spawns as the sidecar process) and CI publishes it — omitting it leaves `latest`
# inconsistent the first time gateway bumps.
PKGS=(
  "crypto:core/crypto"
  "protocol-types:core/protocol-types"
  "transport:core/transport"
  "client:core/client"
  "gateway:core/gateway"
  "daemon:core/daemon"
  "cli:core/cli"
  "connect:core/adapter-claude-code"
)

echo "=== Verifying beta == local, and finding what actually needs promoting ==="
FAILED=0
declare -a PLAN=()
for entry in "${PKGS[@]}"; do
  name="${entry%%:*}"; dir="${entry#*:}"
  local_ver=$(node -p "require('./$dir/package.json').version") || { echo "  $name: cannot read $dir/package.json"; FAILED=1; continue; }
  beta_ver=$(npm view "@cello-protocol/$name@beta" version 2>/dev/null)
  latest_ver=$(npm view "@cello-protocol/$name@latest" version 2>/dev/null)
  if [[ "$local_ver" != "$beta_ver" ]]; then
    printf "  %-15s local=%-8s beta=%-8s  ✗ NOT PUBLISHED YET\n" "$name" "$local_ver" "${beta_ver:-<none>}"
    FAILED=1
  elif [[ "$local_ver" == "$latest_ver" ]]; then
    # Already there. Re-tagging would only emit `npm warn dist-tag add latest is already set`.
    printf "  %-15s %-8s — latest already current, skipping\n" "$name" "$local_ver"
  else
    printf "  %-15s %-8s ← promoting (latest is %s)\n" "$name" "$local_ver" "${latest_ver:-<none>}"
    PLAN+=("$name@$local_ver")
  fi
done

if (( FAILED )); then
  echo
  echo "REFUSING TO PROMOTE. A package's beta does not match the local source version."
  echo "Wait for the tag CI run's publish + smoke-tag jobs to go green, then re-run."
  exit 1
fi

if (( ${#PLAN[@]} == 0 )); then
  echo
  echo "Nothing to promote — every package's latest already matches its published version."
  exit 0
fi

echo
if (( DRY_RUN )); then
  echo "=== DRY RUN — would promote ${#PLAN[@]} package(s) ==="
  for p in "${PLAN[@]}"; do echo "  npm dist-tag add @cello-protocol/$p latest"; done
  exit 0
fi

echo "=== Promoting to latest ==="
# npm may prompt for browser auth once per session; a `+latest: ...` line confirms each.
for p in "${PLAN[@]}"; do
  npm dist-tag add "@cello-protocol/$p" latest || { echo "FAILED: $p"; FAILED=1; }
done

echo
echo "=== Verifying latest (npm's CDN can lag ~1-2 min; re-run if a line looks stale) ==="
echo "    The '+latest: pkg@ver' lines above are the authoritative confirmation, not this loop."
sleep 5
for p in "${PLAN[@]}"; do
  name="${p%@*}"; want="${p#*@}"
  got=$(npm view "@cello-protocol/$name@latest" version 2>/dev/null)
  mark=$([[ "$want" == "$got" ]] && echo "✓" || echo "… CDN lag, or the tag failed — re-check in a minute")
  printf "  %-15s latest=%-8s (expect %-8s) %s\n" "$name" "${got:-<none>}" "$want" "$mark"
done

exit $FAILED
