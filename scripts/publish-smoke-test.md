# Publish Smoke Test — @cello-protocol/connect

This procedure verifies that the npm publish path works end-to-end before
REPOSPLIT-002 needs it for a real release. Run this once after REPOSPLIT-001
merges to main and CI is green on the scaffold.

## Why this exists

First-run npm auth failures are a real class of problem. M5 DEPLOY-004 had
8 first-run failures catching NPM_TOKEN type issues (classic vs granular),
IP restrictions, 2FA blocks, and publishConfig problems. This smoke test
catches all of those before REPOSPLIT-002 needs the publish path for real.

Zero cost if it works; saves hours if it doesn't.

---

## Prerequisites

1. REPOSPLIT-001 is merged to `main` in cello-client.
2. CI is green on the scaffold (build, typecheck, test all pass).
3. `NPM_TOKEN` is configured in GitHub repository secrets:
   - Go to: https://github.com/Mygentic-AI/cello-client/settings/secrets/actions
   - Add: `NPM_TOKEN` = your npm access token
   - Token type: Granular token OR Classic token with `publish` scope
   - Scope: must cover the `@cello-protocol` npm organization

## What the CI publish step does

The CI workflow (`.github/workflows/ci.yml`) publish step:

```yaml
- name: Publish to npm (tags only)
  if: startsWith(github.ref, 'refs/tags/')
  run: pnpm publish --filter @cello-protocol/connect --access public --no-git-checks
  env:
    NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

It runs only when a version tag is pushed (e.g., `v0.0.1`). It publishes
the `@cello-protocol/connect` package only (the adapter).

## Step 1 — Push the smoke test tag

```bash
cd /Users/andrep/Documents/code/cello-client
git tag v0.0.0-scaffold.1
git push origin v0.0.0-scaffold.1
```

This triggers the CI workflow. The publish step runs because the ref is
a tag matching `refs/tags/*`.

## Step 2 — Monitor the CI run

Watch the workflow at:
https://github.com/Mygentic-AI/cello-client/actions

The run should complete all steps including Publish. Look for:
- "Successfully published @cello-protocol/connect@0.0.1" in the publish step output
- The package appearing at: https://www.npmjs.com/package/@cello-protocol/connect

## Step 3 — Verify the published package

```bash
npm view @cello-protocol/connect@0.0.0-scaffold.1
```

Expected output includes:
- `"publishConfig": { "access": "public" }`
- The scaffold stub only — no real code

## Step 4 — Deprecate immediately

The scaffold publish is a smoke test, not a real release. Deprecate it
immediately so no agent accidentally installs it:

```bash
npm deprecate @cello-protocol/connect@0.0.0-scaffold.1 \
  "Scaffold smoke test — not functional. Use v0.1.0 or later."
```

Alternatively, unpublish (only within 72 hours of publish):
```bash
npm unpublish @cello-protocol/connect@0.0.0-scaffold.1
```

## Troubleshooting

### NPM_TOKEN is not working

Check token type:
- Classic tokens: need `publish` scope, not IP-restricted
- Granular tokens: must have `Read and write` permission for `@cello-protocol/*`
  packages, and the token must be for the correct npm organization/user

Check 2FA: npm accounts with 2FA-on-publish require automation tokens or
granular tokens — interactive 2FA tokens do not work in CI.

### publishConfig.access is missing

The package.json for `core/adapter-claude-code` must have:
```json
"publishConfig": { "access": "public" }
```

Without this, scoped packages (`@cello-protocol/connect`) default to
private and the publish fails with `npm ERR! 402 Payment Required`.

### pnpm publish fails with "workspace:*" dependencies

If any dependency uses `workspace:*` version specifiers, pnpm publish
must be run with `--no-git-checks` and after `pnpm install`. The
`--filter` flag ensures only the correct package is published.

After REPOSPLIT-002 extracts real code, all dependencies will be pinned
versions pointing to published npm packages (not workspace:*).

---

## Post-verification checklist

After the smoke test passes:

- [ ] `@cello-protocol/connect@0.0.0-scaffold.1` is deprecated or unpublished
- [ ] NPM_TOKEN type and scope confirmed working from GitHub runners
- [ ] publishConfig.access confirmed working for scoped package
- [ ] Tag-based trigger confirmed firing correctly
- [ ] REPOSPLIT-002 can proceed with confidence that the publish path works
