# Dead Code Report — M6→M7 (Single-MCP-Tool → Daemon) Migration

**Repository:** `cello-client` (`@cello-protocol/connect` and sibling `@cello-protocol/*` packages)
**Date:** 2026-07-12
**Purpose:** Identify code left behind by the M6→M7 architecture change, in which `cello-mcp`
stopped being an in-process client (holding key material, a libp2p node, and a SQLCipher DB) and
became a thin stdio-to-IPC proxy in front of the `cello-daemon` process.

> This document is a planning artifact. It records *what is dead* and *why*. It does not change any
> code. Removal is tracked as its own story (see [Recommended Next Steps](#recommended-next-steps)).

---

## Method

Reachability was traced from the four real production entrypoints:

- `core/daemon/src/bin/cello-daemon.ts`
- `core/adapter-claude-code/src/bin/cello-mcp.ts`
- `core/cli/src/bin/cello.ts`
- `core/gateway/src/bin/cello-gateway.ts` — the security-gateway sidecar `@cello-protocol/gateway`
  ships as a `cello-gateway` bin, and the daemon spawns it as a separate process. It has no
  in-repo importer (nothing imports a bin), so it must be listed as a root or it is wrongly flagged
  dead. `scripts/reachability.mjs` was corrected to include it.

The full file-level result is checked in at `docs/reachability-baseline.json` (regenerated
2026-07-12 against the current tree). Of 168 tracked source files, **35 (21%) are unreachable from
any entrypoint.**

This report groups those 35 files into the stories they belong to, explains *why* each is dead, and
cross-references the codebase's own history where the dead code has already been named and
deliberately deferred.

---

## 🔴 Headline finding — the entire `@cello-protocol/client` package is dead (26 files, ~13,000 LOC)

`@cello-protocol/client` was the M6-era in-process client: key material, libp2p node, SQLCipher
store, session/seal state machines — everything the daemon now owns and runs as a single
long-lived process. The package is still published to npm on every release
(`.github/workflows/ci.yml`, `pnpm publish --filter @cello-protocol/client`) and CI even smoke-tests
that its module graph loads post-publish — despite nothing in the shipped runtime ever constructing
it.

This is not a new discovery: the codebase already enforces it via a dedicated test,
**`core/daemon/src/__tests__/daemon-004-stack-retirement.test.ts`** (CELLO-M7-DAEMON-004, SI-002 /
AC-006), which greps daemon + adapter production source *and built dist bundles* for `new
CelloClient`, `session-manager`, and `seal-manager`, and asserts `daemon/package.json` does not
depend on `@cello-protocol/client` at all. `daemon.ts` only *mentions* the package in a comment:

> "We reimplement natively here — the daemon never imports @cello-protocol/client."

### Why it isn't fully gone yet

Two legacy in-process MCP servers keep re-exporting (and therefore keep "using") the package, even
though no production entrypoint calls either of them:

| File | LOC | Role | Reachable from production? |
|---|---|---|---|
| `core/adapter-claude-code/src/server.ts` | 647 | M1-era `createMcpServer(node, client, keyProvider)` — the original in-process MCP tool set, built directly on `CelloClient` | No — exported from connect's `index.ts`, but `bin/cello-mcp.ts` (the real M7 shim to `~/.cello/daemon.sock`) never imports it. Only referenced by its own tests. |
| `core/client/src/mcp-server.ts` | 1,739 | `createMcpSessionServer` — client-package-local MCP wiring | No — same story, one level further down. |

This is a **named, open story in the repo's own commit history**: `9352b76` ("DELETE
receive-session — no alias, no dead handler") explicitly calls this out and defers it:

> "Left alone deliberately: the legacy in-process MCP servers (adapter/server.ts,
> client/mcp-server.ts) still define cello_receive_session, but there it is a REAL primary tool
> with its own implementation, not an alias. That is **DOD-LEGACY-MCP-1** (delete the dead
> exports), a separate unit — not silently folded in here."

The three most recent commits on `main` (`59465f4`, `5eb9216`, `db67d10`) only **bounded and
disclosed** the quarantine — they added a test (`dod-onboard-help-1-tool-parity.test.ts`) asserting
`server.ts` is the *only* file allowed to still name a renamed-away tool, so the dead surface can't
silently grow. They did not delete it. **DOD-LEGACY-MCP-1 remains outstanding.**

### The rest of the dead `@cello-protocol/client` tree

Everything below is dead as a consequence of the above — it's the implementation these two dead
servers sit on top of. All 26 files in `core/client/src/` (excluding `__tests__/`) are unreachable
from production:

```
agent-hash-queue.ts            connection-inbound-handler.ts   registration-manager.ts
backup-key-derivation.ts       connection-manager.ts           relay-stream-manager.ts
client-backup.ts               connection-policy.ts            s3-cloud-storage-provider.ts
client-send-helpers.ts         db-key-derivation.ts             seal-manager.ts
client-startup.ts              encrypted-file-signing-key-provider.ts   session-assignment-parser.ts
client-state-persistence.ts    frame-dispatch.ts                session-manager.ts
client-wiring.ts                index.ts                        signaling-manager.ts
client.ts                       mcp-server.ts                    sqlcipher-client-store.ts
                                network-directory-node.ts        types.ts
```

---

## 🟠 M6-era single-process mechanisms superseded by daemon equivalents

### `core/adapter-claude-code/src/lock-file.ts`

CELLO-M6B-001's PID-lock manager: "Every new cello-mcp startup kills any prior process holding the
same lock file, ensuring exactly one cello-mcp per agent." This only made sense when `cello-mcp`
*was* the long-lived, stateful process. Post-M7, the daemon is the one long-lived process, and it
has its own, independently-designed lock file manager: `core/daemon/src/lock-file.ts` (atomic
write-then-rename, PID + socket path + version, used by `daemon/src/index.ts`,
`connect-or-start.ts`, `daemon.ts`).

`adapter-claude-code/src/lock-file.ts` is referenced only by its own test,
`__tests__/cello-m6b-001-lock-file.test.ts` — tag: `orphan`.

---

## 🟡 Other dead files (not migration-specific, but currently unreachable)

| File | Tag | Note |
|---|---|---|
| `core/adapter-claude-code/src/config.ts` | api | Directory-URL resolution helpers re-exported from connect's `index.ts`; unused by `bin/cello-mcp.ts`. |
| `core/adapter-claude-code/src/index.ts` | api | The package's public library export surface — dead because nothing consumes `@cello-protocol/connect` as a library; only the `cello-mcp` bin ships. |
| `core/adapter-claude-code/src/notifications.ts` | api | `pushSessionRequestNotification`, used only by the dead `server.ts`. (`bin/cello-mcp.ts` has its own inline channel-notification forwarding.) |
| `core/cli/src/index.ts` | api | CLI's library export (`login/logout/status/register/sessions`). The real `cello` binary goes through `registry.ts` + `cli-args.ts`, not this root export. Nothing in-repo imports `@cello-protocol/cli` as a library. |
| `core/daemon/src/cello-node-transport-dialer.ts` | orphan | `CelloNodeTransportDialer` (CELLO-M7-TRANSPORT-001), introduced 2026-07-10. Its own header calls it "the REAL TransportDialer," but production wires `transport-selector.ts` instead and nothing imports this class outside its own test. Not migration-debris — it is scaffolding that was never hooked into the daemon (or was superseded before it was). Confirm whether it is meant to be wired before deleting. |
| `core/test-fixtures/src/index.ts` | api | The public export of `@cello-protocol/test-fixtures`. Consumed only by other packages' tests, never by a shipped binary — so it is unreachable from the production roots by design. Listed here for completeness; likely *not* a deletion candidate (it is live test infrastructure). |
| `core/client/src/encrypted-file-signing-key-provider.ts` | orphan | Referenced only by `__tests__/persist-010.test.ts`; no production caller even within the (already-dead) client package's own wiring. |
| `core/crypto/src/frost/stubs.ts` | orphan | An in-process FROST directory-node stub for tests; lives in `src/` instead of `__tests__/`. Only used by `frost.test.ts`. Unrelated to the daemon migration — general test-scaffolding-in-src hygiene. |

---

## What's already been cleaned up (context, not new work)

For contrast — recent commits show active, ongoing dead-code removal in this area, so this report
is additive to work already landed, not duplicating it:

- `9352b76` — deleted `cello_receive_session` end-to-end (CLI command, IPC method, parity function,
  vocabulary row, connect shim tool, **and** the daemon handler registration itself) after
  confirming it was a dead alias with no real behavior.
- `59465f4` / `5eb9216` — found and fixed a published doc (`SKILL.md`) advertising tools that no
  longer exist, and hardened the audit from a denylist (misses names it doesn't already know to
  check) to an allowlist (every `cello_*` token named in a shipped `.md` must be a real tool).
- `db67d10` — corrected an imprecise "zero dead references in the dist tarball" claim once it was
  shown `server.ts` still ships inside `dist/`; added a test to keep that quarantine bounded and
  visible rather than re-claiming it's gone.

---

## Recommended Next Steps

1. ~~**Execute DOD-LEGACY-MCP-1**~~ — **DONE 2026-07-12.** Deleted `adapter/server.ts`,
   `adapter/notifications.ts`, `client/mcp-server.ts` and both package-root exports; verified against
   the real tarball (`npm pack` → extract → grep) that connect's `dist/` no longer ships them or
   registers any renamed-away tool.

   **Two corrections to this step as it was written above** — recorded because both were traps:
   - It said to delete `notifications.ts` outright. That file exported **two** functions, and
     `pushChannelNotification` is a **separate published export** this report never mentions. Deleting
     the file "as instructed" would have silently removed a public export nobody had decided to remove.
     (It *was* correct to delete — the live shim inlines its own `buildChannelParams` call and never
     imports the module — but that had to be an explicit decision, not a side effect.)
   - It framed the work as "delete 3 files + exports." Those three files were the **test harness for
     130 cases across 12 suites**, several of which MIXED dead-code assertions with live-code ones in
     the same file. Deleting by file would have destroyed real coverage: `FileKeyProvider` 0o600 key
     persistence, live `client.ts` send/receive, the `DOD-DIR-FAILCLOSED-1` cases, and the sole consumer
     of `rfc6962-external-verify.json` — CELLO's only external RFC 6962 conformance vector. Every case
     was triaged by subject-under-test: 95 deleted, 25 kept, 10 tightened.

   The scope also crossed repos, which this report does not anticipate: `trustless-cello`'s
   `packages/e2e-tests/src/session-fixture.ts` imported `createMcpSessionServer` and 15 e2e cases drove
   it. 12 were real protocol coverage and were re-pointed at the live client; 3 were duplicates.
2. Once (1) lands, remove the `@cello-protocol/client` dependency from `core/adapter-claude-code/package.json`
   and re-run reachability — the entire `core/client/src/*` list above should go to zero importers.
3. Confirm no consumer *outside* this repo depends on `@cello-protocol/client` directly before
   dropping it from the CI publish list (`ci.yml`) and archiving/deleting the package. This is a
   published-package removal and needs its own confirmation step, not a silent deletion.
4. Delete `core/adapter-claude-code/src/lock-file.ts` and its test; delete
   `core/adapter-claude-code/src/config.ts` if still unused after (1)–(2); delete `core/cli/src/index.ts`'s
   export if no external library consumer is found.
5. Move `core/crypto/src/frost/stubs.ts` into `core/crypto/src/__tests__/` (or a `__fixtures__/`
   dir) rather than deleting it — it's genuinely useful test scaffolding, just miscategorized.
6. **Decide the fate of `core/daemon/src/cello-node-transport-dialer.ts`** (CELLO-M7-TRANSPORT-001).
   It advertises itself as "the REAL TransportDialer" but is imported only by its own test — so it is
   either scaffolding waiting to be wired into the daemon, or a superseded implementation to delete.
   This is a live-daemon question, not a migration cleanup: resolve it with whoever owns
   CELLO-M7-TRANSPORT-001 before either wiring or deleting. Do **not** touch
   `core/test-fixtures/src/index.ts` — it is unreachable from the production roots by design (test
   infrastructure), not dead weight.
7. Each deletion above touches a **published `core/*` package** — per this repo's Publishing
   Invariants, any package whose source changes must have its version bumped and be re-published,
   and the whole `workspace:*` dependency cascade re-bumped. Treat this as a dedicated story with
   full SPARC (spec → pseudocode → interfaces → TDD → completion gate), not a quick cleanup PR.
