# cello-client — Claude Code Guide

## What This Project Is

This is the client-side repository for the CELLO protocol — the installable npm package (`@cello-protocol/connect`) that agents use to connect to the live CELLO network.

The server-side infrastructure, protocol design, and architecture documentation live in the [trustless-cello](https://github.com/Mygentic-AI/trustless-cello) monorepo. Read the design docs there before working here.

---

## SPARC Development Process — Non-Negotiable

CELLO is financial trust infrastructure. Every story, every package, every time.

**Five phases in order:**

**S — Specification:** Read the full story YAML first (stories live in trustless-cello/docs/planning/user-stories/). Stories must describe production behavior — every AC must pass if participants are in different OS processes on different machines.

**P — Pseudocode:** Write pseudocode before any implementation. Crypto code must cite the RFC (Ed25519 → RFC 8032, FROST → RFC 9591).

**A — Architecture:** Define TypeScript interfaces and confirm package boundaries before coding.

**R — Refinement (TDD, absolute rule):** Write all tests first → confirm all red → implement → confirm all green. No implementation before red tests exist. No mocks for crypto operations.

**C — Completion gate (in order):** `pnpm run test` → `pnpm run lint` → `pnpm run typecheck` → build → code review (`feature-dev:code-reviewer` agent) → commit with story ID.

---

## Publishing Invariants — Non-Negotiable

Publishing is done by CI on a `v*` git tag (`pnpm publish`, never `npm publish`). The build runs
`tsc --build`, which only compiles packages listed in root `tsconfig.json` `references`. These invariants
exist because each was violated on 2026-06-23 and shipped broken packages to npm. **Source-level tests
do NOT catch publish breakage** — vitest runs TS source, not the built `dist/`. Only the published-artifact
smoke test in `ci.yml` does.

1. **A new publishable `core/*` package needs THREE registrations, not one.** Adding the package and its
   tests is not enough:
   - **Root `tsconfig.json` `references`** — or `tsc --build` never compiles it → `dist/` is empty →
     `files: ["dist/"]` packs nothing → it publishes as `package.json` only (an empty shell that imports
     to nothing). This is how `daemon`/`cli` first published empty.
   - **The CI publish list** (`pnpm publish --filter @cello-protocol/<name>` in `ci.yml`, in dependency
     order) — or it never publishes at all.
   - **The verify + smoke loops** in `ci.yml` — so an empty/unbumped/missing publish fails CI.
   The Build job's "Publish-completeness" step enforces the first two; keep it green.

2. **npm version ≡ published content. If you change ANY `core/*` source, bump that package's version.**
   Same version number with different content is the cardinal publishing sin — npm has the old build
   forever, and any consumer pinning that version silently gets stale code. This is exactly what broke
   `daemon`: `crypto` gained `sealToRecipient` but was never bumped past 0.0.8, so the published 0.0.8
   lacked it and the daemon crashed at startup (`does not provide an export named 'sealToRecipient'`).
   When you change a package, bump it AND re-publish — even if no dependent's version changed.

3. **Bump the whole dependency cascade.** Cross-package deps inside cello-client are `workspace:*` and
   resolve to the current local version at publish time. So bumping crypto means every package that
   depends on it must ALSO be bumped + republished to re-pin the fresh crypto — otherwise their published
   copies keep pinning the old one. See `/cello-publish` for the exact procedure.

The daemon is the heavy local node; `connect` is just an MCP shim that proxies to it over
`~/.cello/daemon.sock`. An operator install is `@cello-protocol/connect` + `@cello-protocol/cli` (the cli
pulls the daemon). Both must be on `latest` for the default install path to work.

---

## Slash Commands

- **`/cello-read`** — Load current CELLO project context. Start every session with this.
- **`/cello-sprint`** — Implementation briefing for a milestone.
- **`/cello-story`** — Write new user stories.
- **`/cello-review STORY-ID`** — Review a completed implementation.
- **`/cello-link`** — Wire new documents into the vault graph.
- **`/cello-chat`** — Enter a CELLO peer-to-peer conversation session.
