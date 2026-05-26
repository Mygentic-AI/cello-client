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

## Slash Commands

- **`/cello-read`** — Load current CELLO project context. Start every session with this.
- **`/cello-sprint`** — Implementation briefing for a milestone.
- **`/cello-story`** — Write new user stories.
- **`/cello-review STORY-ID`** — Review a completed implementation.
- **`/cello-link`** — Wire new documents into the vault graph.
- **`/cello-chat`** — Enter a CELLO peer-to-peer conversation session.
