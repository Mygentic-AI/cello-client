/**
 * THE RETRY QUEUE REMEMBERS HOW EACH QUEUED MESSAGE WAS HASHED — `DOD-M15-SEALWIRE-1` part B2b.
 *
 * The crash-backstop park producer runs at the NEXT BOOT, when the frame that carried the algorithm
 * is gone, so the queued row is its only source.
 */

import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { readFile } from "node:fs/promises";
import { ensureIdentitySchema } from "../db-identity-store.js";
import { RetryQueue } from "../retry-queue.js";
import type { Logger } from "../types.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} } as unknown as Logger;

describe("the queued row REMEMBERS how its message was hashed", () => {
  /**
   * The reason the column exists, and it is a round trip rather than a schema check: the
   * crash-backstop park producer runs at the NEXT BOOT, when the frame that carried the algorithm is
   * long gone. If the value does not survive `enqueue → persist → restart → hydrate`, that producer
   * has nothing to name, and re-parking under the wrong algorithm gets the message refused by the
   * recipient and re-pulled on every drain.
   *
   * Re-deriving it from the session's current row is the wrong answer and is why this is stored:
   * whether a hash is salted is a fact about the MESSAGE THAT WAS SENT, and what this side holds now
   * says nothing about it.
   */
  function freshQueueDb(): DatabaseSync {
    const db = new DatabaseSync(":memory:");
    ensureIdentitySchema(db as unknown as DaemonDatabase);
    db.prepare(
      `INSERT INTO agents (agent_id, agent_name, k_local_seed, k_local_pubkey, state, created_at, updated_at)
       VALUES ('id-alice','alice',x'00','pub-alice','created',1,1)`,
    ).run();
    return db;
  }

  /**
   * Reads the entry the way the BACKSTOP PRODUCER does — through `drainAwaitingToPark`, whose
   * `parkFn` receives it — rather than through a test-only accessor. A seam that hands back the
   * in-memory object would pass even if the value never reached the row, which is the whole thing
   * being tested.
   */
  async function drainedEntry(db: DatabaseSync, sessionId: string) {
    /**
     * A SECOND instance over the same handle, then `loadFromDb()` — which is the restart, and the
     * explicit call matters. The constructor only creates the table and its indexes; hydration is a
     * separate step the daemon runs before the IPC socket opens. A fixture that skipped it saw an
     * empty queue and would have "proved" the value was lost.
     */
    const revived = new RetryQueue(db as unknown as DaemonDatabase, silent);
    revived.loadFromDb();
    // Typed through a mutable holder rather than a bare `let`: TypeScript narrows a `let` assigned
    // only inside a callback to `never` at the read, which is a real error this file could not see
    // until it joined the typechecked allowlist (B2b-1 pass-2 F3).
    const seen: { value: { contentHashAlg?: string } | null } = { value: null };
    await revived.drainAwaitingToPark("id-alice", sessionId, async (entry) => {
      seen.value = entry;
      return { parked: true };
    });
    return seen.value;
  }

  it("★ the algorithm survives enqueue → restart → the backstop's own read", async () => {
    const db = freshQueueDb();
    const rq = new RetryQueue(db as unknown as DaemonDatabase, silent);
    expect(
      rq.enqueueAwaitingContent(
        "id-alice", "s1", new Uint8Array(32).fill(0xa1), new TextEncoder().encode("hello"),
        undefined, undefined, "hmac-sha256-salt-v1", undefined, 0,
      ),
      "precondition: the enqueue must succeed",
    ).toBe(true);

    const entry = await drainedEntry(db, "s1");
    expect(entry, "the row must hydrate at all").not.toBeNull();
    expect(
      entry!.contentHashAlg,
      "without this the backstop re-parks under sha256 and the recipient refuses every copy",
    ).toBe("hmac-sha256-salt-v1");
  });

  it("★ THE PRODUCTION WRITER supplies it — the hooks, not a test calling enqueue directly", async () => {
    /**
     * ⚠️ REVIEW B2b-1 F1 — THE COLUMN HAD NO PRODUCTION WRITER AT ALL, and the test above did not
     * notice because it hands the value straight to `enqueueAwaitingContent`, which nothing in
     * production does. The reviewer's words: *"it proves a plumbing segment with no upstream."*
     *
     * The two real producers are the `onTtf` and `onParkFailed` hooks in `boot-parked-content.ts`, and neither
     * carried the algorithm — so every row would have been written NULL while the commit message
     * said the producer "passes it". It passed a value nothing supplied.
     *
     * This asserts the SHAPE of the wiring at its narrowest point: the hook signature the daemon
     * installs must accept and forward the 7th argument. A source check, because the behavioural
     * difference is invisible while every algorithm is `sha256` — which is precisely the condition
     * that let four other mutants survive.
     */
    // 040-DAEMONROOT unit 7 (phase 4): both hooks moved into boot-parked-content.ts.
    const root = await readFile(new URL("../boot-parked-content.ts", import.meta.url), "utf8");
    for (const hook of ["onTtf", "onParkFailed"]) {
      // The whole hook body, not a paren-capture: `resolveAgentId(agentName)` nests parentheses, so
      // a `[^)]*` group stops at the wrong one and reports a forwarded argument as missing.
      const start = root.indexOf(`${hook}: (`);
      expect(start, `${hook} must exist in boot-parked-content.ts`).toBeGreaterThan(-1);
      /**
       * ⚠️ THE SLICE IS BOUNDED — B2b-1 pass-2 F2, and it was proven vacuous without this.
       *
       * Reindent that closing brace by two spaces (or wrap the enqueue in a `try`, which puts a `}`
       * in front of the anchor) and `indexOf` slides to the NEXT match: the body grew 298 → 1002
       * chars, swallowed the sibling hook, and every assertion below passed **with the argument
       * deleted** — satisfied by the other hook's line. Green, blind, guarding nothing.
       *
       * A missing anchor is worse still: `slice(start, -1)` returns the rest of the file.
       */
      const end = root.indexOf("\n    },", start);
      expect(end, `${hook}'s closing brace must be findable — an unbounded slice guards nothing`).toBeGreaterThan(start);
      expect(
        end - start,
        `${hook}'s body is ${end - start} chars — too long to be one hook, so the slice has run past it into another`,
      ).toBeLessThan(600);
      const body = root.slice(start, end);

      expect(body, `${hook} must still call enqueueAwaitingContent`).toContain("enqueueAwaitingContent");
      const params = body.slice(body.indexOf("("), body.indexOf(")"));
      expect(params, `${hook} must ACCEPT contentHashAlg`).toContain("contentHashAlg");
      const call = body.slice(body.indexOf("enqueueAwaitingContent"));
      expect(
        call,
        `${hook} must FORWARD contentHashAlg — without it the column has no writer and every row is NULL`,
      ).toContain("contentHashAlg");
    }
  });

});
