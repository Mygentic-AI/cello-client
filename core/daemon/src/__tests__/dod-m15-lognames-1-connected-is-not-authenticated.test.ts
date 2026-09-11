/**
 * 058-LOGNAME — **ONE EVENT NAME MUST NOT MEAN TWO THINGS.**
 *
 * ─── What this cost, which is the reason it is a test and not a rename ────────────────────────
 *
 * `directory.signaling.connected` had two emitters in two packages:
 *
 *   - `SignalingManager.runConnectedPhase` — the manager entered the connected STATE. Carries
 *     `manifestVersion`. Knows nothing about which agent.
 *   - `createSignalingConnect` in the daemon — the HANDSHAKE completed. Carries `agentPubkey` and
 *     `verified`. Knows exactly which agent, and whether the directory's challenge checked out.
 *
 * They fire in the same millisecond, so every connection appeared twice and the event could not be
 * counted. On 2026-09-11 that read as **361 connects in 90 minutes** on a real daemon and sent an
 * investigation an hour into connection churn. The churn was the trust-signal sweep behaving
 * exactly as designed; the actual defect was a relay credential that never refreshed
 * (`DOD-M15-TOKENRACE-1`), and the doubled number was pointing away from it the whole time.
 *
 * ─── Why a test rather than trusting the rename ───────────────────────────────────────────────
 *
 * A rename is one edit and re-colliding them is also one edit, in either of two packages, by
 * someone who has not read either comment. The property worth holding is not "the daemon uses this
 * string" — it is **no name is emitted by both layers**, which is what makes the count trustworthy.
 * So this asserts the shape, not the spelling: it reads the source of both emitters and fails if
 * their event names ever match again, whatever they are renamed to next.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const DAEMON_SRC = join(HERE, "..");
const TRANSPORT_SRC = join(HERE, "..", "..", "..", "transport", "src");

/** Every `logger.<level>("<name>"` event name emitted in one file. */
function emittedEventNames(file: string): string[] {
  const src = readFileSync(file, "utf8");
  const out: string[] = [];
  // Only ACTUAL emit sites: a logger call with a string literal first argument. Comments mentioning
  // an event name are deliberately not matched — this is about what the code DOES.
  const re = /logger\.(?:debug|info|warn|error)\(\s*"([a-z0-9_.]+)"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src)) !== null) out.push(m[1]!);
  return out;
}

describe("058-LOGNAME: the connection state and the handshake are different events", () => {
  it("★★★ no event name is emitted by BOTH the transport's manager and the daemon's handshake", () => {
    const transport = new Set(emittedEventNames(join(TRANSPORT_SRC, "signaling-manager.ts")));
    const daemon = new Set(emittedEventNames(join(DAEMON_SRC, "signaling-connect.ts")));

    /**
     * ⚠️ **TWO NAMES ARE SHARED ON PURPOSE, AND SAYING SO IS NOT A CARVE-OUT.**
     *
     * `directory.auth.challenge.verified` / `.failed` mean the SAME fact in both places — the
     * directory's challenge checked out, or did not. That is the opposite of the defect this test
     * is about, which is one name meaning two different things.
     *
     * They are shared because the check is implemented TWICE: `SignalingManager.processStep5Frame`
     * and the daemon's own verification inside `createSignalingConnect`. The transport copy is
     * **called by nothing but its own tests**, while its docstring says "processStep5Frame() is
     * called inside production connect() after auth_ok" — a comment asserting a property the code
     * does not have. Found by this test, tracked separately rather than deleted here: removing a
     * public transport method with its own suite is its own reviewable change, and widening a
     * log-naming order into it is how a unit stops being reviewable.
     */
    const SAME_FACT_TWO_IMPLEMENTATIONS = new Set([
      "directory.auth.challenge.verified",
      "directory.auth.challenge.failed",
    ]);
    const shared = [...daemon].filter((e) => transport.has(e) && !SAME_FACT_TWO_IMPLEMENTATIONS.has(e));

    expect(
      shared,
      "an event name emitted by both layers cannot be counted: every connection logs it twice, in " +
        "the same millisecond, with different payloads. That is not cosmetic — it read as 361 " +
        "connects in 90 minutes and cost an hour chasing connection churn while the real defect " +
        "was a credential that never refreshed",
    ).toEqual([]);
  });

  it("the handshake event still exists and still carries WHO — the half that knows the agent", () => {
    const daemon = emittedEventNames(join(DAEMON_SRC, "signaling-connect.ts"));
    expect(
      daemon,
      "the per-agent handshake result is the only place `verified` and the agent pubkey are " +
        "reported; losing it to a rename would leave no record of whose challenge checked out",
    ).toContain("directory.signaling.authenticated");

    const src = readFileSync(join(DAEMON_SRC, "signaling-connect.ts"), "utf8");
    const idx = src.indexOf('"directory.signaling.authenticated"');
    expect(idx, "the event must be emitted, not merely mentioned").toBeGreaterThan(-1);
    const payload = src.slice(idx, idx + 220);
    expect(payload).toContain("agentPubkey");
    expect(payload).toContain("verified");
  });

  it("the state transition still exists, and is the one the reconnect journey counts", () => {
    const transport = emittedEventNames(join(TRANSPORT_SRC, "signaling-manager.ts"));
    expect(
      transport,
      "`j-sig` counts this to prove a reconnect ran a full re-auth rather than resuming silently",
    ).toContain("directory.signaling.connected");
  });
});
