import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

/**
 * DOD-END-SURFACE-1 — "list the ones I hold and their status".
 *
 * The daemon has returned `consent_state` since DOD-END-ACCEPT-1 review F4, but the CLI never
 * rendered it. That made `cello trust-signals list` show a PENDING endorsement — one that cannot be
 * presented to anyone — as `active` with `include ✓`, identical to a signal that is presented on
 * every session. The operator's own list was telling them the opposite of the truth, and the field
 * that would have corrected it had no consumer (§5a NO CONSUMER, NO SHIP: a field nobody reads is
 * dead weight born dead, and it lies).
 */
const sent = vi.fn();
// `withIpc` is module-private in commands.ts, so the seam is the daemon package it builds on:
// readLock finds the socket, connectToDaemon opens it. Mocking those exercises the real rendering
// path — which is the thing under test — rather than a reimplementation of it.
vi.mock("@cello-protocol/daemon", async (orig) => ({
  ...(await orig<Record<string, unknown>>()),
  readLock: async () => ({ socketPath: "/tmp/x.sock", pid: 1 }),
  connectToDaemon: async () => ({ send: sent, close: () => {} }),
}));

const row = (over: Record<string, unknown> = {}) => ({
  type: "endorsement", signal_hash: "ab".repeat(32), subject_kind: "agent", status: "active",
  issued_at: 1_800_000_000, expires_at: null, supersedes_hash: null, default_present: true,
  consent_state: "accepted", ...over,
});

describe("cello trust-signals list — consent is visible", () => {
  beforeEach(() => sent.mockReset());
  afterEach(() => vi.resetModules());

  async function list(signals: unknown[]) {
    sent.mockResolvedValue({ ok: true, signals });
    const { trustSignals } = await import("../commands.js");
    return (await trustSignals("/tmp/cello", "list", [])).output;
  }

  /** The signal's own ROW. The legend explains what ✓ means, so asserting on the whole output
   *  would match the legend's ✓ and pass (or fail) for reasons that have nothing to do with the row. */
  const rowFor = (out: string) => out.split("\n").find((l) => l.includes("ab".repeat(6))) ?? "";

  it("does NOT show a pending endorsement as presentable", async () => {
    const out = await list([row({ consent_state: "pending" })]);
    expect(rowFor(out)).toMatch(/PENDING/);
    // The include marker must not claim it is presented — it cannot be, at any tier, by any path.
    expect(rowFor(out)).not.toMatch(/✓/);
    expect(rowFor(out)).toMatch(/✗/);
  });

  it("marks a REFUSED signal as refused rather than active", async () => {
    const out = await list([row({ consent_state: "refused" })]);
    expect(rowFor(out)).toMatch(/refused/i);
    expect(rowFor(out)).not.toMatch(/✓/);
  });

  it("still shows an accepted signal as presentable — the check is not just 'hide everything'", async () => {
    // Without this, an implementation that printed "pending" unconditionally would pass the two
    // tests above while making every signal look un-presentable.
    const out = await list([row({ consent_state: "accepted" })]);
    expect(rowFor(out)).toMatch(/✓/);
    expect(rowFor(out)).not.toMatch(/pending|refused/i);
  });

  it("treats an ABSENT consent state as NOT presentable (§5a — absent is not fine)", async () => {
    // A missing or unrecognised consent state must never read as presentable-by-default. An attacker
    // does not have to defeat the check; they omit the thing that triggers it.
    const out = await list([row({ consent_state: null })]);
    expect(rowFor(out)).not.toMatch(/✓/);
    expect(rowFor(out)).toMatch(/✗/);
  });
});
