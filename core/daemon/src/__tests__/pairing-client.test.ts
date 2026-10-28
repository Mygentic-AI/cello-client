/**
 * Opening a pairing: directory failover, and the refusal when none answers.
 */
import { describe, it, expect, afterEach } from "vitest";
import { openPairing, type FetchFn } from "../pairing-client.js";
import { startFakeDirectory, closedPortBase, type FakeDirectory } from "./helpers/fake-pairing-directory.js";

const fetchFn: FetchFn = (url, init) => fetch(url, init);
const facts = { hostname: "h", os: "darwin 25", client_version: "0.0.0" };
const KEY = "ab".repeat(32);

describe("openPairing", () => {
  const dirs: FakeDirectory[] = [];
  afterEach(async () => { await Promise.all(dirs.splice(0).map((d) => d.close())); });

  it("2. with the first directory down, opens the pairing on the next", async () => {
    const down = await closedPortBase();
    const up = await startFakeDirectory({});
    dirs.push(up);
    const r = await openPairing([down, up.base], KEY, facts, fetchFn);
    expect(r).toMatchObject({ ok: true, base: up.base, pairing_code: "KQ7M4TXP" });
    expect(up.pairBodies).toEqual([{ daemon_pubkey: KEY, device_facts: facts }]);
  });

  it("2. a 5xx moves on too, but a 429 stops with the directory's guidance", async () => {
    const failing = await startFakeDirectory({ onPair: () => ({ status: 503, body: { error: "pairing_unavailable" } }) });
    const limited = await startFakeDirectory({ onPair: () => ({ status: 429, body: { error: "rate_limited", guidance: "wait an hour" } }) });
    const never = await startFakeDirectory({});
    dirs.push(failing, limited, never);
    const r = await openPairing([failing.base, limited.base, never.base], KEY, facts, fetchFn);
    expect(r).toMatchObject({ ok: false, reason: "pairing_rate_limited", guidance: "wait an hour" });
    expect(never.pairBodies).toHaveLength(0);
  });

  it("2. with every directory down → directory_unreachable with guidance naming the command", async () => {
    const r = await openPairing([await closedPortBase(), await closedPortBase()], KEY, facts, fetchFn);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.reason).toBe("directory_unreachable");
    expect(r.guidance).toContain("cello register-agent");
    expect(r.failures).toHaveLength(2);
  });
});
