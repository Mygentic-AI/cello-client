import { describe, it, expect } from "vitest";
import { sealCeremonyWithRetry, SEAL_CEREMONY_ATTEMPTS } from "../session-ceremony.js";

/**
 * 2026-09-28: a seal failed because the one reachable holder's connection opened 2 s after the
 * ceremony gave up, and nothing asked again. The directory held the certificate waiting for a
 * signature that never came, and the session stayed unsealed.
 */
const SIG = new Uint8Array(64).fill(7);

function scripted(outcomes: boolean[]) {
  let calls = 0;
  const participate = async () => {
    const ok = outcomes[calls++] ?? false;
    return ok ? { ok: true as const, signature: SIG } : { ok: false as const };
  };
  return { participate, calls: () => calls };
}

describe("seal ceremony retry", () => {
  it("a ceremony that got no signature is tried again, and the later signature is used", async () => {
    const s = scripted([false, true]);
    const attempts: number[] = [];
    const sig = await sealCeremonyWithRetry(s.participate, () => false, (_ok, a) => attempts.push(a), 0);
    expect(sig).toEqual(SIG);
    expect(s.calls()).toBe(2);
    expect(attempts).toEqual([1, 2]);
  });

  it("a holder's refusal is a verdict and is never retried", async () => {
    const s = scripted([false, true]);
    const sig = await sealCeremonyWithRetry(s.participate, () => true, () => {}, 0);
    expect(sig).toBeNull();
    expect(s.calls()).toBe(1);
  });

  it("gives up after the last attempt", async () => {
    const s = scripted([]);
    const sig = await sealCeremonyWithRetry(s.participate, () => false, () => {}, 0);
    expect(sig).toBeNull();
    expect(s.calls()).toBe(SEAL_CEREMONY_ATTEMPTS);
  });
});
