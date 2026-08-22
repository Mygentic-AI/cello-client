/**
 * DOD-M15-BOOTSTRAP-1 — one lost packet stops dropping a directory from the roster.
 *
 * `fetchBootstrapResult` gave each node ONE attempt with a 5-second deadline and no retry. A probe
 * that loses a packet during the TCP handshake is abandoned inside the retransmit backoff, and the
 * node is dropped — for a normal user, on a normal lossy link, with nothing wrong anywhere in the
 * system. Measured over a mobile link: one request returned at **16.2 s**, another returned nothing
 * in 30 s.
 *
 * THE COUNTER-INTUITIVE PART, and the reason this is a retry rather than a bigger timeout: waiting
 * longer on the original socket keeps waiting on the same lost handshake. **The win comes from a
 * fresh connection.** Each attempt is a new `fetch`.
 *
 * Written RED-first per SPARC Phase R. Each test targets one clause.
 */

import { describe, it, expect } from "vitest";
import {
  fetchBootstrapResult,
  createDirectoryEndpointResolver,
  manifestNodesToEndpoints,
  FAST_PROBE,
  PERSISTENT_PROBE,
} from "../directory-bootstrap.js";
import { SIGNALING_CONNECT_WAIT_MS } from "../outbound-sessions.js";

const URL_ = "https://dir.example.test";

function multiaddrResponse(): Response {
  return new Response(JSON.stringify({ multiaddr: "/ip4/1.2.3.4/tcp/4001/p2p/12D3KooWNode" }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

/** An AbortError, which is what a probe that ran out of time actually throws. */
function timeoutError(): Error {
  const e = new Error("The operation was aborted");
  e.name = "AbortError";
  return e;
}

/** A coded transport error, the shape undici nests. */
function connectError(code: string): Error {
  return Object.assign(new Error(`connect ${code}`), { code });
}

describe("DOD-M15-BOOTSTRAP-1: a transient probe failure gets another connection", () => {
  it("RETRIES after a timeout and succeeds — the case that was dropping healthy nodes", async () => {
    // The reported failure, exactly: the first probe loses a packet and times out; the node is
    // perfectly healthy and answers immediately on a fresh connection.
    let calls = 0;
    const fetchFn = (async () => {
      calls++;
      if (calls === 1) throw timeoutError();
      return multiaddrResponse();
    }) as unknown as typeof fetch;

    const result = await fetchBootstrapResult(URL_, fetchFn, () => 0);

    expect(result.ok, "a node that answers on the second probe must not be dropped").toBe(true);
    expect(calls, "the retry must be a NEW fetch — a fresh connection is the mechanism").toBe(2);
    expect(result.attempts).toBe(2);
  });

  it("retries a connection error too, and reports how many probes it took", async () => {
    let calls = 0;
    const fetchFn = (async () => {
      calls++;
      if (calls < 3) throw connectError("ECONNREFUSED");
      return multiaddrResponse();
    }) as unknown as typeof fetch;

    const result = await fetchBootstrapResult(URL_, fetchFn, () => 0);

    expect(result.ok).toBe(true);
    // The count is on the result so a caller can log "reached on probe 3" rather than reporting a
    // clean success that hides a node one packet away from being dropped.
    expect(result.attempts).toBe(3);
  });

  it("gives up after three attempts and keeps the LAST failure's cause", async () => {
    // Invariant 3: the retry must not overwrite what was observed. A caller that sees
    // `dns_error/ENOTFOUND` knows this machine cannot resolve the name — a different problem, with a
    // different fix, from a node that is down.
    let calls = 0;
    const fetchFn = (async () => {
      calls++;
      throw connectError("ENOTFOUND");
    }) as unknown as typeof fetch;

    const result = await fetchBootstrapResult(URL_, fetchFn, () => 0);

    expect(result.ok).toBe(false);
    expect(calls).toBe(3);
    expect(result.ok === false && result.reason).toBe("dns_error");
    expect(result.ok === false && result.detail).toBe("ENOTFOUND");
    expect(result.attempts).toBe(3);
  });
});

describe("DOD-M15-BOOTSTRAP-1: a deterministic answer is not retried", () => {
  it("does NOT retry an HTTP error — the server answered, and it will answer the same way", async () => {
    // Spending the whole budget to receive the same 404 three times delays every other node in the
    // roster. A reachable server giving a definite answer is information, not a transient fault.
    let calls = 0;
    const fetchFn = (async () => {
      calls++;
      return new Response("nope", { status: 404 });
    }) as unknown as typeof fetch;

    const result = await fetchBootstrapResult(URL_, fetchFn, () => 0);

    expect(result.ok).toBe(false);
    expect(calls, "a 404 must cost exactly one probe").toBe(1);
    expect(result.ok === false && result.reason).toBe("http_error");
  });

  it("does NOT retry a malformed payload", async () => {
    let calls = 0;
    const fetchFn = (async () => {
      calls++;
      return new Response(JSON.stringify({ multiaddr: "/ip4/1.2.3.4/tcp/4001" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch;

    const result = await fetchBootstrapResult(URL_, fetchFn, () => 0);

    expect(result.ok).toBe(false);
    expect(calls).toBe(1);
    expect(result.ok === false && result.reason).toBe("bad_response");
  });
});

describe("DOD-M15-BOOTSTRAP-1: the total budget is bounded", () => {
  it("stops early when another full attempt could not finish inside the budget", async () => {
    /**
     * A genuinely dead node must not hold startup while the roster has others to try. With each
     * probe consuming its full 8 s, a third attempt would end at 24 s — past the 20 s cap — so it is
     * not started.
     *
     * The clock is injected rather than real: a test that actually waited 16 seconds to prove a
     * timeout bound is a test nobody runs.
     */
    let calls = 0;
    let clock = 0;
    const fetchFn = (async () => {
      calls++;
      clock += 8_000; // this probe consumed its whole deadline
      throw timeoutError();
    }) as unknown as typeof fetch;

    const result = await fetchBootstrapResult(URL_, fetchFn, () => clock);

    expect(calls, "16s spent + another 8s would exceed the 20s cap, so the third probe is skipped").toBe(2);
    expect(result.ok).toBe(false);
    expect(result.attempts).toBe(2);
  });
});

describe("DOD-M15-BOOTSTRAP-1 review fixes: the retry must not break what it protects", () => {
  it("an ABORTED BODY READ is a timeout, not a malformed payload — and is therefore retried", async () => {
    /**
     * Review F3. The deadline covers the body as well as the request, so a server that sends
     * headers and then stalls — the ordinary shape of a lossy link, this unit's whole subject —
     * aborts inside `resp.json()`.
     *
     * Reporting that as `bad_response` was wrong twice: it sent the operator to inspect a payload
     * that was never received, and `bad_response` is deliberately NOT retryable, so the node got one
     * probe and was dropped. The retry's own policy delivering the outcome the retry exists to
     * prevent.
     */
    let calls = 0;
    const fetchFn = (async () => {
      calls++;
      if (calls === 1) {
        return {
          ok: true,
          status: 200,
          json: async () => {
            const e = new Error("The operation was aborted");
            e.name = "AbortError";
            throw e;
          },
        } as unknown as Response;
      }
      return multiaddrResponse();
    }) as unknown as typeof fetch;

    const result = await fetchBootstrapResult(URL_, fetchFn, () => 0);

    expect(result.ok, "a stalled body must not drop the node — it is a timeout, and timeouts retry").toBe(true);
    expect(calls).toBe(2);
  });

  it("the RECONNECT resolver actually SPENDS the fast budget — asserted at the call site", async () => {
    /**
     * Review HIGH-3. The first version of this test read four fields off two exported constants and
     * never constructed a resolver. Deleting the `FAST_PROBE` argument from the call site — reverting
     * the whole fix — left it green, because constants are inert data. The call site is the fix.
     *
     * This drives the real `createDirectoryEndpointResolver` with a `fetchFn` that always times out
     * and counts the probes. Two, not three.
     */
    let calls = 0;
    const fetchFn = (async () => {
      calls++;
      throw timeoutError();
    }) as unknown as typeof fetch;

    const resolve = createDirectoryEndpointResolver({
      logger: { debug() {}, info() {}, warn() {}, error() {} },
      directoryUrl: URL_,
      fetchFn,
      staleFallback: false,
    });
    await resolve();

    expect(
      calls,
      "the reconnect path must spend the FAST budget — a caller is blocked on it",
    ).toBe(FAST_PROBE.attempts);
    expect(calls, "and it must still RETRY — one probe is the defect this unit fixed").toBeGreaterThan(1);
  });

  it("the ROSTER SWEEP inside the blocked resolver also spends the fast budget", async () => {
    /**
     * Review HIGH-1 — the regression was halved, not removed. The first fix put FAST_PROBE on the
     * resolver's PRIMARY leg and left the roster sweep on the persistent one. Both sit inside the
     * same 10s signaling wait, and the sweep is the SLOWER leg: `Promise.all` waits for the slowest
     * node, so one unreachable node cost it 16s — after the primary had already spent its own.
     *
     * Asserted per node, at the sweep's own call site.
     */
    let calls = 0;
    const fetchFn = (async () => {
      calls++;
      throw timeoutError();
    }) as unknown as typeof fetch;

    await manifestNodesToEndpoints(
      [{ nodeId: "n1", endpoint: "https://n1.example.test", peerId: "12D3KooWN1" }] as never,
      { logger: { debug() {}, info() {}, warn() {}, error() {} }, fetchFn, probeBudget: FAST_PROBE },
    );

    expect(calls, "a blocked sweep must not spend the persistent budget per node").toBe(FAST_PROBE.attempts);
  });

  it("the two budgets are chosen against the SIGNALING WAIT, not in isolation", () => {
    // The number that matters is the caller's deadline. Both legs of the blocked resolver run
    // inside it, so the worst case is primary + sweep — which is what the old test failed to model,
    // and why HIGH-1 slipped past it.
    const worstCaseBothLegs = FAST_PROBE.attempts * FAST_PROBE.timeoutMs * 2;
    expect(
      worstCaseBothLegs,
      "primary leg + roster sweep must both fit inside the 10s wait outbound-sessions allows",
    ).toBeLessThanOrEqual(SIGNALING_CONNECT_WAIT_MS);
    expect(PERSISTENT_PROBE.attempts).toBeGreaterThan(FAST_PROBE.attempts);
  });

  it("honours a caller-supplied budget rather than the module default", async () => {
    let calls = 0;
    const fetchFn = (async () => {
      calls++;
      throw timeoutError();
    }) as unknown as typeof fetch;

    const result = await fetchBootstrapResult(URL_, fetchFn, () => 0, FAST_PROBE);

    expect(calls, "FAST_PROBE spends two probes, not the default three").toBe(FAST_PROBE.attempts);
    expect(result.attempts).toBe(FAST_PROBE.attempts);
  });
});
