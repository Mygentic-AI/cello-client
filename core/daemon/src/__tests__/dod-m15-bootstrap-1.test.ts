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
import { fetchBootstrapResult } from "../directory-bootstrap.js";

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
