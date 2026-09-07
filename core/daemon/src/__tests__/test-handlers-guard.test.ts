/**
 * The `CELLO_ENV=test` guard on the `__test_*` verbs, asserted rather than read.
 *
 * Seven verbs can emit session events, record refusals, insert session rows and push received
 * content straight into an agent's buffer. They are unreachable on a normal daemon because of one
 * `if` — and until this file, nothing checked that. A guard held up by a human reading an `if` is
 * the shape this milestone keeps finding.
 *
 * It is asserted HERE, at `registerTestHandlers`, because 040-DAEMONROOT unit 2 made it cheap: the
 * registration is an exported function taking a deps object, so the whole question is "call it at
 * three env settings and count the map". Before the move it needed a booted daemon.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { registerTestHandlers, type TestHandlerDeps } from "../test-handlers.js";
import type { IpcHandler } from "../ipc-server.js";

/** The six that are NOT gated — a production daemon answers these, which is its own open question. */
const UNGATED = [
  "queue_failed_send",
  "debug_inject_park_fault",
  "enqueue_awaiting_content",
  "mark_content_acked",
  "check_nonce",
  "drain_session",
];

/** The seven that must never exist outside a test environment. */
const GATED = [
  "__test_emit_session_event",
  "__test_record_refusal",
  "__test_delivery_open_begin",
  "__test_delivery_open_end",
  "__test_enqueue_inbound_session",
  "__test_insert_session_row",
  "__test_buffer_received",
];

/**
 * Nothing here is invoked — registration only reads the env and calls `handlers.set`. The stub
 * exists so the deps object type-checks; a member that a handler BODY would touch is never reached.
 */
function registerAt(env: string | undefined): string[] {
  const previous = process.env["CELLO_ENV"];
  if (env === undefined) delete process.env["CELLO_ENV"];
  else process.env["CELLO_ENV"] = env;
  try {
    const handlers = new Map<string, IpcHandler>();
    registerTestHandlers({ handlers } as unknown as TestHandlerDeps);
    return [...handlers.keys()];
  } finally {
    if (previous === undefined) delete process.env["CELLO_ENV"];
    else process.env["CELLO_ENV"] = previous;
  }
}

describe("the __test_ verbs exist only where CELLO_ENV says test", () => {
  let saved: string | undefined;
  beforeEach(() => { saved = process.env["CELLO_ENV"]; });
  afterEach(() => {
    if (saved === undefined) delete process.env["CELLO_ENV"];
    else process.env["CELLO_ENV"] = saved;
  });

  it("registers ONLY the ungated six when CELLO_ENV is unset", () => {
    const keys = registerAt(undefined);
    expect(keys.sort()).toEqual([...UNGATED].sort());
    for (const verb of GATED) expect(keys, `${verb} must not exist`).not.toContain(verb);
  });

  it("registers ONLY the ungated six when CELLO_ENV names a real environment", () => {
    for (const env of ["production", "staging", "dev", "local"]) {
      const keys = registerAt(env);
      expect(keys.sort(), `CELLO_ENV=${env}`).toEqual([...UNGATED].sort());
    }
  });

  it("registers all thirteen under CELLO_ENV=test — the guard opens, and it is the ONLY thing that opens it", () => {
    const keys = registerAt("test");
    expect(keys.sort()).toEqual([...UNGATED, ...GATED].sort());
  });

  it("is exact-match, not a prefix or a truthiness check", () => {
    // "testing" and "Test" are the near-misses that would let a guard leak. Assert the value, not
    // that the string merely contains something — a guard that opens on "not empty" would pass a
    // check written the lazy way and fail this one.
    for (const near of ["testing", "Test", "TEST", "test ", " test", "1", "true"]) {
      const keys = registerAt(near);
      expect(keys, `CELLO_ENV=${JSON.stringify(near)} must NOT open the guard`).toHaveLength(UNGATED.length);
    }
  });
});
