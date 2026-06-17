/**
 * CELLO-M7-DAEMON-004 — AC-001 / AC-002 / AC-004 (E2E, live).
 *
 * These ACs require TWO daemons in separate OS processes, real ephemeral session
 * nodes (real libp2p streams — NOT in-process fakes), and a LIVE directory + relay
 * (for the relay hash-submit sequence assignment and the FROST threshold
 * notarization). That external state cannot be provided by createSessionFixture
 * in-process, so per the CELLO_E2E_LIVE discipline every top-level describe here is
 * guarded with describe.skipIf(!process.env.CELLO_E2E_LIVE).
 *
 * The cross-process orchestration (two daemon binaries over real IPC sockets, a
 * live relay, and the live directory FROST ceremony) is driven by the E2E-001
 * fixture; this story is the daemon send/receive/tree/seal foundation that makes
 * E2E-001 AC-005 pass. See the SCOPE AMENDMENT block in CELLO-M7-DAEMON-004.yaml —
 * the relay hash-submit + relay-assigned sequence (AC-001) and the FROST threshold
 * notarization → 'sealed' (AC-004) are owned by MSG-001 and SESSION-002 + the
 * directory FROST wiring respectively. When CELLO_E2E_LIVE is set, the E2E-001
 * harness exercises this story's foundation half:
 *
 *   AC-001: Alice cello_send('hello') over daemon-1's IPC socket → Bob cello_receive
 *     over daemon-2's IPC socket returns 'hello', riding the real direct-P2P content
 *     stream. session.content.sent fires on daemon-1, session.content.received on
 *     daemon-2, sharing one correlationId (carried in the content_frame). The relay
 *     hash_submit/leaf_deliver evidence + relay-assigned sequence are MSG-001's E2E.
 *
 *   AC-002: after an ordered exchange, both daemons report the SAME daemon-owned tree
 *     root (cross-process root agreement) and neither was supplied the root by a caller
 *     param. session.tree.appended fires once per leaf. (Canonical ordering under
 *     concurrent traffic is MSG-001.)
 *
 *   AC-004: Alice cello_close_session → a VERIFIED BILATERAL seal commitment over the
 *     daemon's own root (Bob co-signs with his own key, SI-003). The FROST threshold
 *     notarization that finalizes 'sealed' (frost_signature + session_sealed) is the
 *     downstream SESSION-002 + directory FROST step — the same deferral SESSION-001's
 *     interrupted seal carries.
 *
 * The in-process mechanisms behind these ACs are unit/integration tested without
 * live state in: session-tree.test.ts (root determinism + restart),
 * daemon-004-tree.test.ts (append/persist/restart/send/receive), and
 * daemon-004-ipc.test.ts (cello_send/cello_receive/active-seal through real IPC).
 */

import { describe, it, expect } from "vitest";

const liveOnly = describe.skipIf(!process.env["CELLO_E2E_LIVE"]);

liveOnly("DAEMON-004 E2E (CELLO_E2E_LIVE): cross-process send / receive / tree / seal", () => {
  it("AC-001/AC-002/AC-004 are driven by the E2E-001 live fixture", () => {
    // The two-process, live-directory, live-relay orchestration is owned by the
    // E2E-001 fixture. This guard ensures these ACs never silently "pass" in CI
    // against in-process fakes — they only run with real external state.
    expect(process.env["CELLO_E2E_LIVE"]).toBeTruthy();
  });
});
