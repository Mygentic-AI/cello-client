/**
 * 049-BRIDGEREPLY Part A — `delivery_mode: explicit`, the new default.
 *
 * Two faults motivated it. The bridge used to forward EVERY line the Hermes agent wrote, so thinking
 * and progress lines reached the peer as messages (21 in 3 minutes on 2026-09-26). The new default,
 * `explicit`, still delivers inbound as an ordinary message but sends NOTHING outbound unless the
 * agent calls cello_send.
 *
 * These tests EXECUTE the real Python out of HERMES_PLUGIN_INIT_PY against a stubbed `gateway`
 * package, via the shared driver in helpers/hermes-python-driver.ts — never substrings of the TS
 * template, which would pass for code that never runs.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { installHermesDriver, runDriver, hintFor } from "./helpers/hermes-python-driver.js";
import { DELIVERY_MODES, DEFAULT_DELIVERY_MODE } from "../hermes/install-hermes.js";

describe("049-BRIDGEREPLY Part A — delivery_mode: explicit, the new default", () => {
  let dir: string;

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "hermes-explicit-"));
    await installHermesDriver(dir);
  });
  afterAll(async () => { await rm(dir, { recursive: true, force: true }); });

  const SID = "aabbccdd11223344";
  const PUB = "77d0c806".repeat(8);
  const MSG = { session_id: SID, from: PUB, who: "Ms_Chelly", whoKnown: true };

  /** The adapter's own constants, read out of the executed Python. */
  function pyConst(expr: string): string {
    return execFileSync("python3", ["-c", `import cello_plugin as m; print(${expr})`], {
      cwd: dir,
      encoding: "utf8",
      env: { ...process.env, PYTHONPATH: dir, PYTHONDONTWRITEBYTECODE: "1" },
    }).trim();
  }

  // ─────────────────────────────────────────────── A1: the default is explicit

  it("A1: the default delivery mode is 'explicit' in both the Python and the TS installer", () => {
    // Python side — the adapter's own constant, executed.
    expect(pyConst("m.DEFAULT_DELIVERY_MODE")).toBe("explicit");
    expect(pyConst("list(m.DELIVERY_MODES)")).toBe("['explicit', 'channel', 'wake']");
    // TS side — the installer that writes CELLO_DELIVERY_MODE into .env.
    expect(DEFAULT_DELIVERY_MODE).toBe("explicit");
    expect([...DELIVERY_MODES]).toEqual(["explicit", "channel", "wake"]);
  });

  // ─────────────────────────────────────────────── A2: inbound = channel, plus a session line

  it("A2: explicit mode fetches the peer's words and prefixes them with the session line", () => {
    const v = runDriver(dir, { op: "notify", kind: "cello_message", data: MSG, delivery_mode: "explicit" });
    const recv = v.calls.find((c) => c.method === "cello_receive");
    expect(recv).toBeDefined();
    expect(recv!.params.session_id).toBe(SID);
    expect(v.delivered).toHaveLength(1);
    const text = v.delivered![0].text;
    // The peer's actual words are handed over…
    expect(text).toContain("hello from the peer");
    // …behind one line that names the session and the reply route, because the Hermes chat is no
    // longer the reply anchor in explicit mode.
    expect(text).toContain(SID);
    expect(text).toContain("cello_send");
    expect(text).toContain("over");
    expect(text).toContain("standby");
    // and the session line comes first, before the peer's words
    expect(text.indexOf(SID)).toBeLessThan(text.indexOf("hello from the peer"));
  });

  // ─────────────────────────────────────────────── A3: send() delivers nothing

  it("A3: send() in explicit mode calls no cello_send and reports success", () => {
    const v = runDriver(dir, {
      op: "send", delivery_mode: "explicit",
      metadata: { reply_to_message_id: "cello-wake-" + SID + "-deadbeef" },
      content: "the agent's answer",
    });
    expect(v.success).toBe(true);
    expect(v.calls.find((c) => c.method === "cello_send")).toBeUndefined();
  });

  // ─────────────────────────────────────────────── A4: the explicit hint

  it("A4: the explicit hint says nothing is sent, names cello_send and both signals", () => {
    const hint = hintFor(dir, "explicit");
    expect(hint).toContain("nothing you write here is sent");
    expect(hint).toContain("cello_send");
    expect(hint).toContain('"over"');
    expect(hint).toContain('"standby"');
    // It must NOT carry the channel-mode promise that the reply is auto-delivered.
    expect(hint).not.toContain("sent back to them");
    expect(hint).not.toContain("the bridge does both");
  });

  // ─────────────────────────────────────────────── A5: connect() mode agreement

  it("A5: connect() refuses an explicit adapter paired with a channel standing hint", () => {
    const v = runDriver(dir, { op: "connect", delivery_mode: "explicit", hint_mode: "channel" });
    expect(v.connected).toBe(false);
  });

  it("A5: connect() proceeds when adapter and hint both read explicit", () => {
    const v = runDriver(dir, { op: "connect", delivery_mode: "explicit", hint_mode: "explicit" });
    expect(v.connected).toBe(true);
  });

  // ─────────────────────────────────────────────── A6: channel/wake unchanged apart from config

  it("A6: channel mode still auto-delivers a reply and does NOT prefix a session line", () => {
    const inbound = runDriver(dir, { op: "notify", kind: "cello_message", data: MSG, delivery_mode: "channel" });
    // Channel mode hands over the peer's words with no cello_send instruction in the prose.
    expect(inbound.delivered![0].text).toContain("hello from the peer");
    expect(inbound.delivered![0].text).not.toContain("cello_send");
    const v = runDriver(dir, {
      op: "send", delivery_mode: "channel",
      metadata: { reply_to_message_id: inbound.delivered![0].message_id },
      content: "reply",
    });
    expect(v.success).toBe(true);
    expect(v.calls.find((c) => c.method === "cello_send")).toBeDefined();
  });

  it("A6: wake mode still delivers content-free prose and sends nothing from the adapter", () => {
    const inbound = runDriver(dir, { op: "notify", kind: "cello_message", data: MSG, delivery_mode: "wake" });
    expect(inbound.calls.find((c) => c.method === "cello_receive")).toBeUndefined();
    expect(inbound.delivered![0].text).toContain("CELLO wake");
    const v = runDriver(dir, {
      op: "send", delivery_mode: "wake",
      metadata: { reply_to_message_id: inbound.delivered![0].message_id },
    });
    expect(v.success).toBe(true);
    expect(v.calls.find((c) => c.method === "cello_send")).toBeUndefined();
  });
});
