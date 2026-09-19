/**
 * 023-MCPCHAN — every channel capability the daemon serves is reachable from MCP.
 *
 * WHY THIS EXISTS, and it is the order's whole thesis. The MCP surface is audited against ONE table,
 * `vocabulary.ts`, in both directions: every tool the shim registers must be in the table, and every
 * row in the table must be registered by the shim. **Neither direction asks whether a capability
 * reached the table at all.** Sixteen orders added fourteen channel verbs to the daemon and the CLI,
 * skipped the table, and every guard stayed green while an agent could not touch a channel.
 *
 * So this audit starts from the DAEMON'S OWN HANDLER REGISTRATIONS — the thing that cannot be
 * forgotten, because it is what makes the verb work — and asks whether the shim can reach each one.
 *
 * ⚠️ IT DERIVES THE LIST, IT DOES NOT RESTATE IT. A hand-written list of fourteen names is exactly
 * the artifact that goes stale: verb fifteen gets added and nobody updates the test.
 *
 * ⚠️ IT CHECKS `proxy.call`, NOT `server.tool`. The tool name follows the CLI command; the daemon
 * WIRE name is never renamed, because `connect` has no daemon dependency and a new daemon must keep
 * serving an old shim. So `cello channel setup` is the tool `cello_channel_setup` calling the method
 * `cello_channel_config` — two legitimately different strings. Reachability is a property of the
 * wire call, and that is what is asserted here.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const SHIM_SRC = readFileSync(join(here, "..", "bin", "cello-mcp.ts"), "utf8");
const DAEMON_SRC = join(here, "..", "..", "..", "daemon", "src");

/**
 * Every `.ts` under the daemon's source, RECURSIVELY.
 *
 * ⚠️ It was a flat `readdirSync` filtered to `isFile()`. Verb fifteen landing in
 * `core/daemon/src/channels/` would have been invisible to the scan, the `>= 14` guard would still
 * have passed on the fourteen at the top level, and the reachability assertion would have passed
 * with it — an audit reporting success about a file it never opened. The parity audit next door
 * learned the same lesson twice; this one is not going to learn it a third time.
 */
function daemonSources(dir: string = DAEMON_SRC): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    if (e.name === "__tests__" || e.name === "node_modules") return [];
    const full = join(dir, e.name);
    return e.isDirectory() ? daemonSources(full) : e.name.endsWith(".ts") ? [full] : [];
  });
}

/** Every `cello_channel*` IPC method the daemon registers a handler for. */
function daemonChannelMethods(): string[] {
  const found = new Set<string>();
  for (const f of daemonSources()) {
    for (const m of readFileSync(f, "utf8").matchAll(/handlers\.set\(\s*"(cello_channels?[a-z_]*)"/g)) {
      found.add(m[1]!);
    }
  }
  return [...found].sort();
}

/**
 * The parameter names a daemon handler actually READS, per method.
 *
 * Handlers read their arguments as `params?.["name"]`, and the two shared helpers `needAgent` and
 * `needChannel` read `agent` and `channel` on every one of them — so those two are added rather
 * than scanned for, since they are read in a different function from the handler body.
 */
function handlerParams(): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  for (const f of daemonSources()) {
    const text = readFileSync(f, "utf8");
    // Each handler body runs to the start of the next `handlers.set(` — good enough to attribute a
    // `params?.["x"]` to the verb it belongs to, and it is checked below by a negative control.
    const starts = [...text.matchAll(/handlers\.set\(\s*"(cello_channels?[a-z_]*)"/g)];
    starts.forEach((m, i) => {
      const body = text.slice(m.index!, starts[i + 1]?.index ?? text.length);
      const names = new Set(["agent", "channel"]);
      for (const p of body.matchAll(/params\??\.\[\s*"([a-z_]+)"\s*\]/g)) names.add(p[1]!);
      out.set(m[1]!, names);
    });
  }
  return out;
}

/** What the shim SENDS to each daemon method: the keys of the object literal it passes. */
function shimPayloads(): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  for (const m of SHIM_SRC.matchAll(/proxy\.call\(\s*"(cello_channels?[a-z_]*)"\s*,\s*\{([\s\S]*?)\}\s*\)\s*\)/g)) {
    const keys = new Set<string>();
    // `channel,` and `title,` (shorthand) and `...(x ? { relay } : {})` (spread) both land here.
    for (const k of m[2]!.matchAll(/(?:^|[\s,{])([a-z_]+)\s*(?:,|:|\})/g)) keys.add(k[1]!);
    out.set(m[1]!, keys);
  }
  return out;
}

/** Every daemon method the shim proxies to, whatever the tool it sits behind is called. */
function shimProxiedMethods(): Set<string> {
  return new Set([...SHIM_SRC.matchAll(/proxy\.call\(\s*"(cello_[a-z_]+)"/g)].map((m) => m[1]!));
}

describe("023-MCPCHAN — the channel verbs are on the MCP surface", () => {
  it("finds the daemon's channel handlers at all (guards against a vacuous pass)", () => {
    // If the scan finds nothing — a moved file, a changed registration idiom — every assertion
    // below passes trivially, which is the failure mode this audit was written to end.
    expect(daemonChannelMethods().length).toBeGreaterThanOrEqual(14);
  });

  it("every channel verb the daemon serves is reachable through the shim", () => {
    const proxied = shimProxiedMethods();
    const unreachable = daemonChannelMethods().filter((m) => !proxied.has(m));
    expect(
      unreachable,
      `The daemon serves these channel verbs and the MCP shim cannot call them, so an agent ` +
        `cannot use them at all — only a person at a terminal can. Register a tool for each and ` +
        `add its row to ALWAYS_ON_VERBS in vocabulary.ts.\n  ${unreachable.join("\n  ")}`,
    ).toEqual([]);
  });

  /**
   * ⚠️ THE ASSERTION ABOVE IS NOT ENOUGH, AND ORDER 022 IS THE PROOF.
   *
   * There, `join` passed `target` where the negotiator read `target_pubkey` and read back
   * `session_id` where the handler returned `sessionId`. Thirteen unit tests were green because
   * every one of them stubbed that seam, and the operator saw a network error for a caller bug.
   * "The shim calls this method" would have been just as green. So this asks the harder question:
   * does it call it with names the handler reads?
   */
  it("every key the shim sends is one the handler reads", () => {
    const reads = handlerParams();
    const sends = shimPayloads();
    expect(sends.size, "no proxy payloads parsed — this audit would be vacuous").toBeGreaterThanOrEqual(14);

    const unread: string[] = [];
    for (const [method, keys] of sends) {
      const known = reads.get(method);
      if (!known) {
        unread.push(`${method}: the shim calls it and no daemon handler registers it`);
        continue;
      }
      for (const k of keys) if (!known.has(k)) unread.push(`${method}: sends '${k}', handler never reads it`);
    }
    expect(
      unread,
      `The shim proxies to a real handler and hands it a name the handler does not read, so the ` +
        `field arrives as undefined and the caller is answered with a refusal that points at the ` +
        `counterparty for a bug in this file.\n  ${unread.join("\n  ")}`,
    ).toEqual([]);
  });

  it("the payload scan can actually see a wrong name (negative control)", () => {
    // A parser that matched nothing would make the test above pass for every possible defect. This
    // proves it reads real keys out of a real call, and that a stray one would not be in the set.
    const publish = shimPayloads().get("cello_channel_publish");
    expect(publish).toBeDefined();
    expect([...publish!].sort()).toEqual(["agent", "body", "channel", "title"]);
    expect(handlerParams().get("cello_channel_publish")?.has("target_pubkey")).toBe(false);
  });
});
