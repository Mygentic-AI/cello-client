/**
 * M16 016-CLIENTREWORK — the epoch layer is gone from what SHIPS, not only from what compiles.
 *
 * Deleting a source file does NOT remove its `dist/` artifact: a stale build keeps publishing the
 * deleted module, so an operator installs code this repo no longer contains. The assertion is
 * therefore made against the BUILT output, and it is the one that would have caught the orphan.
 *
 * `merkle.ts` and the session-seal machinery are untouched by this order — session sealing has
 * nothing to do with channels — so the symbols below are named narrowly enough to say nothing
 * about them.
 */
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";

const CORE = join(import.meta.dirname, "../../../..", "core");

/** Every file under `dir`, recursively. */
function filesUnder(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...filesUnder(full));
    else out.push(full);
  }
  return out;
}

/** The symbols that only ever existed for channel epoch sealing and notarization. */
const DEAD_SYMBOLS = [
  "channel_epoch",
  "ChannelEpochSeal",
  "ChannelEpochSealer",
  "sealIfDue",
  "cello_channel_seal",
  "ChannelSealRequestGate",
  "prev_epoch_root",
  "epoch_index",
  "consistencyProof",
];

describe("M16 016-CLIENTREWORK: the epoch layer is deleted", () => {
  it("1. no built artifact under core/*/dist mentions any epoch-sealing symbol", () => {
    const builtDirs = readdirSync(CORE)
      .map((pkg) => join(CORE, pkg, "dist"))
      .filter((d) => existsSync(d));
    expect(builtDirs.length, "core/*/dist is empty — build before asserting on what ships").toBeGreaterThan(0);

    const offenders: string[] = [];
    for (const dir of builtDirs) {
      for (const file of filesUnder(dir)) {
        if (!/\.(js|d\.ts|map|json)$/.test(file)) continue;
        const text = readFileSync(file, "utf-8");
        for (const symbol of DEAD_SYMBOLS) {
          if (text.includes(symbol)) offenders.push(`${file.slice(CORE.length + 1)}: ${symbol}`);
        }
      }
    }
    expect(offenders, "stale dist output still ships deleted modules; `rm -rf core/*/dist` and rebuild").toEqual([]);
  });

  it("2. no source file under core/*/src carries the deleted modules", () => {
    const sources = readdirSync(CORE)
      .flatMap((pkg) => filesUnder(join(CORE, pkg, "src")))
      .filter((f) => f.endsWith(".ts"));
    const dead = [
      "channel-epoch-sealer.ts",
      "channel-epoch-seal-store.ts",
      "channel-epoch-tick.ts",
      "channel-seal-request.ts",
      "channel-epoch-seal.ts",
      "consistency.ts",
    ];
    const survivors = sources.filter((f) => dead.some((d) => f.endsWith(`/${d}`)));
    expect(survivors).toEqual([]);

    // The publisher's log is a post log now: no epoch column, no epoch state, anywhere in it.
    const logStore = readFileSync(join(CORE, "daemon/src/channel-log-store.ts"), "utf-8");
    expect(logStore.toLowerCase()).not.toContain("epoch");
  });
});
