/**
 * M16 020-CHANADMIN — the subscriber's admin source, wired.
 *
 * `profileAdminPubkey` is what the join exchange compares the answering agent against. Until now it
 * answered only from this daemon's OWN settings, so it returned null for every channel this machine
 * did not itself publish, and the join was refused `admin_unresolved`. That made channels
 * single-machine. It now falls through to the directory.
 *
 * ⚠️ **`null` STILL MEANS REFUSE.** This order removes a refusal that was firing on every channel;
 * it must not weaken the one that remains. A directory that cannot be reached leaves the join
 * refused exactly as before — the tests below are mostly about that.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";
import { ChannelMembershipStore } from "../channel-membership-store.js";
import { createProfileAdminPubkey } from "../channel-membership-wiring.js";
import type { ChannelAdminOutcome } from "../channel-admin-lookup.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const OURS = "aa".repeat(32);
const THEIRS = "bb".repeat(32);
const OUR_ADMIN = "11".repeat(32);
const THEIR_ADMIN = "22".repeat(32);
const AGENT = "agent-1";
const RELAY_A = "/dns4/relay-a.example/tcp/443/tls/ws";

let dir: string;
let db: DaemonDatabase;
let members: ChannelMembershipStore;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cello-m16-020w-"));
  db = openTestDb(join(dir, "sessions.db"));
  members = new ChannelMembershipStore(db, silent);
  // A channel THIS daemon administers. The other one it has never heard of.
  members.putSettings(OURS, {
    access: "invite_only", members_visible: false, guidance: "",
    retention_seconds: 3600, relays: [RELAY_A], admin_pubkey: OUR_ADMIN,
  });
});
afterEach(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

function build(lookup: (agentId: string, channelHex: string) => Promise<ChannelAdminOutcome>) {
  return createProfileAdminPubkey({ members, lookup, logger: silent });
}

describe("M16 020 — where the subscriber's admin key comes from", () => {
  it("13. a channel this daemon does NOT administer now resolves, from the directory", async () => {
    /**
     * ⚠️ **THE WHOLE POINT OF THE ORDER.** This returned null before, for every channel not
     * published from this machine, and the join was refused. Nobody could join anybody else's
     * channel — including their own, from a second device.
     */
    const lookup = vi.fn(async () => ({ kind: "admin", adminPubkeyHex: THEIR_ADMIN }) as ChannelAdminOutcome);
    expect(await build(lookup)(THEIRS, AGENT)).toEqual({ ok: true, adminPubkeyHex: THEIR_ADMIN });
    expect(lookup).toHaveBeenCalledWith(AGENT, THEIRS);
  });

  it("14. a directory that cannot be reached leaves it REFUSED, never accepted", async () => {
    /**
     * ⚠️ The refusal this order must not weaken. `unavailable` is the absence of an answer, and
     * answering with anything at all here — least of all "whoever answered" — would turn a network
     * problem into an admission.
     */
    /**
     * ⚠️ M16 021 item 21: the REASON now travels with the refusal. Both of these still refuse —
     * that is the property this test exists for — but `admin_unresolved` alone could not tell a
     * timeout against an unrolled directory from a database fault, and an operator got one word.
     */
    const unreachable = build(async () => ({ kind: "unavailable", reason: "timeout" }));
    expect(await unreachable(THEIRS, AGENT)).toEqual({ ok: false, reason: "timeout" });

    const faulted = build(async () => ({ kind: "unavailable", reason: "lookup_failed" }));
    expect(await faulted(THEIRS, AGENT)).toEqual({ ok: false, reason: "lookup_failed" });
  });

  it("14b. a pubkey the directory says is NOT a channel is refused too", async () => {
    // A settled answer, and it still gives the comparison nothing to run against. There is no admin
    // because there is no channel.
    expect(await build(async () => ({ kind: "not_a_channel" }))(THEIRS, AGENT))
      .toEqual({ ok: false, reason: "not_a_channel" });
  });

  it("15. a channel this daemon administers is answered LOCALLY — the directory is not asked", async () => {
    /**
     * We are the publisher; our own settings are the source. Asking the directory about ourselves
     * would put a network round trip, and a directory outage, in the path of a join to a channel
     * running on this very machine.
     */
    const lookup = vi.fn(async () => ({ kind: "unavailable", reason: "timeout" }) as ChannelAdminOutcome);
    expect(await build(lookup)(OURS, AGENT)).toEqual({ ok: true, adminPubkeyHex: OUR_ADMIN });
    expect(lookup, "the directory was never asked").not.toHaveBeenCalled();
  });

  it("15b. a lookup that THROWS is refused, and does not escape into the join path", async () => {
    // The join handler runs this inside the inbound content path. An exception here would surface as
    // a broken session rather than a refused join.
    // Refused, and the thrown message is what the operator sees rather than a bare word.
    expect(await build(async () => { throw new Error("boom"); })(THEIRS, AGENT))
      .toEqual({ ok: false, reason: "boom" });
  });
});
