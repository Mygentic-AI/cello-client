/**
 * M16 019-MEMBERSHIP — the PUBLISHER's side: who is in a channel, and the generation counter.
 *
 * Covers the storage half of tests 11, 12 and 15. The delivery half — wrapping a new key per
 * remaining member and sending it — is tested against the join handler.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";
import { ChannelMembershipStore, ChannelMembershipError } from "../channel-membership-store.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const CHANNEL = "aa".repeat(32);
const ALICE = "11".repeat(32);
const BOB = "22".repeat(32);
const RELAY_A = "/dns4/relay-a.example/tcp/443/tls/ws";

let dir: string;
let db: DaemonDatabase;
let members: ChannelMembershipStore;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cello-m16-019m-"));
  db = openTestDb(join(dir, "sessions.db"));
  members = new ChannelMembershipStore(db, silent);
  members.putSettings(CHANNEL, {
    access: "invite_only", members_visible: false, guidance: "release notes",
    retention_seconds: 7 * 24 * 3600, relays: [RELAY_A],
  });
});
afterEach(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("M16 019 — the publisher's membership records", () => {
  it("a channel starts at generation 0 — no key has ever been issued", () => {
    expect(members.settings(CHANNEL)?.key_generation).toBe(0);
    expect(members.activeMembers(CHANNEL)).toEqual([]);
  });

  it("11. already_member and ejected are distinguishable, and an ejected row is never deleted", () => {
    members.admit(CHANNEL, ALICE, "active", 1000);
    expect(members.statusOf(CHANNEL, ALICE)).toBe("active");

    members.eject(CHANNEL, ALICE);
    // ⚠️ THE ROW SURVIVES. Deleting it would make an ejected member indistinguishable from a
    // stranger, so their next join request would be admitted as a new one — which is the whole
    // thing an ejection is for.
    expect(members.statusOf(CHANNEL, ALICE)).toBe("ejected");
    expect(members.activeMembers(CHANNEL)).toEqual([]);
  });

  it("12. an eject flips the row and bumps the generation IN THE SAME TRANSACTION", () => {
    members.admit(CHANNEL, ALICE, "active", 1000);
    members.admit(CHANNEL, BOB, "active", 1000);
    const before = members.settings(CHANNEL)?.key_generation ?? -1;

    const result = members.eject(CHANNEL, BOB);
    expect(result.generation).toBe(before + 1);
    expect(members.settings(CHANNEL)?.key_generation).toBe(before + 1);
    expect(members.statusOf(CHANNEL, BOB)).toBe("ejected");

    /**
     * ⚠️ **THE REMAINING MEMBERS ARE WHO THE NEW KEY GOES TO, and the ejected one is simply not in
     * that list.** An eject that flipped the row without bumping the generation is not an eject at
     * all: every member including the ejected one keeps reading, and nothing says otherwise.
     */
    expect(result.remaining).toEqual([ALICE]);
    expect(members.activeMembers(CHANNEL)).toEqual([ALICE]);
  });

  it("12c. if the generation bump FAILS, the status flip rolls back with it", () => {
    members.admit(CHANNEL, ALICE, "active", 1000);
    members.admit(CHANNEL, BOB, "active", 1000);
    const before = members.settings(CHANNEL)?.key_generation ?? -1;

    /**
     * ⚠️ **THE REVERT THE DoD ASKS FOR, AND TEST 12 CANNOT DETECT IT.** Test 12 asserts the OUTCOME —
     * generation up by one, the right member left — so moving the bump outside the transaction
     * leaves it green: both statements still run, just not atomically. Only deleting the bump makes
     * it red, which is a weaker claim than the one the DoD quotes.
     *
     * This asserts the ATOMICITY instead, with a trigger that aborts the BUMP specifically — after
     * the status flip has run, inside the same transaction. Reads still work, so the eject gets as
     * far as it can before failing. Either both facts commit or neither does, so BOB stays active.
     */
    db.exec(`CREATE TRIGGER block_bump BEFORE UPDATE OF key_generation ON channel_config
             BEGIN SELECT RAISE(ABORT, 'bump blocked'); END`);
    let threw = false;
    try { members.eject(CHANNEL, BOB); } catch { threw = true; }
    db.exec(`DROP TRIGGER block_bump`);

    expect(threw, "the bump could not run").toBe(true);
    expect(members.statusOf(CHANNEL, BOB), "the status flip went back with it").toBe("active");
    expect(members.settings(CHANNEL)?.key_generation).toBe(before);
    expect(members.activeMembers(CHANNEL).sort()).toEqual([ALICE, BOB].sort());
  });

  it("12b. ejecting somebody who is not an active member changes NOTHING, generation included", () => {
    members.admit(CHANNEL, ALICE, "active", 1000);
    const before = members.settings(CHANNEL)?.key_generation ?? -1;

    // A stranger, and then a member already ejected. Both must leave the generation alone: bumping
    // it would re-key every real member for nothing, and each re-key is a delivery that can fail.
    expect(() => members.eject(CHANNEL, BOB)).toThrow(ChannelMembershipError);
    members.eject(CHANNEL, ALICE);
    const afterFirst = members.settings(CHANNEL)?.key_generation ?? -1;
    expect(() => members.eject(CHANNEL, ALICE)).toThrow(/not_an_active_member/);
    expect(members.settings(CHANNEL)?.key_generation).toBe(afterFirst);
    expect(afterFirst).toBe(before + 1);
  });

  it("15. an OPEN channel and a PUBLIC channel each refuse the eject BY NAME", () => {
    const openChannel = "bb".repeat(32);
    members.putSettings(openChannel, {
      access: "open", members_visible: false, guidance: "", retention_seconds: 3600, relays: [RELAY_A],
    });
    members.admit(openChannel, ALICE, "active", 1000);
    /**
     * ⚠️ An OPEN channel cannot eject because the member would simply rejoin — the re-key would cost
     * every other member a delivery and change nothing. Refusing by name says that, where a generic
     * failure would leave an admin retrying.
     */
    expect(() => members.eject(openChannel, ALICE)).toThrow(/eject_not_applicable_open_channel/);

    const publicChannel = "cc".repeat(32);
    members.putSettings(publicChannel, {
      access: "public", members_visible: true, guidance: "", retention_seconds: 3600, relays: [RELAY_A],
    });
    // A public channel has no members at all, so there is nothing to eject.
    expect(() => members.eject(publicChannel, ALICE)).toThrow(/eject_not_applicable_public_channel/);
  });

  it("a pending member is not an active one, and approval is what moves them", () => {
    members.admit(CHANNEL, ALICE, "pending", 1000);
    expect(members.statusOf(CHANNEL, ALICE)).toBe("pending");
    // ⚠️ A pending member receives NO KEY. Invite-only admission is the admin agent's decision, and
    // counting a pending request as a member would auto-approve every stranger who asked.
    expect(members.activeMembers(CHANNEL)).toEqual([]);

    members.approve(CHANNEL, ALICE);
    expect(members.statusOf(CHANNEL, ALICE)).toBe("active");
    expect(members.activeMembers(CHANNEL)).toEqual([ALICE]);
  });

  it("an unknown channel has no settings, and that is an answer rather than a throw", () => {
    expect(members.settings("dd".repeat(32))).toBeNull();
    expect(members.statusOf("dd".repeat(32), ALICE)).toBeNull();
  });

  it("035 item 6 — approve with nothing pending is not_a_pending_request, with refuse's own guidance", () => {
    // Today approve threw `not_an_active_member: no pending request…` — a DIFFERENT reason word from
    // `refuse` for the same situation, so an operator who typed approve when there was no request got
    // a contradictory label. Both now report not_a_pending_request and point at eject.
    expect(() => members.approve(CHANNEL, ALICE)).toThrow(/not_a_pending_request/);
    expect(() => members.approve(CHANNEL, ALICE)).toThrow(/eject them/);
    // The SAME guidance refuse gives for the same state — the two are now indistinguishable in reason.
    expect(() => members.refusePending(CHANNEL, ALICE)).toThrow(/not_a_pending_request/);
    expect(() => members.refusePending(CHANNEL, ALICE)).toThrow(/eject them/);
  });
});
