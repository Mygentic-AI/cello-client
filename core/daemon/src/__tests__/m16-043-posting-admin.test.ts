/**
 * M16 043-POSTERS Part E — the admin's side: the posting setting, listed posters, passes, the lease.
 *
 *   - `posting` admin | listed | members, stored on channel_config; members' `can_post` for listed
 *   - passes go to: listed → can_post members; members → every active member (and on admission)
 *   - the renewal tick re-issues a pass with < 2 days left; an unreached poster is retried next tick
 *   - remove / eject / switch to admin → a revocation entry in the info record, and no renewal
 *   - a channel whose posting is admin with no revocations deposits `ext: null` — today's record
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeypair } from "@cello-protocol/crypto";
import type { InMemoryKeyProvider } from "@cello-protocol/crypto";
import { decodeChannelPosterPass, verifyPosterPass } from "@cello-protocol/protocol-types";
import { ChannelConfigStore } from "../channel-config-store.js";
import { ChannelMembershipStore } from "../channel-membership-store.js";
import { ChannelPosterGrantStore } from "../channel-poster-grant-store.js";
import { createChannelPostingAdmin } from "../channel-posting-admin.js";
import { openTestDb } from "./helpers/encrypted-db.js";
import type { DaemonDatabase } from "../sqlcipher-db.js";
import type { Logger } from "../types.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const RELAY = "/dns4/relay-a.example/tcp/443/tls/ws/p2p/12D3KooWJXHpnWQhGk3jXBJYdXMmeLxEhRqzwZCYd1bxSUh4pg83";
const T0 = 1_800_000_000_000;
const DAY = 86_400_000;
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

let dir: string;
let db: DaemonDatabase;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "cello-m16-043e-"));
  db = openTestDb(join(dir, "sessions.db"));
});
afterEach(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
});

interface H {
  admin: ReturnType<typeof createChannelPostingAdmin>;
  config: ChannelConfigStore; members: ChannelMembershipStore; grants: ChannelPosterGrantStore;
  channel: InMemoryKeyProvider; channelHex: string; clock: { now: number };
  sent: Array<{ member: string; issued_at: number; expires_at: number; members: string[] }>;
  removed: Array<{ member: string; channelHex: string }>;
  unreachable: Set<string>;
  deposits: number;
}

async function harness(access: "invite_only" | "public" = "invite_only"): Promise<H> {
  const channel = generateKeypair();
  const adminAgent = generateKeypair();
  const channelHex = hex(await channel.getPublicKey());
  const config = new ChannelConfigStore(db, silent);
  const members = new ChannelMembershipStore(db, silent);
  const grants = new ChannelPosterGrantStore(db, silent);
  config.set(channelHex, { access, relays: [RELAY], guidance: "", retention_seconds: 3600, admin_pubkey: hex(await adminAgent.getPublicKey()) }, T0);
  const h = { config, members, grants, channel, channelHex, clock: { now: T0 }, sent: [], removed: [], unreachable: new Set<string>(), deposits: 0 } as unknown as H;
  let depositsAtLastRing = -1;
  h.admin = createChannelPostingAdmin({
    logger: silent, config, members, grants, now: () => h.clock.now,
    channelKeyFor: (ch) => (ch === channelHex ? channel : null),
    adminAgentNameFor: (ch) => (ch === channelHex ? "admin" : null),
    postingChannels: () => [channelHex],
    // 045-NOTICEBELL: a pass is a sealed notice plus a ring; a removal is the info record plus a ring.
    sendPass: async (ch, member, passCbor, memberList) => {
      if (h.unreachable.has(member)) return false;
      const d = decodeChannelPosterPass(passCbor);
      if (!d.ok) throw new Error(d.reason);
      expect(ch).toBe(channelHex);
      expect(verifyPosterPass(d.pass, await channel.getPublicKey())).toEqual({ ok: true });
      expect(hex(d.pass.poster_pubkey)).toBe(member);
      h.sent.push({ member, issued_at: d.pass.issued_at, expires_at: d.pass.expires_at, members: memberList.map((m) => hex(m)) });
      return true;
    },
    ringPoster: (ch, member) => {
      // The ring must follow the deposit of the revoking info record, never precede it.
      expect(h.deposits, "the revoking info record is deposited before the ring").toBeGreaterThan(depositsAtLastRing);
      depositsAtLastRing = h.deposits;
      h.removed.push({ member, channelHex: ch });
      return Promise.resolve();
    },
    depositInfo: () => { h.deposits += 1; return Promise.resolve(); },
  });
  return h;
}

function memberHex(n: number): string {
  return n.toString(16).padStart(64, "0");
}

describe("043-POSTERS Part E — the admin's posting setting", () => {
  it("E1. `members` issues a pass to every active member, and on a later admission; `admin` ext is null", async () => {
    const h = await harness();
    expect(h.admin.infoExt(h.channelHex)).toBeNull();
    h.members.admit(h.channelHex, memberHex(1), "active", T0);
    h.members.admit(h.channelHex, memberHex(2), "pending", T0);
    expect(await h.admin.setPosting(h.channelHex, "members")).toEqual({ ok: true });
    expect(h.config.get(h.channelHex)?.posting).toBe("members");
    expect(h.sent.map((s) => s.member)).toEqual([memberHex(1)]);
    expect(h.sent[0]!.expires_at - h.sent[0]!.issued_at).toBe(7 * DAY);
    expect(h.deposits).toBe(1);
    expect(h.admin.infoExt(h.channelHex)).toEqual({ posting: "members", revoked: [] });

    h.members.admit(h.channelHex, memberHex(3), "active", T0);
    await h.admin.onAdmitted(h.channelHex, memberHex(3));
    expect(h.sent.map((s) => s.member)).toEqual([memberHex(1), memberHex(3)]);
  });

  it("E2. the renewal tick re-issues a pass under 2 days left, not one with more; unreached is retried next tick", async () => {
    const h = await harness();
    h.members.admit(h.channelHex, memberHex(1), "active", T0);
    h.members.admit(h.channelHex, memberHex(2), "active", T0);
    await h.admin.setPosting(h.channelHex, "members", 3);
    expect(h.sent.length).toBe(2);

    h.clock.now = T0 + DAY; // 2 days left — not under 2
    await h.admin.tick();
    expect(h.sent.length).toBe(2);

    h.clock.now = T0 + DAY + 1; // under 2 days left
    h.unreachable.add(memberHex(2));
    await h.admin.tick();
    expect(h.sent.map((s) => s.member)).toEqual([memberHex(1), memberHex(2), memberHex(1)]);
    expect(h.sent[2]!.issued_at).toBe(T0 + DAY + 1);

    h.unreachable.clear();
    h.clock.now = T0 + DAY + 2;
    await h.admin.tick();
    expect(h.sent.map((s) => s.member)).toEqual([memberHex(1), memberHex(2), memberHex(1), memberHex(2)]);
  });

  it("E3. `poster remove` revokes: a revocation entry in the info record, and no renewal", async () => {
    const h = await harness();
    h.members.admit(h.channelHex, memberHex(1), "active", T0);
    await h.admin.setPosting(h.channelHex, "members");
    h.clock.now = T0 + 10;
    expect(await h.admin.removePoster(h.channelHex, memberHex(1))).toEqual({ ok: true });
    expect(h.admin.infoExt(h.channelHex)).toEqual({
      posting: "members", revoked: [{ poster_pubkey: new Uint8Array(Buffer.from(memberHex(1), "hex")), revoked_at: T0 + 10 }],
    });
    h.clock.now = T0 + 6 * DAY;
    await h.admin.tick();
    expect(h.sent.length).toBe(1);
    // Re-adding issues a newer pass, after the revocation time.
    h.clock.now = T0 + 6 * DAY + 5;
    await h.admin.setPosting(h.channelHex, "listed");
    expect(await h.admin.addPoster(h.channelHex, memberHex(1))).toEqual({ ok: true });
    expect(h.sent[1]!.issued_at).toBeGreaterThan(T0 + 10);
  });

  it("E4. `listed`: only can_post members get passes; add refuses non-members and public channels", async () => {
    const h = await harness();
    h.members.admit(h.channelHex, memberHex(1), "active", T0);
    h.members.admit(h.channelHex, memberHex(2), "active", T0);
    await h.admin.setPosting(h.channelHex, "listed");
    expect(h.sent.length).toBe(0);
    expect(await h.admin.addPoster(h.channelHex, memberHex(2))).toEqual({ ok: true });
    expect(h.sent.map((s) => s.member)).toEqual([memberHex(2)]);
    expect(await h.admin.addPoster(h.channelHex, memberHex(9))).toMatchObject({ ok: false, reason: "not_an_active_member" });

    // 044-POSTERBELL Part E1: a PUBLIC channel CAN name posters now, as long as the poster is an
    // active member (a reader who joined). A non-member is still refused.
    const p = await harness("public");
    p.members.admit(p.channelHex, memberHex(1), "active", T0);
    await p.admin.setPosting(p.channelHex, "listed");
    expect(await p.admin.addPoster(p.channelHex, memberHex(1))).toEqual({ ok: true });
    expect(await p.admin.addPoster(p.channelHex, memberHex(9))).toMatchObject({ ok: false, reason: "not_an_active_member" });
  });

  it("E5. eject and switching to admin revoke every live pass and stop renewing", async () => {
    const h = await harness();
    h.members.admit(h.channelHex, memberHex(1), "active", T0);
    h.members.admit(h.channelHex, memberHex(2), "active", T0);
    await h.admin.setPosting(h.channelHex, "members");
    h.clock.now = T0 + 1;
    h.members.eject(h.channelHex, memberHex(1));
    await h.admin.onEjected(h.channelHex, memberHex(1));
    expect(h.admin.infoExt(h.channelHex)?.revoked.map((r) => hex(r.poster_pubkey))).toEqual([memberHex(1)]);
    h.clock.now = T0 + 2;
    await h.admin.setPosting(h.channelHex, "admin");
    expect(h.admin.infoExt(h.channelHex)?.posting).toBe("admin");
    expect(h.admin.infoExt(h.channelHex)?.revoked.map((r) => hex(r.poster_pubkey)).sort()).toEqual([memberHex(1), memberHex(2)]);
    h.clock.now = T0 + 6 * DAY;
    await h.admin.tick();
    expect(h.sent.length).toBe(2);
  });

  it("E6. a bad posting value or lease is refused by name", async () => {
    const h = await harness();
    expect(await h.admin.setPosting(h.channelHex, "everyone" as never)).toMatchObject({ ok: false, reason: "bad_posting" });
    expect(await h.admin.setPosting(h.channelHex, "members", 0)).toMatchObject({ ok: false, reason: "bad_lease" });
  });

  // 044-POSTERBELL Part B: every pass carries the channel's current members, and a membership change
  // re-sends passes on the next tick even when the lease is nowhere near expiring — so an ejected
  // member drops out of a poster's ring targets promptly rather than at expiry.
  it("B. a pass carries current members, and after an eject the tick re-sends without the ejected", async () => {
    const h = await harness();
    h.members.admit(h.channelHex, memberHex(1), "active", T0);
    h.members.admit(h.channelHex, memberHex(2), "active", T0);
    await h.admin.setPosting(h.channelHex, "members");
    // Both posters got a pass, each carrying BOTH members.
    expect(h.sent.map((s) => s.member).sort()).toEqual([memberHex(1), memberHex(2)]);
    for (const s of h.sent) expect(s.members.slice().sort()).toEqual([memberHex(1), memberHex(2)]);

    // Eject member 1. Its grant is revoked; member 2 still holds a pass with plenty of lease left.
    h.clock.now = T0 + 1;
    h.members.eject(h.channelHex, memberHex(1));
    await h.admin.onEjected(h.channelHex, memberHex(1));
    h.sent.length = 0;

    // The next tick — nowhere near the 2-day renewal window — re-sends to member 2 because the
    // roster changed, and the fresh pass's member list no longer names the ejected member.
    h.clock.now = T0 + 2;
    await h.admin.tick();
    expect(h.sent.map((s) => s.member)).toEqual([memberHex(2)]);
    expect(h.sent[0]!.members).toEqual([memberHex(2)]);

    // A second tick with no further change sends nothing (the dirty flag was cleared).
    h.sent.length = 0;
    h.clock.now = T0 + 3;
    await h.admin.tick();
    expect(h.sent).toEqual([]);
  });

  // 044-POSTERBELL Part E3: a removed poster is TOLD — remove, eject, and switch-to-admin each send
  // the poster-removed notice over the sealed-session route.
  it("E3. remove and switch-to-admin ring the poster after the revoking record; an eject rings through its own eject notice", async () => {
    // remove a listed poster
    const h1 = await harness();
    h1.members.admit(h1.channelHex, memberHex(1), "active", T0);
    await h1.admin.setPosting(h1.channelHex, "listed");
    await h1.admin.addPoster(h1.channelHex, memberHex(1));
    await h1.admin.removePoster(h1.channelHex, memberHex(1));
    expect(h1.removed).toEqual([{ member: memberHex(1), channelHex: h1.channelHex }]);

    // eject a members-mode poster
    const h2 = await harness();
    h2.members.admit(h2.channelHex, memberHex(2), "active", T0);
    await h2.admin.setPosting(h2.channelHex, "members");
    h2.members.eject(h2.channelHex, memberHex(2));
    await h2.admin.onEjected(h2.channelHex, memberHex(2));
    // 045-NOTICEBELL: the eject verb writes the member's eject notice and rings them; the posting
    // admin only revokes and re-deposits the record — a second ring would be a duplicate notice.
    expect(h2.removed).toEqual([]);
    expect(h2.admin.infoExt(h2.channelHex)?.revoked.map((r) => hex(r.poster_pubkey))).toEqual([memberHex(2)]);

    // switch to admin — every live poster is told
    const h3 = await harness();
    h3.members.admit(h3.channelHex, memberHex(3), "active", T0);
    await h3.admin.setPosting(h3.channelHex, "members");
    h3.clock.now = T0 + 1;
    await h3.admin.setPosting(h3.channelHex, "admin");
    expect(h3.removed).toEqual([{ member: memberHex(3), channelHex: h3.channelHex }]);
  });
});
