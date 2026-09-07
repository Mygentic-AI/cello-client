/**
 * DOD-M15-INBOXCAUSE-1 / `041-PARKSTUCK` Unit 2 — the park drain's refusals reach a PERSON.
 *
 * ─── The failure, measured on Andre's own daemon 2026-09-07 ────────────────────────────────────
 *
 * One parked message on session `dcec3c3f…` was pulled, verified and refused 731 times over 64
 * hours. What the operator could see was a count and the reason `session_committed`, plus *"Nothing
 * is wrong on your side. There is nothing to repair here."* Both true, and neither about the loop:
 * `session_committed` is where the message was turned away ON ARRIVAL; `annex_salt_unavailable` is
 * why it never LEAVES the mailbox. The second one existed — with an `impact` and a `guidance`
 * written for a person — at ERROR, in `daemon.log`, addressed to nobody.
 *
 * That is error substitution in the one place there is no upstream to chase. Everywhere else in
 * this system naming the exit point instead of the cause costs an engineer an hour of tracing;
 * pointed at an operator it is a dead end, because `daemon.log` is not an operator affordance. The
 * diagnosis had to be done by a coding agent grepping a log file, which is the whole reason this
 * unit exists.
 *
 * Three properties, and the third is the one that bites.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { readdirSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { PassthroughGatewayClient } from "@cello-protocol/gateway/testing";
import { startDaemon, type DaemonHandle } from "../daemon.js";
import { connectToDaemon, type IpcClient } from "../ipc-client.js";
import { FileKeyProvider } from "@cello-protocol/crypto";
import {
  PARK_REFUSAL_REASONS,
  PARK_REFUSAL_NOTICE,
  TERMINAL_SESSION_STATUSES,
  refusalRecurrence,
  type ParkRefusalReason,
} from "../park-refusals.js";
import type { Logger, DaemonConfig } from "../types.js";

const SRC = join(dirname(fileURLToPath(import.meta.url)), "..");
const ALL_PARK_REASONS = Object.values(PARK_REFUSAL_REASONS) as ParkRefusalReason[];

/**
 * ⚠️ **EVERY DAEMON SOURCE FILE, GLOBBED — never a hand-typed list.**
 *
 * `DOD-M15-GUARD-HEARD-1` records why in its own words: a loop over a maintained list gets SHORTER
 * when someone forgets an entry, never red, and three separate guards in this suite went blind that
 * way during the 036/037 god-file split. A glob cannot shrink, and the next file to refuse a parked
 * message is scanned the day it is written.
 */
function daemonSources(): string {
  return readdirSync(SRC)
    /**
     * ⚠️ **`park-refusals.ts` IS EXCLUDED, AND WITHOUT THAT THIS SCAN CANNOT FAIL.**
     *
     * `PARK_REFUSAL_NOTICE` keys its total map on `[PARK_REFUSAL_REASONS.<MEMBER>]`, so every
     * reason references itself inside the very file that DECLARES it — and because the map is
     * typed total, a new reason must appear there. The emission check below therefore found a
     * reference for every reason no matter what any refusal site did, and reported coverage that
     * had never been earned. A false CAUGHT, which is the worse half of the pair: a false green
     * leaves the suspicion alive, a false caught retires it.
     *
     * ⚠️ **AND THIS EXCLUSION WAS WRITTEN ONCE ALREADY AND LOST BEFORE IT WAS COMMITTED.** The
     * mutation loop that found the defect restores mutated paths with `git checkout --`, which
     * reads the INDEX — and this file's fix was not yet staged, so a later mutant's cleanup
     * silently reverted it while the commit message went on claiming it. That is the lost-work
     * shape M15-PROCEDURE §2 rule 1 exists for: commit the fix BEFORE the loop exists. Recorded
     * here rather than in the journal alone because the next person to add a mutation loop to this
     * file is the one who needs it.
     *
     * The declaring file is not an emitter. Only the files that REFUSE are scanned.
     */
    .filter((f) => f.endsWith(".ts") && f !== "park-refusals.ts")
    .map((f) =>
      // Comments do not emit. A commented-out reference would otherwise satisfy the scan while the
      // real emission was replaced by a bare literal.
      readFileSync(join(SRC, f), "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, ""),
    )
    .join("\n");
}

describe("DOD-M15-INBOXCAUSE-1: every park refusal reason is emitted, and none is a bare literal", () => {
  it("the scan can SEE — a positive control before any negative is believed", () => {
    /**
     * An empty search result is evidence only if the search was shown capable of finding something.
     * Without this, a broken `SRC` path or a filter that matches nothing makes every assertion
     * below pass by finding no violations in no files.
     */
    const sources = daemonSources();
    expect(sources.length, "the daemon source glob read nothing at all").toBeGreaterThan(10_000);
    expect(
      /PARK_REFUSAL_REASONS\./.test(sources),
      "no daemon source references PARK_REFUSAL_REASONS — the emitter scan is matching nothing, so " +
        "everything it proves below is vacuous",
    ).toBe(true);
  });

  it("EVERY declared park reason is actually emitted by a refusal site", () => {
    // The direction that rots quietly: a reason nobody emits is dead weight that still reads as
    // coverage, and the inbox tests below would happily prove that an unreachable reason surfaces
    // beautifully.
    const sources = daemonSources();
    const memberFor: Record<string, string> = Object.fromEntries(
      Object.entries(PARK_REFUSAL_REASONS).map(([member, value]) => [value, member]),
    );
    const unemitted = ALL_PARK_REASONS.filter((v) => !sources.includes(`PARK_REFUSAL_REASONS.${memberFor[v]}`));
    expect(
      unemitted,
      `Declared, given a notice, and emitted by nothing: ${unemitted.join(", ")}. Either wire the ` +
        `refusal or delete the reason — a reason with guidance and no emitter reads as a control ` +
        `that exists.`,
    ).toEqual([]);
  });

  it("no daemon source writes a park reason as a bare string literal", () => {
    /**
     * The park drain used to push free-form strings into its refusal list, so a renamed reason
     * would miss the notice lookup in silence and the operator would be back to a bare code — the
     * exact defect the notice table exists to end, reintroduced by a typo with every test green.
     *
     * `park-refusals.ts` is excluded because it is where the values are DECLARED.
     */
    const offenders: string[] = [];
    for (const file of readdirSync(SRC).filter((f) => f.endsWith(".ts") && f !== "park-refusals.ts")) {
      const text = readFileSync(join(SRC, file), "utf8")
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/^\s*\/\/.*$/gm, "");
      for (const value of ALL_PARK_REASONS) {
        if (text.includes(`"${value}"`)) offenders.push(`${file}: "${value}"`);
      }
    }
    expect(
      offenders,
      `These write a park refusal reason as a literal: ${offenders.join(", ")}. Use ` +
        `PARK_REFUSAL_REASONS.<MEMBER> so a rename is a compile error rather than a silently missed ` +
        `notice lookup.`,
    ).toEqual([]);
  });

  it("★ no park reason enters the refusal list without the operator being told — structurally", () => {
    /**
     * Review H3, second half. The emission scan above asks only whether a reason NAME appears in a
     * source file, and a bare `refusals.push({ reason })` satisfies that on its own — so a branch
     * that reported a refusal to its IPC caller and told the operator NOTHING would pass it. That
     * is the very defect this unit exists to remove, reachable one branch over.
     *
     * `noteParkRefusal` now writes the notice AND returns the record, so the pairing is structural.
     * This asserts the structure holds: nothing may build a refusal record carrying a park reason
     * except that helper.
     */
    const text = readFileSync(join(SRC, "content-park.ts"), "utf8")
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/^\s*\/\/.*$/gm, "");
    // Positive control: the pushes this is reasoning about must actually be in the file.
    expect(
      (text.match(/refusals\.push\(/g) ?? []).length,
      "no refusals.push( in content-park.ts — this check is reasoning about code that is not there",
    ).toBeGreaterThan(0);

    const offenders = (text.match(/refusals\.push\(\s*\{[^}]*\}/g) ?? []).filter((push) =>
      ALL_PARK_REASONS.some((r) => push.includes(r)) || push.includes("PARK_REFUSAL_REASONS."),
    );
    expect(
      offenders,
      `A park refusal reason is pushed to the drain's refusal list without going through ` +
        `noteParkRefusal, so the IPC caller is told and the OPERATOR is not: ${offenders.join(" | ")}. ` +
        `Push the helper's return value instead — it writes the notice first.`,
    ).toEqual([]);
  });

  it("every park reason has a notice with all three parts filled in", () => {
    // The map is typed total, so this cannot drift — but the test tsconfig is separate, and a
    // runtime check survives someone widening the type to make an error go away.
    for (const reason of ALL_PARK_REASONS) {
      const notice = PARK_REFUSAL_NOTICE[reason]({
        sessionStatus: "abandoned", released: false, declaredAlg: "sha256", saltReason: "none", errorDetail: null,
      });
      expect(notice.kind, `${reason} has no kind`).toBeTruthy();
      expect(notice.impact.length, `${reason} has no impact`).toBeGreaterThan(40);
      expect(notice.guidance.length, `${reason} has no guidance`).toBeGreaterThan(40);
    }
  });

  it("★ NO notice tells an operator to close a conversation that is already closed", () => {
    /**
     * Property 3, and the one that bites. The log's remedy for this loop was *"This message will
     * keep being re-pulled and re-refused until the session is closed, so close it and start a new
     * one"* — printed 731 times about a session closed three days earlier, where closing it is what
     * made the refusal permanent.
     *
     * A remedy whose action the reader has already taken is worse than none: it spends the trust
     * they would have brought to the next notice. The notice knows the status; it must use it.
     */
    const forbidden = /close (it|this|the) (session|conversation)|start a new one|cello_close_session/i;
    for (const status of TERMINAL_SESSION_STATUSES) {
      for (const reason of ALL_PARK_REASONS) {
        for (const released of [true, false]) {
          const { guidance } = PARK_REFUSAL_NOTICE[reason]({
            sessionStatus: status, released, declaredAlg: "hmac-sha256-salt-v1", saltReason: "none", errorDetail: null,
          });
          expect(
            forbidden.test(guidance),
            `${reason} tells an operator to close a session that is already "${status}": ${guidance}`,
          ).toBe(false);
        }
      }
    }
  });
});

describe("DOD-M15-INBOXCAUSE-1: a refusal that LOOPS says so, with its cadence", () => {
  it("★ 731 refusals over 64 hours reads as one loop every 5 minutes, not 731 events", () => {
    // The exact figures from the live daemon. `731` beside nothing is read as 731 things going
    // wrong; the row already held the span that says otherwise and nothing divided by it.
    const r = refusalRecurrence(731, 0, 64 * 3600 * 1000);
    expect(r).toContain("731 times");
    expect(r).toContain("about once every 5 minutes");
    expect(r).toContain("3 days");
    expect(r, "and it must say the count is not a message count").toContain("NOT 731 SEPARATE EVENTS");
  });

  it("claims nothing it cannot support", () => {
    /**
     * Two points are not a cadence, and a zero span would print an interval that is an artifact of
     * the clock rather than of the behaviour. Absent is the honest answer for both — the same rule
     * `timesTotal` follows when there is no durable row.
     */
    expect(refusalRecurrence(2, 0, 60_000), "two refusals cannot establish a rate").toBeNull();
    expect(refusalRecurrence(50, 1000, 1000), "a zero span divides into nonsense").toBeNull();
    expect(refusalRecurrence(50, 2000, 1000), "a negative span is a broken row, not a fast loop").toBeNull();
  });
});

/**
 * ─── The path to `cello_inbox`, driven through a REAL daemon ─────────────────────────────────────
 *
 * The two describes above prove the reasons exist and are emitted. This one proves the last hop:
 * a reason recorded by the drain is READ BACK by the door `cello_check_notifications` uses. Without
 * it, everything above could hold while the notice sat in a store nothing opens — which is the
 * shape of the defect this whole unit is about.
 */
describe("DOD-M15-INBOXCAUSE-1: every park refusal reason has a path to cello_inbox", () => {
  let tempDir: string;
  let handle: DaemonHandle | null;
  let clients: IpcClient[];
  let logger: Logger;

  beforeEach(async () => {
    process.env["CELLO_ENV"] = "test";
    tempDir = await mkdtemp(join(tmpdir(), "cello-inboxcause-"));
    const noop = (): void => {};
    logger = { debug: noop, info: noop, warn: noop, error: noop };
    handle = null;
    clients = [];
  });

  afterEach(async () => {
    for (const c of clients) { try { c.close(); } catch { /* closed */ } }
    if (handle) { try { await handle.stop("test_cleanup"); } catch { /* stopped */ } }
    await rm(tempDir, { recursive: true, force: true });
    delete process.env["CELLO_ENV"];
  });

  async function boot(): Promise<DaemonHandle> {
    await mkdir(join(tempDir, "agents", "alice"), { recursive: true });
    await FileKeyProvider.load(join(tempDir, "agents", "alice", "key"));
    const config: DaemonConfig = {
      securityGateway: new PassthroughGatewayClient(),
      celloDir: tempDir,
      socketPath: join(tempDir, "daemon.sock"),
      lockFilePath: join(tempDir, "daemon.lock"),
      maxConnections: 16,
      version: "0.0.1-test",
      logger,
    };
    handle = await startDaemon(config);
    return handle;
  }

  async function connect(): Promise<IpcClient> {
    const client = await connectToDaemon(join(tempDir, "daemon.sock"));
    clients.push(client);
    await client.send("ipc.connect", { clientType: "mcp" });
    return client;
  }

  type Refusal = {
    session_id: string; reason: string; kind: string; impact: string; guidance: string;
    times_since_dismissed: number; times_total?: number; recurrence?: string;
  };

  async function inboxRefusals(client: IpcClient): Promise<Refusal[]> {
    await client.send("cello_use_agent", { name: "alice" });
    const res = (await client.send("cello_check_notifications", {})) as {
      agents: Array<{ refusals?: Refusal[] }>;
    };
    return res.agents[0]?.refusals ?? [];
  }

  it("★ EVERY declared park reason comes back out of cello_check_notifications", async () => {
    await boot();
    const mgr = handle!.getSessionNodeManager();
    // One session per reason, so the notice store's (session, reason) key cannot hide one behind
    // another and every reason has to survive the read on its own.
    ALL_PARK_REASONS.forEach((reason, i) => {
      mgr.noteContentRefusal(
        "alice",
        `${i.toString(16).padStart(2, "0")}`.repeat(16),
        reason,
        PARK_REFUSAL_NOTICE[reason]({
          sessionStatus: "abandoned", released: false, declaredAlg: "hmac-sha256-salt-v1", saltReason: "none", errorDetail: null,
        }),
      );
    });

    const seen = await inboxRefusals(await connect());

    const missing = ALL_PARK_REASONS.filter((r) => !seen.some((s) => s.reason === r));
    expect(
      missing,
      `Recorded by the drain and NOT readable from cello_inbox: ${missing.join(", ")}. A refusal ` +
        `whose only consumer is the daemon log is not a control — nothing in the running system ` +
        `changes behaviour on it, and the operator concludes their counterparty went quiet.`,
    ).toEqual([]);
    for (const row of seen) {
      expect(row.impact, `${row.reason} arrived with no impact`).toBeTruthy();
      expect(row.guidance, `${row.reason} arrived with no guidance`).toBeTruthy();
    }
  });

  it("★ the annex cause and the ingest exit point arrive SIDE BY SIDE, not one instead of the other", async () => {
    /**
     * The live defect exactly: the operator had `session_committed` and nothing else. Both belong
     * — one says the conversation is closed, the other says why the message cannot leave — and the
     * notice store keys on (session, reason) precisely so the second does not overwrite the first.
     */
    await boot();
    const mgr = handle!.getSessionNodeManager();
    const sid = "dc".repeat(16);
    mgr.noteContentRefusal("alice", sid, "session_committed", {
      kind: "refused", impact: "the conversation is closed", guidance: "there is nothing to repair here",
    });
    mgr.noteContentRefusal("alice", sid, PARK_REFUSAL_REASONS.ANNEX_SALT_UNAVAILABLE,
      PARK_REFUSAL_NOTICE[PARK_REFUSAL_REASONS.ANNEX_SALT_UNAVAILABLE]({
        sessionStatus: "abandoned", released: true, declaredAlg: "hmac-sha256-salt-v1", saltReason: "none", errorDetail: null,
      }));

    const seen = (await inboxRefusals(await connect())).filter((r) => r.session_id === sid);

    expect(seen.map((r) => r.reason).sort()).toEqual(["annex_salt_unavailable", "session_committed"]);
  });

  it("★ a repeated refusal arrives labelled as a LOOP with its cadence", async () => {
    /**
     * Driven through the real notice store rather than the pure function, because the cadence is
     * computed from the lifetime totals row and a function tested alone proves nothing about
     * whether the door reads that row.
     */
    await boot();
    const mgr = handle!.getSessionNodeManager();
    const sid = "ab".repeat(16);
    const notice = PARK_REFUSAL_NOTICE[PARK_REFUSAL_REASONS.ANNEX_SALT_UNAVAILABLE]({
      sessionStatus: "abandoned", released: false, declaredAlg: "hmac-sha256-salt-v1", saltReason: "none", errorDetail: null,
    });
    // Three real refusals five minutes apart, written the way the drain writes them, then the
    // totals row's span widened to the one measured in production. The COUNT stays what the store
    // actually recorded — inventing a total is the misreading DOD-M15-REFUSALTERMINAL-1 removed.
    for (let i = 0; i < 3; i++) mgr.noteContentRefusal("alice", sid, PARK_REFUSAL_REASONS.ANNEX_SALT_UNAVAILABLE, notice);
    const db = mgr.getDb()!;
    const now = Date.now();
    db.prepare(
      "UPDATE content_refusal_totals SET first_at = ?, last_at = ? WHERE session_id = ? AND reason = ?",
    ).run(now - 10 * 60_000, now, sid, PARK_REFUSAL_REASONS.ANNEX_SALT_UNAVAILABLE);

    const row = (await inboxRefusals(await connect())).find((r) => r.session_id === sid)!;

    expect(row.times_total, "three refusals were recorded, so three is what is reported").toBe(3);
    expect(row.recurrence, "a count with no cadence beside it is read as that many separate problems").toBeTruthy();
    expect(row.recurrence).toContain("about once every 5 minutes");
    expect(row.recurrence).toContain("3 times");
  });
});
