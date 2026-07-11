/**
 * DOD-ONBOARD-HELP-1 (reopened 2026-07-11) — the help must be REAL help.
 *
 * The table STRUCTURE shipped in cli 0.0.45 and Andre reopened the line anyway: it rendered, but
 * `register` sat above `create-agent` (step 2 above step 1), `install` read as "install CELLO
 * itself", `receipts` and `sealed-receipt` were indistinguishable, and several descriptions were
 * internal jargon. "Renders" was never the bar. These tests encode the actual bar.
 */

import { describe, it, expect } from "vitest";
import { DUAL_SURFACE_VERBS } from "@cello-protocol/daemon";
import { COMMANDS, GROUP_ORDER, commandNames, findCommand, renderCommandsTable } from "../registry.js";
import { USAGE } from "../cli-args.js";

describe("§1 — the help is grouped and logically ordered", () => {
  it("renders a section per group, in GROUP_ORDER", () => {
    const table = renderCommandsTable();
    const positions = GROUP_ORDER.map((g) => table.indexOf(`${g}:`));
    for (const p of positions) expect(p).toBeGreaterThanOrEqual(0);
    // Strictly increasing → the sections appear in the declared order.
    expect(positions).toEqual([...positions].sort((a, b) => a - b));
  });

  it("puts create-agent BEFORE register-agent — step 1 above step 2 (the reopen)", () => {
    const table = renderCommandsTable();
    expect(table.indexOf("create-agent")).toBeLessThan(table.indexOf("register-agent"));
  });

  it("clusters the session-lifecycle verbs, then the bare message verbs, then inbox", () => {
    const messaging = COMMANDS.filter((c) => c.group === "Messaging").map((c) => c.name);
    expect(messaging).toEqual([
      "initiate-session",
      "await-session",
      "close-session",
      "send",
      "receive",
      "inbox",
    ]);
  });

  it("every command declares a group — so a new command cannot be invisible in the help", () => {
    for (const c of COMMANDS) {
      expect(GROUP_ORDER, `${c.name} has an unknown group '${c.group}'`).toContain(c.group);
    }
  });

  it("every command appears in the rendered table exactly once", () => {
    const table = renderCommandsTable();
    for (const name of commandNames()) {
      const rows = table.split("\n").filter((l) => l.startsWith(`  ${name} `) || l.trim() === name);
      expect(rows.length, `${name} should appear once as a row`).toBe(1);
    }
  });
});

describe("§2 — the renames are CLEAN (old names gone, no aliases)", () => {
  it("the new names exist", () => {
    for (const n of ["bridge", "register-agent", "close-session", "initiate-session", "contacts", "contact", "relay-receipts"]) {
      expect(findCommand(n), `${n} missing`).toBeDefined();
    }
  });

  it("the OLD names are GONE — not aliased, not deprecated. Deleted.", () => {
    // One user, no install base: an alias would be permanent debt bought for nobody.
    for (const old of ["install", "register", "close", "initiate", "receipts", "receive-session"]) {
      expect(findCommand(old), `'${old}' must be deleted, not kept as an alias`).toBeUndefined();
    }
  });

  it("the onboarding line in USAGE points at register-agent — a half-rename is a broken rename", () => {
    // The exact trap the work order named: rename the command, leave the first-run string telling a
    // brand-new user to run a verb that no longer exists.
    expect(USAGE).toContain("cello register-agent <name> <token>");
    expect(USAGE).not.toMatch(/cello register </);
  });

  it("bridge does not hardcode Hermes in its summary — the runtime is a PARAMETER", () => {
    const bridge = findCommand("bridge")!;
    expect(bridge.summary).toContain("third-party agent runtime");
    expect(bridge.summary).toContain("…"); // more runtimes coming; don't claim done
  });
});

describe("§2b — CLI ↔ MCP name parity: one capability, one name", () => {
  it("every dual-surface capability's CLI name is a real command", () => {
    for (const { mcp, cli } of DUAL_SURFACE_VERBS) {
      // "cello contact <pubkey> set-tier" → the command is `contact`.
      const command = cli.split(/\s+/)[1];
      expect(findCommand(command), `${mcp} claims CLI command '${command}', which does not exist`).toBeDefined();
    }
  });

  it("the parity commands' ipcMethod is the daemon's real handler name", () => {
    // Cheap, but it is the claim DOD-CLI-PARITY-1 rests on: the CLI calls the SAME handler as the
    // tool. If this drifts, "parity" is a word in a doc rather than a property of the binary.
    expect(findCommand("send")!.ipcMethod).toBe("cello_send");
    expect(findCommand("close-session")!.ipcMethod).toBe("cello_close_session");
    expect(findCommand("initiate-session")!.ipcMethod).toBe("cello_initiate_session");
    expect(findCommand("contacts")!.ipcMethod).toBe("cello_contact_list"); // wire name unchanged
  });
});

describe("§4 — the wording is accurate and jargon-free", () => {
  const summaries = COMMANDS.map((c) => `${c.name}: ${c.summary}`).join("\n");

  it("no internal jargon leaks into the command table", () => {
    // These are OUR words, not a user's. They were the reopen: a description written for the person
    // who implemented it is not help, it is a reminder.
    for (const jargon of ["watermark", "epoch rollover", "read-before-write", "push-loss", "reconciler", "cursor"]) {
      expect(summaries.toLowerCase(), `'${jargon}' is internal jargon`).not.toContain(jargon);
    }
  });

  it("relay-receipts and sealed-receipt are unmistakably different", () => {
    const relay = findCommand("relay-receipts")!;
    const sealed = findCommand("sealed-receipt")!;
    // Andre could not tell them apart, and he designed the protocol. The NAME must carry it...
    expect(relay.name).not.toBe("receipts");
    // ...the summary must say which one you want...
    expect(relay.summary.toLowerCase()).toContain("advanced");
    expect(relay.summary).toContain("sealed-receipt"); // points at the one you probably wanted
    expect(sealed.summary.toLowerCase()).toContain("notarized");
    // ...and each help must disown the other explicitly.
    expect(relay.help).toContain("sealed-receipt");
    expect(sealed.help).toContain("relay-receipts");
  });

  it("send explains the block in plain words rather than naming the rule", () => {
    const send = findCommand("send")!;
    expect(send.summary.toLowerCase()).toContain("unread");
    expect(send.summary.toLowerCase()).toContain("blocked");
  });

  it("refresh describes the ceremony truthfully, incl. the directory precondition", () => {
    // VERIFIED against cello_refresh_shares → runAgentRefresh before this was written.
    const refresh = findCommand("refresh")!;
    expect(refresh.summary.toLowerCase()).toContain("rotate");
    expect(refresh.help.toLowerCase()).toContain("directory to be reachable");
    expect(refresh.help.toLowerCase()).toContain("does not change"); // public identity is stable
  });

  it("telegram does not over-claim — 'etc.' is deliberate", () => {
    expect(findCommand("telegram")!.summary.toLowerCase()).toContain("notifications");
  });
});

describe("§3 — the contacts split", () => {
  it("'contacts' is the book; 'contact' acts on ONE contact", () => {
    expect(findCommand("contacts")!.summary.toLowerCase()).toContain("address book");
    expect(findCommand("contact")!.summary.toLowerCase()).toContain("one contact");
  });

  it("the per-contact shape is `contact <pubkey> <op>` — subject first", () => {
    expect(findCommand("contact")!.help).toContain("cello contact <pubkey> <operation>");
  });
});
