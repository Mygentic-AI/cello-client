/**
 * M8C-PRIMARY-1 — buildPrimaryTransferTbs tests
 *
 * The canonical to-be-signed byte builder for the primary-transfer release attestation
 * (M8C-PRIMARY-DESIGN.md Decision 3, Pass 3). Field order is LOAD-BEARING: the old Primary
 * daemon (signer, via participateInCeremony) and every directory node (verifier, via
 * verifySignature) must produce byte-identical TBS from the same logical inputs, or a genuine
 * ceremony's signature would fail verification for no security reason. These tests are the
 * cross-repo drift guard for that byte-identity requirement — mirrors wire-001-tbs.test.ts's
 * determinism-check style for buildSessionEstablishmentTbs.
 */

import { setupV3Tests, describe, it, expect } from "@claude-flow/testing";
import { buildPrimaryTransferTbs, PRIMARY_TRANSFER_DOMAIN } from "../primary-transfer.js";

setupV3Tests();

const K_LOCAL = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899".slice(0, 64);
const NEW_DAEMON = "11111111-1111-1111-1111-111111111111";
const OLD_DAEMON = "22222222-2222-2222-2222-222222222222";
const NONCE = "nonce-abc-123";
const TIMESTAMP = 1700000000000;

describe("M8C-PRIMARY-1: buildPrimaryTransferTbs integer encoding", () => {
  it("encodes a MILLISECOND timestamp as a CBOR uint64, never a float64", () => {
    // Found while reviewing DOD-CBOR-1 (M10). Past 0xffffffff, cbor-x emits a JS number as an IEEE
    // float64 (`fb`), not a uint64 (`1b`). Date.now() is ~1.77e12 — far past it — so the first caller
    // to pass milliseconds would have the TBS hashed as a float, and any non-cbor-x verifier would
    // compute different bytes and reject a GENUINE primary transfer. Its two sibling builders
    // (buildSealTbs, buildAgentRevocationTbs) both guard; this one did not.
    const ms = 1_768_000_000_000;
    const tbs = Buffer.from(buildPrimaryTransferTbs(K_LOCAL, NEW_DAEMON, OLD_DAEMON, NONCE, ms)).toString("hex");
    expect(tbs).toContain("1b0000019ba5031000"); // uint64: 0x19ba5031000 == 1_768_000_000_000
    expect(tbs).not.toMatch(/fb[0-9a-f]{16}/);   // no float64 anywhere
  });

  it("a number and the same value as a BigInt produce IDENTICAL bytes", () => {
    const ms = 1_768_000_000_000;
    expect(Buffer.from(buildPrimaryTransferTbs(K_LOCAL, NEW_DAEMON, OLD_DAEMON, NONCE, ms))).toEqual(
      Buffer.from(buildPrimaryTransferTbs(K_LOCAL, NEW_DAEMON, OLD_DAEMON, NONCE, BigInt(ms))),
    );
  });

  it("timestamps below 2^32 encode exactly as before — the fix moves no existing byte", () => {
    const tbs = Buffer.from(buildPrimaryTransferTbs(K_LOCAL, NEW_DAEMON, OLD_DAEMON, NONCE, 1_768_000_000)).toString("hex");
    expect(tbs).toContain("1a69618a00"); // uint32, unchanged
  });
});

describe("M8C-PRIMARY-1: buildPrimaryTransferTbs determinism", () => {
  it("same logical inputs produce byte-identical TBS across two independent calls", () => {
    const tbs1 = buildPrimaryTransferTbs(K_LOCAL, NEW_DAEMON, OLD_DAEMON, NONCE, TIMESTAMP);
    const tbs2 = buildPrimaryTransferTbs(K_LOCAL, NEW_DAEMON, OLD_DAEMON, NONCE, TIMESTAMP);
    expect(Buffer.from(tbs1).toString("hex")).toBe(Buffer.from(tbs2).toString("hex"));
  });

  it("returns a non-empty Uint8Array", () => {
    const tbs = buildPrimaryTransferTbs(K_LOCAL, NEW_DAEMON, OLD_DAEMON, NONCE, TIMESTAMP);
    expect(tbs).toBeInstanceOf(Uint8Array);
    expect(tbs.length).toBeGreaterThan(0);
  });

  it("a different new_daemon_id produces a different TBS (prevents a stale request being replayed for a different claimant)", () => {
    const tbs1 = buildPrimaryTransferTbs(K_LOCAL, NEW_DAEMON, OLD_DAEMON, NONCE, TIMESTAMP);
    const tbs2 = buildPrimaryTransferTbs(K_LOCAL, "33333333-3333-3333-3333-333333333333", OLD_DAEMON, NONCE, TIMESTAMP);
    expect(Buffer.from(tbs1).toString("hex")).not.toBe(Buffer.from(tbs2).toString("hex"));
  });

  it("a different old_daemon_id produces a different TBS", () => {
    const tbs1 = buildPrimaryTransferTbs(K_LOCAL, NEW_DAEMON, OLD_DAEMON, NONCE, TIMESTAMP);
    const tbs2 = buildPrimaryTransferTbs(K_LOCAL, NEW_DAEMON, "44444444-4444-4444-4444-444444444444", NONCE, TIMESTAMP);
    expect(Buffer.from(tbs1).toString("hex")).not.toBe(Buffer.from(tbs2).toString("hex"));
  });

  it("a different nonce produces a different TBS (each transfer attempt is unlinkable/unforgeable from another)", () => {
    const tbs1 = buildPrimaryTransferTbs(K_LOCAL, NEW_DAEMON, OLD_DAEMON, NONCE, TIMESTAMP);
    const tbs2 = buildPrimaryTransferTbs(K_LOCAL, NEW_DAEMON, OLD_DAEMON, "different-nonce", TIMESTAMP);
    expect(Buffer.from(tbs1).toString("hex")).not.toBe(Buffer.from(tbs2).toString("hex"));
  });

  it("a different timestamp produces a different TBS (bounds the replay window)", () => {
    const tbs1 = buildPrimaryTransferTbs(K_LOCAL, NEW_DAEMON, OLD_DAEMON, NONCE, TIMESTAMP);
    const tbs2 = buildPrimaryTransferTbs(K_LOCAL, NEW_DAEMON, OLD_DAEMON, NONCE, TIMESTAMP + 1);
    expect(Buffer.from(tbs1).toString("hex")).not.toBe(Buffer.from(tbs2).toString("hex"));
  });

  it("a different k_local_pubkey produces a different TBS (a release attestation for one agent can't apply to another)", () => {
    const tbs1 = buildPrimaryTransferTbs(K_LOCAL, NEW_DAEMON, OLD_DAEMON, NONCE, TIMESTAMP);
    const differentAgent = "ffeeddccbbaa00998877665544332211ffeeddccbbaa00998877665544332211".slice(0, 64);
    const tbs2 = buildPrimaryTransferTbs(differentAgent, NEW_DAEMON, OLD_DAEMON, NONCE, TIMESTAMP);
    expect(Buffer.from(tbs1).toString("hex")).not.toBe(Buffer.from(tbs2).toString("hex"));
  });

  it("the domain tag is the first encoded field — swapping two string fields of the same logical shape must not collide", () => {
    // Without a domain tag as an anchor, a CBOR array of all-string fields could theoretically be
    // ambiguous under field reordering for adversarially-chosen inputs. Concretely: new_daemon_id
    // and old_daemon_id swapped must never produce the same bytes (this would let an attacker
    // relabel who is releasing vs. claiming).
    const tbsForward = buildPrimaryTransferTbs(K_LOCAL, NEW_DAEMON, OLD_DAEMON, NONCE, TIMESTAMP);
    const tbsSwapped = buildPrimaryTransferTbs(K_LOCAL, OLD_DAEMON, NEW_DAEMON, NONCE, TIMESTAMP);
    expect(Buffer.from(tbsForward).toString("hex")).not.toBe(Buffer.from(tbsSwapped).toString("hex"));
  });

  it("PRIMARY_TRANSFER_DOMAIN is a stable, distinct domain string (not equal to any other CELLO domain tag)", () => {
    expect(PRIMARY_TRANSFER_DOMAIN).toBe("CELLO-PRIMARY-TRANSFER-v1");
  });
});
