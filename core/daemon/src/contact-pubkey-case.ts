/**
 * A PUBLIC KEY IS BYTES. ITS HEX CASE IS NOT PART OF ITS IDENTITY.
 *
 * ─── The defect, from the operator's chair ─────────────────────────────────────────────────────
 *
 * You paste a counterparty's public key with any uppercase in it — which is what half the tools in
 * the world hand you — and CELLO stored that string verbatim. From then on the address book held a
 * contact you could SEE in `cello_contacts` and that every behavioural read treated as a stranger:
 *
 *  - `getTier` returned UNKNOWN, so the tighter inbound bounds applied;
 *  - `isKnown` was false, so they got the stranger wording;
 *  - a per-contact away message, a pet name, a trust-signal disclosure choice — all set against one
 *    spelling and read against the other, so none of them ever applied;
 *  - and **a key you BLOCKED in one spelling was unblocked in the other**.
 *
 * The fix: every accessor normalizes, so a caller may pass either spelling and always reach one row,
 * and two spellings can never create two rows through the `(agent_id, pubkey)` primary key.
 *
 * ⚠️ **THE WIRE BOUNDARY STILL ACCEPTS EITHER SPELLING, DELIBERATELY.** `invalidPubkey` validates
 * `[0-9a-fA-F]{64}`, and tightening it to lowercase would reject a key the operator pasted correctly
 * from a tool that happens to upper-case. The answer is to accept what they paste and store one form,
 * not to argue with them about capitals.
 */

/**
 * The one spelling every contact-keyed table stores and every accessor compares against.
 *
 * Hex, so lowercase is the conventional form and the one `Buffer.toString("hex")` produces — which
 * matters, because keys arriving from the wire come through that call and keys arriving from an
 * operator's paste do not.
 */
export function normalizeContactPubkey(pubkey: string): string {
  return pubkey.toLowerCase();
}
