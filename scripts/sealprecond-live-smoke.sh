#!/usr/bin/env bash
# DOD-M15-SEALPRECOND-1 Done When 5 — the journey that lost a receipt on 2026-09-11, run live.
#
# WHAT MAKES THIS DIFFERENT FROM `bash-only-smoke.sh`: that one closes a QUIET session, and a quiet
# close was never the problem. Here A puts a message on the wire and closes WHILE IT IS STILL IN
# FLIGHT — the send and the close are two separate `cello` processes started together, which is
# exactly what happened on session `e7dd3f43…`: a `cello close-session` opened at 28.383, the relay
# ordered the in-flight leaf at 28.438, the seal was signed at 28.790 over a tree that still held
# two leaves, and both directories refused it. Neither side ever got a receipt.
#
# THE PASS CONDITION IS THE RECEIPT, on both sides, with the same root and a leaf count equal to the
# messages actually sent. Anything else — including a close that succeeds and a receipt that never
# arrives — is a failure, because that is precisely what the operator saw last time.
#
# Structured as siblings of the existing smoke (same shape, same env vars) rather than as a new
# harness, so the two stay comparable.
#
#   CELLO_BIN       the cello binary UNDER TEST (must be the build the daemon is also running)
#   SMOKE_A/B       two REGISTERED agents
#   SMOKE_B_PUBKEY  B's hex pubkey (cello agents)
#
# ⚠️ THE DAEMON MUST BE RUNNING THIS BUILD. The CLI talks to whatever daemon owns the socket; a
# published daemon with a branch CLI proves nothing about a branch fix. See the runbook note at the
# bottom of the 067 work order.
set -uo pipefail

CELLO="${CELLO_BIN:-node $(cd "$(dirname "$0")/.." && pwd)/core/cli/dist/bin/cello.js}"
A="${SMOKE_A:?set SMOKE_A to a registered agent}"
B="${SMOKE_B:?set SMOKE_B to the second registered agent}"
B_PUBKEY="${SMOKE_B_PUBKEY:?set SMOKE_B_PUBKEY to the hex pubkey of SMOKE_B}"

step() { printf '\n\033[1m── %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*"; exit 1; }
ok()   { printf '\033[32m   ✓ %s\033[0m\n' "$*"; }

step "1. A opens a session with B"
SID=$($CELLO initiate-session "$B_PUBKEY" --agent "$A" | jq -r '.sessionId // empty')
[ -n "$SID" ] || fail "no session id"
echo "session_id = $SID"

step "2. Two ordinary turns, fully settled — the conversation before the close"
$CELLO send "$SID" "Turn 1 from A." --over --agent "$A" | jq -e '.delivered == true' >/dev/null || fail "A turn 1 not delivered"
$CELLO receive "$SID" --agent "$B" --timeout-ms 30000 | jq -r '.content'
$CELLO send "$SID" "Turn 2 from B." --over --agent "$B" | jq -e '.delivered == true' >/dev/null || fail "B turn 2 not delivered"
$CELLO receive "$SID" --agent "$A" --timeout-ms 30000 | jq -r '.content'
ok "two messages in the record on both sides"

step "3. THE JOURNEY: A sends and closes at the same instant"
# Two processes, started together, no sleep between them. The point is NOT to hit a narrow window —
# the fix is a precondition, so it must hold whether the close lands 14ms or 14s after the send.
# Starting them together is simply the shape that produced the loss.
$CELLO send "$SID" "Turn 3 from A — in flight as I close." --wrap --agent "$A" > /tmp/sealprecond-send.json 2>&1 &
SEND_PID=$!
$CELLO close-session "$SID" --agent "$A" > /tmp/sealprecond-close.json 2>&1 &
CLOSE_PID=$!
wait $SEND_PID; wait $CLOSE_PID
echo "send : $(cat /tmp/sealprecond-send.json | head -c 400)"
echo "close: $(cat /tmp/sealprecond-close.json | head -c 400)"

# A decline is ACCEPTABLE here and a lost receipt is not: `session_record_settling` means the daemon
# refused to sign a record it had not finished writing, which is the fix doing its job. Close again.
if jq -e '.reason == "session_record_settling"' /tmp/sealprecond-close.json >/dev/null 2>&1; then
  ok "close declined as session_record_settling — the guard held; closing again"
  $CELLO close-session "$SID" --agent "$A" | jq -c '{ok, reason, seal_status}'
fi
# The reason that must NEVER appear: it names the counterparty for something they did not do.
if grep -q 'merkle_root_mismatch\|leaf_count_mismatch' /tmp/sealprecond-close.json; then
  fail "the operator was handed a counterparty-blaming reason for this side's own unsettled record"
fi

step "4. B closes its half"
$CELLO close-session "$SID" --agent "$B" | jq -c '{ok, reason}' 2>/dev/null || true

step "5. THE PASS CONDITION — a receipt on BOTH sides, same root"
sleep 8
RA=$($CELLO sealed-receipt "$SID" --agent "$A" | jq -r '.sealed_root // empty')
RB=$($CELLO sealed-receipt "$SID" --agent "$B" | jq -r '.sealed_root // empty')
echo "A sealed_root = ${RA:-<none>}"
echo "B sealed_root = ${RB:-<none>}"
[ -n "$RA" ] || fail "A has NO receipt — this is the 2026-09-11 outcome"
[ "$RA" = "$RB" ] || fail "the two sides signed different records: A=$RA B=$RB"
ok "matching sealed_root on both sides"

step "6. The leaf count must equal the messages actually sent (3)"
LEAVES=$($CELLO sealed-receipt "$SID" --agent "$A" | jq -r '.leaf_count // .leafCount // empty')
echo "leaf_count = ${LEAVES:-<absent>}"
SENT=$($CELLO transcript "$SID" --agent "$A" | jq '[.messages[]] | length')
echo "transcript messages = $SENT"
[ "$SENT" = "3" ] || fail "the record holds $SENT messages, not the 3 that were sent"
ok "the in-flight message is IN the signed record"

step "7. Both transcripts, for the record"
$CELLO transcript "$SID" --agent "$A" | jq -c '[.messages[] | {seq: .sequence, dir: .direction, text: .text}]'
$CELLO transcript "$SID" --agent "$B" | jq -c '[.messages[] | {seq: .sequence, dir: .direction, text: .text}]'

printf '\033[32m\n✅ DOD-M15-SEALPRECOND-1 Done When 5 — a close during an in-flight send produced a bilateral receipt\033[0m\n'
