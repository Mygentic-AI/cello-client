#!/usr/bin/env bash
# DOD-CURSOR-DURABLE-1 + DOD-CLI-PARITY-1 — the BIDIRECTIONAL bash-only smoke.
#
# The one-way smoke already passed. THIS is the real proof: B's reply is the exact thing the
# per-connection cursor made impossible. Two agents, each SENDING and RECEIVING, each replying to
# what the other actually said, then close + bilateral seal — every step a separate `cello` process
# (so every step is a fresh daemon connection, cursor -1), no MCP anywhere.
set -uo pipefail

# The reusable bash-only live-smoke harness (DOD-CLI-PARITY-1 Phase 3).
#   CELLO_BIN   path to the cello binary (default: this repo's build)
#   SMOKE_A/B   the two REGISTERED agents to converse between
#   SMOKE_B_PUBKEY  B's hex pubkey (see: cello agents)
# Example:
#   SMOKE_A=alice SMOKE_B=bob SMOKE_B_PUBKEY=$(cello agents | jq -r '.agents[]|select(.name=="bob").pubkey') \
#     ./scripts/bash-only-smoke.sh
CELLO="${CELLO_BIN:-node $(cd "$(dirname "$0")/.." && pwd)/core/cli/dist/bin/cello.js}"
A="${SMOKE_A:-Ms_Chelly_Hermes}"
B="${SMOKE_B:-CELLO_Feedback}"
B_PUBKEY="${SMOKE_B_PUBKEY:-da0c73f892648da9c6edae58e2a6b96194bfc27ec3883946fd6d44448253f8b7}"

step() { printf '\n\033[1m── %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*"; exit 1; }
ok()   { printf '\033[32m   ✓ %s\033[0m\n' "$*"; }

step "1. A initiates"
SID=$($CELLO initiate "$B_PUBKEY" --agent "$A" | jq -r '.sessionId // empty')
[ -n "$SID" ] || fail "no session id"
echo "session_id = $SID"

step "2. A → B  (turn 1)"
$CELLO send "$SID" "Turn 1 from A. Can you reply?" --agent "$A" | jq -e '.delivered == true' >/dev/null \
  || fail "A turn-1 send not delivered"
ok "A sent"

GOT=$($CELLO receive "$SID" --agent "$B" --timeout-ms 30000 | jq -r '.content // empty')
[ "$GOT" = "Turn 1 from A. Can you reply?" ] || fail "B did not read A's turn 1 (got: '$GOT')"
ok "B received: $GOT"

step "3. B → A  (turn 2) — THE THING THAT WAS BLOCKED"
# Fresh process, fresh connection, cursor -1. Before DOD-CURSOR-DURABLE-1 this was refused forever
# with session_not_current / last_read_seq:-1, even though B had just read A's message.
REPLY=$($CELLO send "$SID" "Turn 2 from B. Yes — I can reply now." --agent "$B")
echo "$REPLY" | jq -e '.delivered == true' >/dev/null \
  || fail "B'S REPLY WAS REFUSED — the cursor fix did not take: $REPLY"
ok "B REPLIED (this is the fix)"

GOT2=$($CELLO receive "$SID" --agent "$A" --timeout-ms 30000 | jq -r '.content // empty')
[ "$GOT2" = "Turn 2 from B. Yes — I can reply now." ] || fail "A did not read B's reply (got: '$GOT2')"
ok "A received: $GOT2"

step "4. A → B  (turn 3) — a real back-and-forth, not a fluke"
$CELLO send "$SID" "Turn 3 from A. Confirmed two-way over bash." --agent "$A" | jq -e '.delivered == true' >/dev/null \
  || fail "A turn-3 send refused"
ok "A sent turn 3"
GOT3=$($CELLO receive "$SID" --agent "$B" --timeout-ms 30000 | jq -r '.content // empty')
[ -n "$GOT3" ] || fail "B did not read turn 3"
ok "B received: $GOT3"

step "5. B → A  (turn 4)"
$CELLO send "$SID" "Turn 4 from B. Sealing now." --agent "$B" | jq -e '.delivered == true' >/dev/null \
  || fail "B turn-4 send refused"
ok "B sent turn 4"
$CELLO receive "$SID" --agent "$A" --timeout-ms 30000 | jq -r '.content'

step "6. The GUARANTEE still holds: an unread counterparty message still BLOCKS a blind send"
# B speaks; A does NOT read it; A tries to send. Must be refused — the fix is not a bypass.
$CELLO send "$SID" "Turn 5 from B — A has not read this." --agent "$B" >/dev/null
BLIND=$($CELLO send "$SID" "A replying blind" --agent "$A" 2>&1 >/dev/null); RC=$?
echo "exit=$RC stderr=$BLIND"
echo "$BLIND" | jq -e '.reason == "session_not_current"' >/dev/null \
  && ok "REFUSED as it must be — unread counterparty content still blocks" \
  || fail "SECURITY REGRESSION: a blind send was ALLOWED"
# A reads it, and is then allowed.
$CELLO receive "$SID" --agent "$A" --timeout-ms 30000 >/dev/null
$CELLO send "$SID" "A caught up, now replying." --agent "$A" | jq -e '.delivered == true' >/dev/null \
  && ok "after reading, A may send again"

step "7. CLOSE → bilateral seal"
$CELLO close "$SID" --agent "$A" | jq -c '{ok, sealed_root}'
$CELLO close "$SID" --agent "$B" | jq -c '{ok, reason}' 2>/dev/null || true

step "8. The notarized receipt, from BOTH sides"
sleep 5
RA=$($CELLO sealed-receipt "$SID" --agent "$A" | jq -r '.sealed_root // empty')
RB=$($CELLO sealed-receipt "$SID" --agent "$B" | jq -r '.sealed_root // empty')
echo "A sealed_root = ${RA:-<none>}"
echo "B sealed_root = ${RB:-<none>}"
if [ -n "$RA" ] && [ "$RA" = "$RB" ]; then
  printf '\033[32m\n✅ BIDIRECTIONAL bash-only conversation + matching seal — DOD-CURSOR-DURABLE-1 PROVEN\033[0m\n'
else
  fail "sealed roots missing or mismatched"
fi

step "9. Full transcript (both directions), from bash"
$CELLO transcript "$SID" --agent "$A" | jq -c '[.messages[] | {seq: .sequence, dir: .direction, text: .text}]'
