# Transport Path Runbook — REPOSPLIT-001 AC-007

This document covers manual verification steps for AC-007 (WebSocket transport
path through ALB) that cannot be automated in the unit/integration test suite.

---

## AC-007 dimension 2 — CloudWatch log verification

The automated test (`transport-path.test.ts`) proves that:
- The circuit relay reservation succeeds within 10 seconds
- A second client can reach the first via the relayed path

What the test **cannot** verify automatically is that the relay emits the
`relay.message.forwarded` log event in CloudWatch within 10 seconds of
forwarding traffic. This requires manual inspection after deploying to a live
environment.

### How to verify

After running the transport-path test against the live ALB, check CloudWatch
within 10 seconds:

```bash
aws logs filter-log-events \
  --log-group-name /ecs/cello-relay-dev \
  --region us-east-1 \
  --start-time $(date -d '-30 seconds' +%s000) \
  --filter-pattern '"relay.message.forwarded"'
```

On macOS (BSD date):

```bash
aws logs filter-log-events \
  --log-group-name /ecs/cello-relay-dev \
  --region us-east-1 \
  --start-time $(( $(date +%s) - 30 ))000 \
  --filter-pattern '"relay.message.forwarded"'
```

Or use the AWS console: CloudWatch → Log groups → `/ecs/cello-relay-dev` →
Search for `relay.message.forwarded` with a time window of the last 1 minute.

### Post-deploy checklist for AC-007 dimension 2

- [ ] Run the transport-path test against the live ALB
- [ ] Within 10 seconds, verify `relay.message.forwarded` appears in CloudWatch
- [ ] Confirm the log event contains `{ peerId, circuitPeerId, correlationId }`

---

## AC-007 dimension 3 — Idle timeout test

The idle timeout test verifies that a WebSocket connection survives 5 minutes
of idle without the ALB dropping it (requires `IdleTimeout: 300` in the
`cello-ecs-directory.yaml` CloudFormation template).

This test is **skipped by default** even when `CELLO_DIR_ALB` is set because
it takes ~5.5 minutes to run.

### When to run

- Before every ALB configuration change that touches `IdleTimeout`
- Before any REPOSPLIT-002 merge that depends on long-lived WebSocket sessions
- When debugging unexpected client disconnections

### How to run

```bash
CELLO_DIR_ALB=cello-dir-dev-1136016900.us-east-1.elb.amazonaws.com \
CELLO_DIR_PUBKEY=167ca6b145bfdd3696af8f4befd883c3dc610f4a9c8d52a30f6a22f669dc27b5 \
IDLE_TIMEOUT_TEST=true \
pnpm --filter @cello-protocol/e2e-tests run test -- transport-path \
  --pool-options.threads.maxThreads=1 --pool-options.threads.minThreads=1
```

Expected duration: ~5.5 minutes. The test waits 5 minutes 30 seconds of idle
before asserting the connection is still alive.

---

## REPOSPLIT-002 reminders

- **Add `bin` entry to `core/adapter-claude-code/package.json`** before the
  real publish. The entry was removed in REPOSPLIT-001 because `dist/bin/cello-mcp.js`
  does not exist in the scaffold. REPOSPLIT-002 must add it back when the binary
  is present:
  ```json
  "bin": {
    "cello-mcp": "./dist/bin/cello-mcp.js"
  }
  ```

- **Add `eslint` devDependency** to the root `package.json` if a lint script
  is needed. The lint script was removed in REPOSPLIT-001 (no source yet to
  lint). REPOSPLIT-002 should add eslint when real TypeScript source files
  are present.
