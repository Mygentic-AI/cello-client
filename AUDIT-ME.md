# AUDIT-ME — CELLO Client Privacy Claims

This document makes three verifiable claims about the privacy properties of the
CELLO client. Each claim names specific source files that an investigator can
read to verify the claim. File paths are relative to the cello-client repository
root. All paths listed are valid — packages were extracted from trustless-cello
into cello-client by REPOSPLIT-002.

---

## Claim 1 — The relay never sees message content in plaintext

**Summary:** All libp2p connections are encrypted using the Noise XX handshake
before any application data is sent. Message content is additionally encrypted
at the application layer (AES-GCM envelope). The relay node receives only
encrypted bytes and assigns sequence numbers to them — it never holds a key
that could decrypt content.

**How to verify:**

The Noise XX handshake setup is in:
- `core/transport/src/node.ts` — `createNode()` function; shows
  `connectionEncrypters: [noise()]` as the only allowed connection encrypter
  with no plaintext fallback; TCP and WebSocket transports always go through
  the Noise encrypter — there is no unencrypted transport path
- `core/transport/src/types.ts` — transport type definitions; Noise is
  the only declared connection encrypter type

Circuit relay fallback (when direct connection fails):
- `core/transport/src/node.ts` — `circuitRelayTransport()` and
  `circuitRelayServer()` configuration; circuit-relayed connections also
  go through Noise XX — the relay forwards encrypted blobs, not plaintext

Backup encryption (SQLCipher database export):
- `core/client/src/client-backup.ts` — AES-256-GCM envelope encryption
  for encrypted database backups (PERSIST-011)

**Verify:**
1. `core/transport/src/node.ts` — `createNode()` shows `connectionEncrypters: [noise()]`
   and no `plaintext()` import; no unencrypted transport path
2. `core/transport/src/node.ts` — circuit relay transport configuration;
   relay handles opaque encrypted streams
3. `core/client/src/client-backup.ts` — AES-256-GCM encryption with
   fresh random 96-bit nonce per backup; backup key derived via HKDF
4. `core/transport/src/types.ts` — transport type definitions; only
   Noise is the declared connection encrypter

---

## Claim 2 — K_local never leaves the client process

**Summary:** K_local (the agent's operational Ed25519 signing key) is stored
and used exclusively inside the client process. It is loaded from a local key
file at startup and never serialized to the network. The key file path defaults
to `~/.cello/key` and is readable only by the process owner (mode 0o600).
K_local and the libp2p transport key are distinct keypairs — K_local is never
used as a libp2p Peer ID, and it is never sent in plaintext in any protocol
frame (ADR-0001).

**How to verify:**

Key generation and storage:
- `core/crypto/src/ed25519.ts` — `FileKeyProvider.load()` reads the key
  from a local file; `FileKeyProvider.generate()` creates a new key and writes
  it with `chmod 600` (mode 0o600); `sign()` and `getPublicKey()` operate in
  memory; no network calls

FROST threshold ceremony (DKG):
- `core/client/src/client.ts` — only public commitments and signature
  shares (never the private key scalar) are sent over the network during the
  DKG ceremony; K_local is the private input, threshold signature shares are
  the outputs; grep `#registerFrost` for the DKG flow

Wire frame inspection:
- `core/protocol-types/src/envelope.ts` — all serialized frames carry public
  keys (`sender_pubkey`, `signer_pubkey`) and signatures — never private key
  material
- `core/client/src/client.ts` — `buildEnvelope()` call; input is the message
  bytes and sender_pubkey; private key stays inside the `KeyProvider.sign()` closure

**Verify:**
1. `core/crypto/src/ed25519.ts` — `FileKeyProvider` class; `sign()` returns a
   signature, never the private scalar; key file read with `readFile` at path
2. `core/client/src/client.ts` — DKG messages: public commitments and signature
   shares, not private scalars; grep `dkg_round1`, `dkg_round2`, `dkg_ready`
3. `core/protocol-types/src/envelope.ts` — envelope type definition; grep for
   private key field names (`privateKey`, `privKey`, `secret`) — none present
4. `core/transport/src/node.ts` — `createNode()` generates a *separate*
   libp2p transport keypair; K_local from `keyProvider` is stored but never
   passed to libp2p's Noise handshake (ADR-0001 invariant)

---

## Claim 3 — No telemetry, analytics, or phone-home behavior

**Summary:** The CELLO client makes outbound network connections only to the
directory node (for registration, session establishment signaling, and FROST
ceremonies) and to relay nodes (for message routing). There are no telemetry
endpoints, analytics beacons, error reporting services, or any other outbound
HTTP calls.

**How to verify:**

All outbound network calls flow through libp2p streams to known peers:
- `core/transport/src/node.ts` — only libp2p transports are registered (TCP,
  WebSocket, circuit relay); no `fetch()`, `http.request()`, or SDK clients
  for analytics services
- `core/client/src/client.ts` — all external calls are `node.dial()`
  to the directory multiaddr or relay multiaddr passed in at construction time;
  caller controls both addresses; grep `dial(` for every outbound connection
- `core/adapter-claude-code/src/server.ts` — MCP server entry point; registers
  tool handlers that call into the client; no additional outbound network calls

There are no imports of telemetry SDKs (Sentry, Datadog, Segment, Mixpanel,
PostHog, OpenTelemetry exporter) anywhere in the codebase:

**Verify:**
1. `core/transport/src/node.ts` — grep for `fetch`, `http.request`,
   `https.request` — none present
2. `core/client/src/client.ts` — all outbound calls are `dial()` to
   the directory/relay addresses provided at construction time
3. `core/adapter-claude-code/src/server.ts` — no analytics or telemetry
   client imported; only `@modelcontextprotocol/sdk` and cello packages
4. Root `package.json` and all `core/*/package.json` — grep for telemetry
   package names (sentry, datadog, segment, mixpanel, posthog, opentelemetry)
   — none present

---

## Verification instructions

To verify all three claims after REPOSPLIT-002 extracts the packages:

```bash
# Check no plaintext transport
grep -r "plaintext" core/transport/src/  # should find nothing

# Check K_local never on the wire
grep -r "privateKey\|privKey\|keyMaterial" core/client/src/frames.ts  # should find nothing

# Check no telemetry packages
grep -r "sentry\|datadog\|segment\|mixpanel\|posthog" core/*/package.json  # should find nothing

# Check no unexpected outbound HTTP
grep -rn "fetch\|http\.request\|https\.request" core/*/src/  # should show only directory/relay calls
```

---

*File paths reference the cello-client layout (core/crypto, core/transport,
core/client, core/adapter-claude-code) and are valid as of REPOSPLIT-002.*
