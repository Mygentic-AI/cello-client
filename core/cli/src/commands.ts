/**
 * CLI command implementations for the `cello` binary.
 */

import { join } from "node:path";
import {
  connectOrStart,
  connectToDaemon,
  readLock,
  removeLock,
  // isProcessAlive may NEVER answer "does a daemon exist?" — a pid can be dead, or reused by an
  // unrelated process. The kernel's lock is the only thing that knows that, and every EXISTENCE
  // decision in this file still goes through probeSingletonLock.
  //
  // DOD-LOGOUT-EXIT-1 imports it for the one question it CAN answer: "is this specific pid, which
  // was alive when I told it to stop, gone yet?" That is a non-existence check layered ON TOP of
  // the lock, never instead of it, and being wrong fails safe (logout reports "did not complete"
  // instead of claiming a stop that did not happen). See `daemonGone`.
  isProcessAlive,
  probeSingletonLock,
  SINGLETON_LOCK_FILENAME,
  type DaemonStatusResponse,
  type IpcClient,
  type Logger,
} from "@cello-protocol/daemon";

/**
 * Open an IPC connection, run `fn`, and ALWAYS close it.
 *
 * The close belongs in a `finally`, never after the send. The daemon enforces IPC_CONNECTION_LIMIT,
 * so a connection is a BOUNDED resource: a `client.close()` written after `client.send()` inside a
 * try is SKIPPED on any throw, and each failed command leaks a socket the daemon never reclaims.
 * Leak enough and it refuses new connections — a failure whose symptom looks nothing like its cause.
 *
 * Every single-call command goes through this. The three that cannot are `login` (the connection is
 * created by connectOrStart and handed to us), `logout` (it must outlive the send to poll for death),
 * and `daemonGone` (it races the connect against a timeout). Each closes in a `finally` or reaps the
 * abandoned promise explicitly — see them. Any NEW command that reaches for connectToDaemon directly
 * is reintroducing the leak.
 */
async function withIpc<T>(socketPath: string, fn: (client: IpcClient) => Promise<T>): Promise<T> {
  const client = await connectToDaemon(socketPath);
  try {
    return await fn(client);
  } finally {
    client.close();
  }
}

/**
 * M8C-LOGINSTART-1 CORE: bring every loaded agent online. Called by `cello login` after the daemon
 * is up. login ALWAYS completes — a per-agent start failure is COLLECTED, never thrown, so one bad
 * agent can't abort login. `cello_start_agent` is idempotent, so re-login is safe. The per-agent
 * `autoStart: false` opt-out is PARKED until the M9 config store lands (D14).
 * Lives here rather than inline in login() so it is unit-testable against an in-process daemon.
 */
export async function autoStartAllAgents(
  client: IpcClient,
): Promise<{ started: string[]; failed: Array<{ name: string; reason: string }> }> {
  const started: string[] = [];
  const failed: Array<{ name: string; reason: string }> = [];
  const listRes = (await client.send("cello_list_agents")) as { agents?: Array<{ name: string }> };
  for (const a of listRes.agents ?? []) {
    try {
      const r = (await client.send("cello_start_agent", { name: a.name })) as { ok?: boolean; reason?: string };
      if (r.ok) started.push(a.name);
      else failed.push({ name: a.name, reason: r.reason ?? "unknown" });
    } catch (err: unknown) {
      failed.push({ name: a.name, reason: err instanceof Error ? err.message : String(err) });
    }
  }
  return { started, failed };
}

export interface CommandResult {
  exitCode: number;
  /**
   * STDOUT. For a command whose help promises JSON, this must be JSON and NOTHING ELSE — see
   * `guidance` below for why that had to be written down.
   */
  output: string;
  /**
   * STDERR — guidance for a human, kept OUT of the data stream.
   *
   * DOD-M15-CLIJSON-1: `register-agent` used to append its "Next: run cello status…" hint to
   * `output`, after the JSON. It exits 0, the registration succeeds, and every consumer that parses
   * the output dies on the trailing prose — with a parse error naming a byte offset, so it reads as
   * "registration is broken" when registration is fine. Five end-to-end journeys died at their first
   * line on it.
   *
   * The hint is worth keeping: it is what tells a new operator that registration is asynchronous and
   * may take a minute. It just belongs on stderr, which is what stderr is for. A human sees both
   * streams in a terminal and loses nothing; a script sees clean JSON.
   */
  guidance?: string;
}

export async function login(
  celloDir: string,
  daemonBin: string,
  logger: Logger,
): Promise<CommandResult> {
  try {
    const result = await connectOrStart(celloDir, logger, daemonBin);
    // M8C-LOGINSTART-1: bring every registered agent online, then report. Never let this abort login.
    const head = result.alreadyRunning ? "Daemon already running." : "Daemon started.";
    let summary: string;
    try {
      await result.client.send("ipc.connect", { clientType: "cli" });
      summary = formatLoginSummary(await autoStartAllAgents(result.client));
    } catch (err: unknown) {
      // Auto-start is best-effort — the daemon IS up. Surface the reason but complete login (exit 0).
      summary = `Agents were not auto-started (${err instanceof Error ? err.message : String(err)}); run 'cello status' and start them with cello_use_agent.`;
    } finally {
      result.client.close();
    }
    return { exitCode: 0, output: `${head}\n${summary}` };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { exitCode: 1, output: `Failed to start daemon: ${message}` };
  }
}

/**
 * M8C-LOGINSTART-1: compose the operator-facing auto-start summary — every failed agent enumerated
 * by name + reason. Pure + exported so the enumeration string is directly testable.
 */
export function formatLoginSummary(result: { started: string[]; failed: Array<{ name: string; reason: string }> }): string {
  const parts: string[] = [];
  if (result.started.length > 0) parts.push(`Started ${result.started.length} agent(s): ${result.started.join(", ")}.`);
  if (result.failed.length > 0) {
    parts.push(
      `${result.failed.length} agent(s) failed to start: ${result.failed.map((f) => `${f.name} (${f.reason})`).join(", ")}. ` +
      "Run 'cello status' to check; a failed agent stays offline and can be retried with cello_use_agent.",
    );
  }
  if (result.started.length === 0 && result.failed.length === 0) parts.push("No registered agents to start.");
  return parts.join("\n");
}

// DOD-LOGOUT-WAIT-1: how long logout waits for the daemon to actually die after acknowledging
// the shutdown request, and how often it re-checks. A daemon closing SQLCipher + libp2p takes
// real time; 5 s is generous headroom, and a daemon still alive past it is genuinely stuck.
const LOGOUT_WAIT_TIMEOUT_MS = 5_000;
const LOGOUT_WAIT_POLL_MS = 50;

/**
 * DOD-LOGOUT-WAIT-1: is the daemon actually GONE — judged by the same evidence `connectOrStart`
 * consults, so a completed logout GUARANTEES the next login starts fresh.
 *
 * Two facts, both required, neither of them a file:
 *  1. nothing answers on the socket, and
 *  2. no process holds the singleton lock.
 *
 * (1) alone is not enough: a daemon wedged mid-shutdown may have closed its IPC server while still
 * holding the DB. (2) alone is not enough either, because a pre-singleton-lock daemon holds no
 * singleton lock at all — for those, "free" says nothing about whether it is alive, and only the
 * socket can tell us. Together they are exactly the conditions under which the next daemon can
 * safely start.
 *
 * Neither `isProcessAlive(lock.pid)` nor the lock FILE may be SUBSTITUTED for these two facts: a pid
 * can be reused, and a lock file can be deleted by anyone.
 *
 * DOD-LOGOUT-EXIT-1 adds a THIRD, and the distinction from the paragraph above is the whole point:
 * `livePid` is an ADDITIONAL requirement, never a substitute. Both facts above are released inside
 * `stop()`'s `finally`, BEFORE the daemon actually ends — that gap is precisely how logout came to
 * report "Daemon stopped." over a process still holding a directory connection. So when we know a
 * pid that was alive at the moment we asked it to stop, it must also be gone.
 *
 * The pid-reuse objection does not apply to this use: the window is the 5 s logout wait, and being
 * wrong here fails SAFE — an unrelated process inheriting the pid makes logout report "did not
 * complete" (exit 1, loud, actionable) rather than claim a stop that did not happen.
 */
async function daemonGone(
  celloDir: string,
  socketPath: string,
  logger: Logger,
  livePid?: number,
): Promise<boolean> {
  // Checked FIRST — it is the cheapest, and it is the only one of the three that is about the
  // process rather than about a handle the process has already let go of.
  if (livePid !== undefined && isProcessAlive(livePid)) return false;

  // connectToDaemon has no connect timeout of its own — bound the probe so a pathological hang
  // cannot stall the poll loop past its deadline. On the expected path the socket is already gone,
  // so this fails fast (ENOENT/ECONNREFUSED).
  //
  // The race LOSER must still be closed. If the timeout wins, the connect promise is abandoned — but
  // it can still resolve afterwards into a live IpcClient that nobody holds and nobody closes. This
  // runs in a POLL LOOP inside one process, against the daemon's bounded IPC_CONNECTION_LIMIT, so
  // those accumulate. Of every connect in this file it is the only one that can genuinely exhaust the
  // pool — everywhere else the process exits and the OS reclaims the fd. So: keep the promise, and
  // close whatever it eventually yields.
  const connecting = connectToDaemon(socketPath);
  connecting.then(
    (late) => { try { late.close(); } catch { /* already closed by the winner below */ } },
    () => { /* never connected — nothing to reap */ },
  );

  try {
    const probe = await Promise.race([
      connecting,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("probe_timeout")), 500)),
    ]);
    probe.close();
    return false; // something still answers — the daemon is up
  } catch {
    // Nothing answers. Now make sure the process is really gone and not merely deaf: a daemon that
    // still holds the kernel lock is still alive, and the next login would refuse to start beside it.
    return probeSingletonLock(celloDir, logger) === "free";
  }
}

export async function logout(
  celloDir: string,
  onProgress?: (line: string) => void,
  // Injectable bounds so the timeout path is testable without a 5 s wait. Production (the bin)
  // passes nothing and gets the named defaults.
  waitOpts?: { timeoutMs?: number; pollMs?: number },
): Promise<CommandResult> {
  const lockFilePath = join(celloDir, "daemon.lock");
  const noopLogger: Logger = { debug() {}, info() {}, warn() {}, error() {} };
  const timeoutMs = waitOpts?.timeoutMs ?? LOGOUT_WAIT_TIMEOUT_MS;
  const pollMs = waitOpts?.pollMs ?? LOGOUT_WAIT_POLL_MS;

  // The socket path is DETERMINISTIC. `daemon.lock`'s copy of it is metadata, and metadata is not
  // to be trusted here.
  const socketPath = join(celloDir, "daemon.sock");
  const lock = await readLock(lockFilePath);

  // DOD-SINGLE-DAEMON-1 (AC4) — the lock file does not get to decide whether a daemon exists.
  //
  // Never short-circuit on `if (!lock) return "No daemon running."`. That is a KILL SWITCH REPORTING
  // SUCCESS WITHOUT DOING ANYTHING, and the state that triggers it is real: an exiting orphan unlinks
  // a HEALTHY daemon's lock (so does `rm ~/.cello/daemon.lock`). The operator then runs `cello logout`
  // to stop their agent, is told it was never running, and walks away — while the daemon is still
  // online, still on the directory, still extending the hash chain. A kill switch may not lie.
  //
  // So we ask the daemon itself. If something ANSWERS on the socket, a daemon is running — that is
  // the strongest evidence available, it needs no file, and it holds even for a pre-singleton-lock
  // daemon, which holds no singleton lock at all.
  let client: IpcClient;
  try {
    client = await connectToDaemon(socketPath);
  } catch (err: unknown) {
    // Nothing answered. Now the kernel decides — not the pid in the JSON, which may be dead, or
    // REUSED by an unrelated process (in which case `isProcessAlive` says "alive" forever).
    const probe = probeSingletonLock(celloDir, noopLogger);

    if (probe === "held") {
      // A daemon holds the lock but will not talk to us. We have NOT stopped it, and must not imply
      // otherwise. Point at the authoritative holder rather than a pid we did not verify.
      const named = lock ? ` (daemon.lock names pid ${lock.pid}, which may be stale)` : "";
      return {
        exitCode: 1,
        output:
          `A daemon is running${named} and holds the singleton lock, but is not answering on ` +
          `${socketPath} (${err instanceof Error ? err.message : String(err)}). It has NOT been ` +
          `stopped. Find the process that holds the lock with \`lsof ${join(celloDir, SINGLETON_LOCK_FILENAME)}\`, ` +
          "stop it, then re-run 'cello logout' to clean up.",
      };
    }

    if (probe === "unknown") {
      // We could not ask. Reporting "no daemon running" on a guess is the whole failure mode.
      return {
        exitCode: 1,
        output:
          `Could not determine whether a daemon is running: the singleton lock at ` +
          `${join(celloDir, SINGLETON_LOCK_FILENAME)} could not be checked. Refusing to report a ` +
          "daemon stopped without proof.",
      };
    }

    // probe === "free": nothing holds the lock and nothing answers. There is no daemon.
    if (!lock) {
      return { exitCode: 0, output: "No daemon running." };
    }
    // DOD-LOGOUT-WAIT-1: only CLAIM the removal when it actually happened — removeLock swallows
    // non-ENOENT errors into a (here discarded) warn, and printing "Removed" for a lock still on
    // disk would be this unit's own lie in miniature.
    const removed = await removeLock(lockFilePath, noopLogger)
      .then(async () => (await readLock(lockFilePath)) === null)
      .catch(() => false);
    return {
      exitCode: 0,
      output: removed
        ? "No daemon running. (Removed a stale daemon.lock — no daemon holds the singleton lock.)"
        : `No daemon running. (A stale daemon.lock remains at ${lockFilePath} and could not be removed — check its permissions.)`,
    };
  }

  try {
    await client.send("shutdown");
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { exitCode: 1, output: `Failed to stop daemon: ${message}` };
  } finally {
    // In the `finally`, not after the send: a throw from `shutdown` must not leak the connection.
    client.close();
  }

  // The request is in — tell the operator NOW, then report "stopped" only when it is true.
  onProgress?.("Shutting down the daemon…");

  // DOD-LOGOUT-WAIT-1: do NOT return the instant the shutdown request is WRITTEN. That leaves a
  // window where `cello logout && cello login` finds the daemon mid-death — connectOrStart sees a
  // live pid + connectable socket and prints "Daemon already running.", leaving the operator logged
  // out while being told otherwise. Wait until the daemon is genuinely gone; "Daemon stopped." for a
  // daemon that is still running is the same class of lie as a success log on a failed send
  // (DOD-SENDRAW-1).
  // DOD-LOGOUT-EXIT-1: the pid to hold the shutdown to. Taken from the lock read BEFORE the
  // shutdown was sent, and only trusted if it was actually alive then — a stale lock naming a dead
  // (or never-ours) pid must not make every logout wait out the full timeout. `undefined` here
  // means we have no process-level evidence to demand, and the two handle facts stand alone, which
  // is the pre-singleton-lock daemon's case.
  //
  // `lock.pid !== process.pid` is NOT a test accommodation: an IN-PROCESS daemon (an embedder, or
  // vitest) writes OUR pid into the lock, and requiring it to exit would mean requiring the caller
  // to exit before its own logout returns — never satisfiable, so every such logout would burn the
  // full timeout and then report a failure that did not happen. For that daemon "the process
  // ended" is not the right question; the handles are all there is, which is the pre-existing
  // contract. The defect this unit fixes is only reachable when the daemon is a SEPARATE process.
  const pidToOutlive =
    lock && lock.pid !== process.pid && isProcessAlive(lock.pid) ? lock.pid : undefined;

  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await daemonGone(celloDir, socketPath, noopLogger, pidToOutlive)) {
      return { exitCode: 0, output: "Daemon stopped." };
    }
    await new Promise((r) => setTimeout(r, pollMs));
  }
  const who = lock ? `pid ${lock.pid}, ` : "";
  return {
    exitCode: 1,
    output:
      `Daemon shutdown did not complete within ${timeoutMs / 1000}s ` +
      `(${who}socket ${socketPath}). The daemon acknowledged the request but is ` +
      `still running — it may be stuck closing sessions or its database. Check 'cello status'; ` +
      `if it never exits, find it with \`lsof ${join(celloDir, SINGLETON_LOCK_FILENAME)}\`, stop it, ` +
      "and re-run 'cello logout' to clean up.",
  };
}

/**
 * register(celloDir, agent, preAuthToken, phoneStub):
 *  - Read lock file to find socket path (daemon must be running)
 *  - Connect to daemon, send 'cello_register' with { agent, preAuthToken, phoneStub }
 *  - The daemon runs ML-DSA keygen → FROST DKG → register_success and persists
 *    the agent's key material + registration state + agent→user link.
 *  - Print structured JSON; exit 0 on success, 1 on failure.
 */
/**
 * Does this look like a pre-auth capability rather than a mis-paste?
 *
 * A capability (M8B-PREAUTH-CAP) is base64url JSON carrying a signed authorization. This decodes
 * far enough to tell it apart from someone pasting the literal words "CELLO_PREAUTH_TOKEN", and no
 * further: the directory verifies the signature, the issuer and the window. Anything stricter here
 * would let a client-side "malformed" strand a capability the consortium would have accepted.
 */
function hasCapabilityShape(value: string): boolean {
  try {
    const parsed: unknown = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
    if (typeof parsed !== "object" || parsed === null) return false;
    const c = parsed as Record<string, unknown>;
    return typeof c["sig"] === "string" && typeof c["nonce"] === "string" && typeof c["expires_at"] === "string";
  } catch {
    return false;
  }
}

export async function register(
  celloDir: string,
  agent: string,
  preAuthToken: string,
  phoneStub = "",
): Promise<CommandResult> {
  // M8C-ONBOARD-ERRORS-1 (R3/R4): specific, actionable errors on the core onboarding path — never a
  // bare Usage dump, never a pointless DKG round-trip to a generic dkg_failed for an obviously
  // malformed token. Client-side because a typo'd token and a missing one are knowable without the
  // directory. (Unknown-agent stays the daemon's job — it already returns a good agent_not_found.)
  if (!agent) {
    return { exitCode: 1, output: "You didn't name an agent to register. Usage: cello register-agent <agent> <pre-auth-token>. See your agents with 'cello status'." };
  }
  if (!preAuthToken) {
    return {
      exitCode: 1,
      output: `You're missing the pre-auth token. Get a single-use token from the CELLO Operations Agent on Telegram, then run:\n  cello register-agent ${agent} <token>\nor set it in the environment:\n  CELLO_PREAUTH_TOKEN=<token> cello register-agent ${agent}\nThe token is single-use and expires in 24 hours.`,
    };
  }
  // Client-side gate on the STABLE brand prefix only (real tokens are "CELLO-" + 33 base58 chars).
  // Checking just the prefix catches the common typo (pasting the literal words "CELLO_PREAUTH_TOKEN")
  // without hard-coding the exact length/alphabet — the directory stays the authority on the full format,
  // so a future format bump can't strand a valid token behind a client-side "malformed". The "DEV-"
  // sentinel is ALSO allowed: it is the dev/local pre-auth prefix that DevTokenValidator accepts
  // (CELLO_ENV=local), and it is unmistakably intentional, not a paste error. A wrong token of either
  // prefix reaches the daemon and is rejected there with a structured reason (the local DevTokenValidator
  // rejects non-DEV-, the prod PgTokenValidator rejects non-CELLO-). Without this, local CLI registration
  // is impossible — the CLI rejects the very DEV- tokens the local validator requires (it broke the whole
  // spine suite).
  // A pre-auth CAPABILITY (M8B-PREAUTH-CAP) is also valid here and has neither prefix: it is
  // base64url JSON, and preauth-capability.ts specifies it is "carried in the existing round-1
  // preAuthToken string field and pasted into `cello register`". Gating on the two legacy prefixes
  // alone rejected the very artifact the capability design says to paste — a capability could be
  // minted, signed and accepted by every directory, and never got past the client.
  //
  // Shape only, and deliberately NOT by importing @cello-protocol/crypto: the CLI does not depend
  // on it, and adding a package to the operator's install for a paste-error guard is the wrong
  // trade. The signature, the issuer and the validity window stay the directory's to verify — this
  // must never become a second authority on whether a capability is valid.
  const looksLikeCapability = hasCapabilityShape(preAuthToken);
  if (!looksLikeCapability && !preAuthToken.startsWith("CELLO-") && !preAuthToken.startsWith("DEV-")) {
    return {
      exitCode: 1,
      output: "That doesn't look like a pre-auth token or capability — tokens start with 'CELLO-' followed by 33 characters, and a capability is a long base64url blob. (Did you paste the words 'CELLO_PREAUTH_TOKEN' instead of the value itself?) Get one from the CELLO Operations Agent on Telegram, then retry.",
    };
  }

  const lockFilePath = join(celloDir, "daemon.lock");
  const lock = await readLock(lockFilePath);
  if (!lock) {
    return { exitCode: 1, output: "No daemon running. Run 'cello login' first, then retry registration." };
  }

  try {
    const result = (await withIpc(lock.socketPath, (client) => client.send("cello_register", { agent, preAuthToken, phoneStub }))) as {
      ok: boolean;
      reason?: string;
      guidance?: string;
      agent_id?: string;
      primary_pubkey?: string;
    };

    if (!result.ok) {
      return {
        exitCode: 1,
        output: JSON.stringify({ ok: false, reason: result.reason, guidance: result.guidance }, null, 2),
      };
    }
    return {
      exitCode: 0,
      output: JSON.stringify(
        { ok: true, agent_id: result.agent_id, primary_pubkey: result.primary_pubkey },
        null,
        2,
      ),
      // M8C-ONBOARD-NEXTSTEP-1: every command output carries the next step + state legibility.
      // Broken onto multiple lines — a dense one-liner buries the three status cues.
      //
      // DOD-M15-CLIJSON-1: on STDERR, not appended to the JSON above. A human in a terminal sees
      // both streams and loses nothing; a script gets parseable output. This text used to make
      // `register-agent` unparseable on its SUCCESS path.
      guidance:
        `Next: run  cello status  to confirm '${agent}' is registered.\n` +
        `  • it's normal for this to take a minute or two while registration settles.\n` +
        `  • ready = the agent shows state 'online' and directory_signaling 'connected'.\n` +
        `  • if it stays offline, run  cello logout  then  cello login.`,
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { exitCode: 1, output: `Failed to register: ${message}` };
  }
}

/**
 * createAgent(celloDir, name):
 *  - Connect to the daemon, send 'cello_create_agent' with { name }.
 *  - The daemon generates a fresh K_local seed, writes it as an `agents` row in the encrypted DB
 *    (PERSIST-002 — no key file), and wires the agent in so it can be registered immediately.
 */
export async function createAgent(celloDir: string, name: string): Promise<CommandResult> {
  if (!name) {
    return { exitCode: 1, output: "Usage: cello create-agent <name>  — creates a new local agent identity." };
  }

  const lockFilePath = join(celloDir, "daemon.lock");
  const lock = await readLock(lockFilePath);
  if (!lock) {
    return { exitCode: 1, output: "No daemon running. Run 'cello login' first, then retry create-agent." };
  }

  try {
    const result = (await withIpc(lock.socketPath, (client) => client.send("cello_create_agent", { name }))) as {
      ok: boolean;
      reason?: string;
      guidance?: string;
      name?: string;
      pubkey?: string;
      agentId?: string;
    };

    if (!result.ok) {
      return { exitCode: 1, output: JSON.stringify({ ok: false, reason: result.reason, guidance: result.guidance }, null, 2) };
    }
    return {
      exitCode: 0,
      output: JSON.stringify({ ok: true, name: result.name, pubkey: result.pubkey, agentId: result.agentId }, null, 2),
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { exitCode: 1, output: `Failed to create agent: ${message}` };
  }
}

/**
 * refreshShares(celloDir, name): M8B DOD-REFRESH-1.
 *  - Connect to the daemon, send 'cello_refresh_shares' with { agent }.
 *  - The daemon runs a proactive share refresh across the consortium: every shareholder rotates its
 *    share to a new epoch, the group public key is unchanged, and old-epoch shares no longer sign.
 */
export async function refreshShares(celloDir: string, name: string): Promise<CommandResult> {
  if (!name) {
    return { exitCode: 1, output: "Usage: cello refresh <name>  — proactively refresh the agent's threshold shares (new epoch)." };
  }
  const lockFilePath = join(celloDir, "daemon.lock");
  const lock = await readLock(lockFilePath);
  if (!lock) {
    return { exitCode: 1, output: "No daemon running. Run 'cello login' first, then retry refresh." };
  }
  try {
    const result = (await withIpc(lock.socketPath, (client) => client.send("cello_refresh_shares", { agent: name }))) as {
      ok: boolean;
      reason?: string;
      guidance?: string;
      epoch?: number;
      primary_pubkey?: string;
      verifying_shares_digest?: string;
    };
    if (!result.ok) {
      return { exitCode: 1, output: JSON.stringify({ ok: false, reason: result.reason, guidance: result.guidance }, null, 2) };
    }
    return {
      exitCode: 0,
      output: JSON.stringify({ ok: true, epoch: result.epoch, primary_pubkey: result.primary_pubkey, verifying_shares_digest: result.verifying_shares_digest }, null, 2),
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { exitCode: 1, output: `Failed to refresh shares: ${message}` };
  }
}

/**
 * relayReceipts(celloDir, name): M8B DOD-RELAYSIG-1.
 *  - Connect to the daemon, send 'cello_get_relay_receipts' with { agent }.
 *  - Returns the agent's durably-stored, signature-verified relay ordering-record receipts.
 */
export async function relayReceipts(celloDir: string, name: string): Promise<CommandResult> {
  if (!name) {
    return { exitCode: 1, output: "Usage: cello relay-receipts <name>  — ADVANCED/DEBUG: the per-message proofs a relay signed when it "
        + "delivered for this agent. For a session's notarized seal, use 'cello sealed-receipt <session-id>'." };
  }
  const lockFilePath = join(celloDir, "daemon.lock");
  const lock = await readLock(lockFilePath);
  if (!lock) {
    return { exitCode: 1, output: "No daemon running. Run 'cello login' first, then retry receipts." };
  }
  try {
    const result = (await withIpc(lock.socketPath, (client) => client.send("cello_get_relay_receipts", { agent: name }))) as {
      ok: boolean;
      reason?: string;
      guidance?: string;
      receipts?: unknown[];
    };
    if (!result.ok) {
      return { exitCode: 1, output: JSON.stringify({ ok: false, reason: result.reason, guidance: result.guidance }, null, 2) };
    }
    return { exitCode: 0, output: JSON.stringify({ ok: true, receipts: result.receipts ?? [] }, null, 2) };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { exitCode: 1, output: `Failed to get relay receipts: ${message}` };
  }
}

/**
 * removeAgent(celloDir, name) — CELLO-M7-REMOVE-001 (DOD-REMOVE-1):
 *  - Connect to the daemon, send 'cello_remove_agent' with { name }.
 *  - The daemon RETIRES the agent (state=retired; row, keys, and history KEPT for accountability) and
 *    FREES the human name for reuse. One-way.
 */
export async function removeAgent(celloDir: string, name: string): Promise<CommandResult> {
  if (!name) {
    return { exitCode: 1, output: "Usage: cello remove-agent <name>  — retires a local agent (one-way) and frees its name." };
  }

  const lockFilePath = join(celloDir, "daemon.lock");
  const lock = await readLock(lockFilePath);
  if (!lock) {
    return { exitCode: 1, output: "No daemon running. Run 'cello login' first, then retry remove-agent." };
  }

  try {
    const result = (await withIpc(lock.socketPath, (client) => client.send("cello_remove_agent", { name }))) as {
      ok: boolean;
      reason?: string;
      guidance?: string;
      name?: string;
      agentId?: string;
      oneWay?: boolean;
      directoryRevocation?: string;
    };

    if (!result.ok) {
      return { exitCode: 1, output: JSON.stringify({ ok: false, reason: result.reason, guidance: result.guidance }, null, 2) };
    }
    return {
      exitCode: 0,
      output: JSON.stringify(
        {
          ok: true,
          name: result.name,
          agentId: result.agentId,
          oneWay: result.oneWay,
          // DOD-REMOVE-2: whether the signed revocation was recorded at the directory (recorded /
          // deferred — directory unreachable / skipped — never registered). The daemon's guidance
          // carries the actionable detail.
          directoryRevocation: result.directoryRevocation,
          message: result.guidance ?? "Agent retired (one-way). Its identity and history are kept; the name is free to reuse.",
        },
        null,
        2,
      ),
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { exitCode: 1, output: `Failed to remove agent: ${message}` };
  }
}

export async function status(celloDir: string): Promise<CommandResult> {
  const lockFilePath = join(celloDir, "daemon.lock");
  const lock = await readLock(lockFilePath);

  // DOD-LOGOUT-EXIT-1 (AC3): `stopped` used to come from a single FILE STAT — no lock file, no
  // daemon. That is exactly the reasoning `logout` refuses by name above ("the lock file does not
  // get to decide whether a daemon exists"), and it fails the same way: an exiting orphan unlinks a
  // HEALTHY daemon's lock, and so does `rm ~/.cello/daemon.lock`. The operator then reads `stopped`
  // while the daemon is online, on the directory, and extending the hash chain.
  //
  // So ask the daemon itself first, at the DETERMINISTIC socket path — daemon.lock's copy is
  // metadata, and here there may be no lock file to read it from anyway.
  const socketPath = lock?.socketPath ?? join(celloDir, "daemon.sock");

  try {
    // Bounded, for the same reason `daemonGone` bounds its probe: connectToDaemon has no connect
    // timeout of its own, so a half-dead daemon holding a listening socket it will never answer on
    // would hang `cello status` forever. That is not a hypothetical here — it is a shape of the
    // very broken-shutdown state this function now has to report on.
    const result = (await Promise.race([
      withIpc(socketPath, (client) => client.send("status")),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("status probe timed out after 3000ms")), 3_000),
      ),
    ])) as DaemonStatusResponse;
    return { exitCode: 0, output: JSON.stringify(result, null, 2) };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);

    // Nothing answered. Now the kernel decides whether a daemon process exists — not a file.
    const probe = probeSingletonLock(celloDir, { debug() {}, info() {}, warn() {}, error() {} });

    if (probe === "held") {
      // A daemon process exists but has released (or never opened) its socket. That is a BROKEN
      // SHUTDOWN, not a clean stop, and it is the state DOD-LOGOUT-EXIT-1 was filed for: the
      // process is still alive and may still be on the network. Reporting `stopped` here is the
      // lie. Name the state and point at the holder.
      return {
        exitCode: 1,
        output: JSON.stringify(
          {
            daemon: "broken_shutdown",
            detail:
              "A daemon process holds the singleton lock but is not answering on its socket. It has " +
              "NOT cleanly stopped and may still be connected to a directory. Find it with " +
              `\`lsof ${join(celloDir, SINGLETON_LOCK_FILENAME)}\` and stop it, then run 'cello logout' to clean up.`,
            socketPath,
            error: message,
          },
          null,
          2,
        ),
      };
    }

    if (probe === "unknown") {
      // We could not ask. Reporting either "running" or "stopped" on a guess is the failure mode.
      return {
        exitCode: 1,
        output: JSON.stringify(
          {
            daemon: "unknown",
            detail:
              `The singleton lock at ${join(celloDir, SINGLETON_LOCK_FILENAME)} could not be checked, ` +
              "so whether a daemon is running cannot be determined.",
            error: message,
          },
          null,
          2,
        ),
      };
    }

    // probe === "free": nothing holds the lock and nothing answers, so there is no daemon OF THIS
    // VERSION. The claim is deliberately narrower than "no daemon": a pre-singleton-lock daemon
    // holds no singleton lock at all, so `free` says nothing about it and only the socket could
    // have told us — which is why the socket is tried first, above. That residue is bounded by the
    // upgrade and cannot be closed from this side.
    // A lock file that is still present is stale metadata, not evidence of a process.
    if (!lock) {
      return { exitCode: 1, output: JSON.stringify({ daemon: "stopped" }, null, 2) };
    }
    return {
      exitCode: 1,
      output: JSON.stringify({ daemon: "unreachable", error: message }, null, 2),
    };
  }
}

export type SessionFilter = "open" | "closed" | "failed" | "all";

/**
 * `cello sessions [--open|--closed|--failed|--all] [--limit N]` — the full, queryable session
 * history (the discovery surface `cello status` deliberately does NOT dump). Defaults to OPEN
 * (live + resumable) so a long-lived agent's failed/closed history doesn't flood it, and caps the
 * count at the daemon's default limit. Output reports `totalMatched` so the operator can tell when
 * results were truncated.
 */
export async function sessions(
  celloDir: string,
  opts: { filter?: SessionFilter; limit?: number } = {},
): Promise<CommandResult> {
  const lockFilePath = join(celloDir, "daemon.lock");
  const lock = await readLock(lockFilePath);

  if (!lock) {
    return { exitCode: 1, output: JSON.stringify({ daemon: "stopped" }, null, 2) };
  }

  try {
    const params: Record<string, unknown> = {};
    if (opts.filter) params.filter = opts.filter;
    if (opts.limit !== undefined) params.limit = opts.limit;
    const result = (await withIpc(lock.socketPath, (client) => client.send("list_sessions", params)));
    return { exitCode: 0, output: JSON.stringify(result, null, 2) };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      exitCode: 1,
      output: JSON.stringify({ daemon: "unreachable", error: message }, null, 2),
    };
  }
}

/** M8C-TGDOOR-1: `cello telegram set-token <bot_token> <allowlisted_chat_id>` — persists the
 *  daemon-wide bot credentials (narrow, dedicated surface; NOT folded into the parked `cello
 *  config`, since a bot token has no sensible default and can't wait for M9-CFG-001). */
/**
 * `cello attestations` — YOUR words about ANOTHER agent, and what became of them.
 *
 * SEPARATE FROM `trust-signals` ON PURPOSE. On the wire an attestation IS a trust signal, so folding
 * the two together is the obvious move — and it is the wrong one. A trust signal is the NETWORK
 * verifying an attribute of yours; an attestation is a PERSON vouching for a PERSON. That second
 * thing is the primitive collaboration rests on, and filing it as a subcommand of a wallet listing
 * makes the most important capability the hardest one to find.
 *
 * Subcommands:
 *   issue <pubkey> <text…>  — attest to something you have seen them do
 *   issued                  — what happened to the ones you wrote
 *
 * The receiving direction — what others wrote about YOU — is `cello attestation-consent`.
 */
export async function attestations(
  celloDir: string,
  sub: string,
  args: string[],
): Promise<CommandResult> {
  const lockFilePath = join(celloDir, "daemon.lock");
  const lock = await readLock(lockFilePath);
  if (!lock) {
    return { exitCode: 1, output: "No daemon running. Run 'cello login' first." };
  }

  // M10B / `M10B-D25r2` — "what happened to what I submitted?". A NETWORK call, so it is its own verb
  // rather than folded into `list`: listing what you hold must keep working when the directory is
  // unreachable, and a remote failure must not break a local read.
  if (sub === "issued") {
    try {
      // TWO CALLS. `wallet_list_issued` is the local record of what was submitted; `wallet_fetch_results`
      // is the network sweep for outcomes. Showing only the second made a submission still awaiting the
      // subject INVISIBLE — three in flight printed as "no outcomes waiting", which reads as "nothing
      // was ever sent" rather than "nobody has answered yet".
      const [issued, res] = (await withIpc(lock.socketPath, (client) =>
        Promise.all([client.send("wallet_list_issued"), client.send("wallet_fetch_results")]),
      )) as [
        { ok: boolean; reason?: string; guidance?: string; issued?: Array<{ submission_id: string; subject_pubkey: string; op: string; submitted_at: number }> },
        {
          ok: boolean;
          reason?: string;
          guidance?: string;
          results?: Array<{ submission_id: string; outcome: string; reason: string | null; signal_hash: string | null; message: string | null; created_at: string }>;
          unreachable_nodes?: string[];
        },
      ];
      if (!issued.ok) {
        return { exitCode: 1, output: `${issued.reason ?? "failed"}\n${issued.guidance ?? ""}`.trim() };
      }
      if (!res.ok) {
        return { exitCode: 1, output: `${res.reason ?? "failed"}\n${res.guidance ?? ""}`.trim() };
      }
      const byId = new Map((res.results ?? []).map((r) => [r.submission_id, r]));
      const rows: Array<{ submission_id: string; outcome: string; reason: string | null; message: string | null }> =
        (issued.issued ?? []).map((s) => ({
          ...(byId.get(s.submission_id) ?? { outcome: "pending", reason: null, message: null }),
          submission_id: s.submission_id,
        }));
      // Anything that came back for a submission this wallet has no local record of still gets shown —
      // dropping it would hide a real outcome behind a local bookkeeping gap.
      for (const r of res.results ?? []) if (!rows.some((x) => x.submission_id === r.submission_id)) rows.push(r);
      // A node that did not answer is stated, never folded into the list — an incomplete sweep must not
      // be readable as "nothing came back".
      const partial = (res.unreachable_nodes ?? []).length > 0
        ? `\n\n  ⚠ ${res.unreachable_nodes!.length} node(s) did not answer (${res.unreachable_nodes!.join(", ")}).\n    This list may be incomplete — an outcome recorded there is not shown yet.`
        : "";
      if (rows.length === 0) {
        return { exitCode: 0, output: "You have submitted no endorsements. Results are held until you collect them, so nothing has been missed." + partial };
      }
      const lines = rows.map((r) => {
        const head = `  ${r.outcome.padEnd(10)}  ${r.submission_id.slice(0, 12)}…  ${r.reason ?? "—"}`;
        // THE MESSAGE ON ITS OWN LINE, quoted and attributed. It is the SUBJECT'S words about the
        // operator's claim, and running it into the status columns would read as CELLO's verdict.
        return r.message ? `${head}\n      they said: "${r.message}"` : head;
      });
      const header = `  ${"outcome".padEnd(10)}  submission    reason`;
      return {
        exitCode: 0,
        output: [header, "  " + "─".repeat(60), ...lines].join("\n") +
          "\n\n  A refusal is the subject declining to stand behind your claim — not a fault in it.\n" +
          "  Re-submitting a corrected version is the intended next step.\n" +
          "  'pending' means the subject has not answered yet — the submission is not lost." + partial,
      };
    } catch (err) {
      return { exitCode: 1, output: `Could not reach the daemon: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  if (sub === "issue") {
    const [subject, ...rest] = args;
    // `--` ENDS FLAG PARSING. Free prose is the whole point of this verb, and prose contains things
    // that look like flags: "cut p99 -30ms" is rejected as an unknown flag, and "-h" anywhere prints
    // help instead of issuing. The operator needs a way to say "the rest is text", and `--` is the
    // convention every shell user already knows.
    const body = (rest[0] === "--" ? rest.slice(1) : rest).join(" ");
    if (!subject || body.length === 0) {
      return {
        exitCode: 1,
        output:
          "Usage: cello attestations issue <subject-pubkey> <what you are endorsing them for…>\n" +
          "\n" +
          "If your text contains something that looks like a flag (a leading '-', or '-h'), put `--`\n" +
          "before it so it is read as text:\n" +
          "  cello attestations issue <pubkey> -- cut p99 by -30ms on the auth path",
      };
    }
    try {
      const result = (await withIpc(lock.socketPath, (client) =>
        client.send("cello_attestations_issue", { subject_pubkey: subject, body }))) as {
        ok: boolean; reason?: string; guidance?: string; submission_id?: string;
      };
      if (!result.ok) {
        return { exitCode: 1, output: `${result.reason}\n${result.guidance ?? ""}`.trim() };
      }
      return { exitCode: 0, output: result.guidance ?? "Submitted." };
    } catch (err: unknown) {
      return { exitCode: 1, output: `Failed to issue signal: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  return {
    exitCode: 1,
    output:
      "Usage:\n" +
      "  cello attestations issue <pubkey> <text…>  — attest to something you have seen them do\n" +
      "  cello attestations issued                  — what happened to the ones you wrote\n" +
      "\n" +
      "What others wrote about YOU is 'cello attestation-consent'.",
  };
}

/**
 * `cello trust-signals` — inspect and manage the operator's trust-signal wallet.
 *
 * Subcommands:
 *   list                   — tabular view of all signals (includes default column)
 *   view <hash-prefix>     — full decoded payload for one signal
 *   enable <hash-prefix>   — include signal in the default presentation bundle
 *   disable <hash-prefix>  — exclude signal from the default bundle
 *   revoke <hash-prefix>   — tombstone at the directory AND hard-delete locally
 */
export async function trustSignals(
  celloDir: string,
  sub: string,
  args: string[],
): Promise<CommandResult> {
  const lockFilePath = join(celloDir, "daemon.lock");
  const lock = await readLock(lockFilePath);
  if (!lock) {
    return { exitCode: 1, output: "No daemon running. Run 'cello login' first." };
  }

  if (sub === "list") {
    const showAll = args.includes("--all");
    try {
      const result = (await withIpc(lock.socketPath, (client) => client.send("wallet_list_signals"))) as {
        ok: boolean;
        signals?: Array<{
          type: string;
          signal_hash: string;
          subject_kind: string;
          status: string;
          issued_at: number;
          expires_at: number | null;
          supersedes_hash: string | null;
          default_present: boolean;
          consent_state: string | null;
          /** M10B / DOD-END-COUNT-1 — the endorser and the subject are the same operator. */
          same_operator?: boolean;
        }>;
        reason?: string;
      };
      if (!result.ok) {
        return { exitCode: 1, output: JSON.stringify({ ok: false, reason: result.reason }, null, 2) };
      }
      const all = result.signals ?? [];
      const signals = showAll ? all : all.filter((s) => s.status === "active");
      const supersededCount = all.filter((s) => s.status !== "active").length;
      if (signals.length === 0 && all.length === 0) {
        return { exitCode: 0, output: "No trust signals in wallet." };
      }
      if (signals.length === 0) {
        return { exitCode: 0, output: `No active trust signals. ${supersededCount} superseded (run with --all to show).` };
      }
      // M10B / DOD-END-SURFACE-1. `status` is the DIRECTORY's answer (is the notarization live);
      // consent is the SUBJECT's answer (may it be shown at all). A signal needs both, and only
      // `accepted` is presentable — so anything else must never render as included, or the
      // operator's own list contradicts what presentation actually does.
      const presentable = (s: { consent_state: string | null }) => s.consent_state === "accepted";
      const anyAwaiting = signals.some((s) => !presentable(s));
      const lines = signals.map((s) => {
        const date = new Date(s.issued_at * 1000).toISOString().slice(0, 10);
        const hash = s.signal_hash.slice(0, 12) + "…";
        const status = s.status === "active" ? "active" : s.status === "superseded" ? "superseded" : s.status;
        // ABSENT IS NOT FINE (§5a): an unset or unrecognised consent state reads as "awaiting", never
        // as presentable. The attacker never has to defeat this check — they omit what triggers it.
        const consent = s.consent_state === "accepted" ? "—"
          : s.consent_state === "pending" ? "PENDING"
          : s.consent_state === "refused" ? "refused"
          : "awaiting";
        const inc = presentable(s) ? (s.default_present ? "✓" : "–") : "✗";
        // M10B / DOD-END-COUNT-1 — MCP/CLI parity (DOD-END-SURFACE-1). The daemon returns
        // `same_operator` and the MCP surface shows it; without this column the CLI operator sees two
        // endorsements as identical when one is capped — a recipient's floor excludes a co-owned
        // endorsement from `min_count` — and that reads as the protocol behaving arbitrarily.
        const own = s.same_operator === true ? "own" : "—";
        return `  ${s.type.padEnd(22)}  ${hash}  ${status.padEnd(12)}  ${consent.padEnd(9)}  ${own.padEnd(5)}  ${inc.padEnd(4)}  ${date}`;
      });
      const header = `  ${"type".padEnd(22)}  hash          status        consent    co-own  include  issued`;
      const divider = "  " + "─".repeat(92);
      const consentLegend = anyAwaiting
        ? `\n  consent: PENDING = someone issued this ABOUT you and it awaits your decision — it is NOT\n           shown to anyone until you accept.  Run 'cello attestation-consent list' to read and decide.\n           refused = you refused it; it stays inert.  ✗ = not presentable, whatever 'include' says.`
        : "";
      // The co-own legend appears only when a co-owned signal is present: a line explaining a column
      // that reads "—" on every row is noise, and its APPEARANCE is what makes the operator look.
      const anyCoOwned = signals.some((s) => s.same_operator === true);
      const coOwnLegend = anyCoOwned
        ? `\n  co-own:  'own' = the endorser and the subject are your own agents. Still shown to contacts,\n           but it does NOT count toward a counterparty's minimum-endorsements requirement.`
        : "";
      const legend = `\n  include: ✓ = presented to contacts by default  – = excluded from presentation\n           To change: 'cello trust-signals enable <hash>'  or  'cello trust-signals disable <hash>'${coOwnLegend}${consentLegend}`;
      const footer = !showAll && supersededCount > 0
        ? `\n  (${supersededCount} superseded not shown — run with --all to include)`
        : "";
      return { exitCode: 0, output: [header, divider, ...lines].join("\n") + legend + footer };
    } catch (err: unknown) {
      return { exitCode: 1, output: `Failed to list signals: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  if (sub === "view") {
    const prefix = args[0];
    if (!prefix) {
      return { exitCode: 1, output: "Usage: cello trust-signals view <hash-prefix>" };
    }
    try {
      const result = (await withIpc(lock.socketPath, (client) => client.send("wallet_view_signal", { hash_prefix: prefix }))) as {
        ok: boolean;
        type?: string;
        signal_hash?: string;
        subject_kind?: string;
        subject?: string;
        issuer_kind?: string;
        issuer_pubkey?: string;
        schema_version?: number;
        status?: string;
        default_present?: boolean;
        issued_at?: number;
        expires_at?: number | null;
        supersedes_hash?: string | null;
        payload?: unknown;
        reason?: string;
        guidance?: string;
      };
      if (!result.ok) {
        return { exitCode: 1, output: result.guidance ?? result.reason ?? "signal not found" };
      }
      const lines = [
        `type:            ${result.type}`,
        `signal_hash:     ${result.signal_hash}`,
        `status:          ${result.status}`,
        `default_present: ${result.default_present ? "yes" : "no"}`,
        `subject_kind:    ${result.subject_kind}`,
        `subject:         ${result.subject}`,
        `issuer_kind:     ${result.issuer_kind}`,
        `issuer_pubkey:   ${result.issuer_pubkey}`,
        `schema_version:  ${result.schema_version}`,
        `issued_at:       ${result.issued_at ? new Date(result.issued_at * 1000).toISOString() : "—"}`,
        `expires_at:      ${result.expires_at ? new Date(result.expires_at * 1000).toISOString() : "—"}`,
        `supersedes:      ${result.supersedes_hash ?? "—"}`,
        `payload:         ${JSON.stringify(result.payload, null, 2)}`,
      ];
      return { exitCode: 0, output: lines.join("\n") };
    } catch (err: unknown) {
      return { exitCode: 1, output: `Failed to view signal: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  if (sub === "enable") {
    const prefix = args[0];
    if (!prefix) {
      return { exitCode: 1, output: "Usage: cello trust-signals enable <hash-prefix>" };
    }
    try {
      const result = (await withIpc(lock.socketPath, (client) => client.send("wallet_enable_signal", { hash_prefix: prefix }))) as {
        ok: boolean;
        signal_hash?: string;
        reason?: string;
        guidance?: string;
      };
      if (!result.ok) {
        return { exitCode: 1, output: result.guidance ?? result.reason ?? "failed to enable signal" };
      }
      return { exitCode: 0, output: `Signal ${result.signal_hash} enabled (included in default presentation).` };
    } catch (err: unknown) {
      return { exitCode: 1, output: `Failed to enable signal: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  if (sub === "disable") {
    const prefix = args[0];
    if (!prefix) {
      return { exitCode: 1, output: "Usage: cello trust-signals disable <hash-prefix>" };
    }
    try {
      const result = (await withIpc(lock.socketPath, (client) => client.send("wallet_disable_signal", { hash_prefix: prefix }))) as {
        ok: boolean;
        signal_hash?: string;
        reason?: string;
        guidance?: string;
      };
      if (!result.ok) {
        return { exitCode: 1, output: result.guidance ?? result.reason ?? "failed to disable signal" };
      }
      return { exitCode: 0, output: `Signal ${result.signal_hash} disabled (excluded from default presentation).` };
    } catch (err: unknown) {
      return { exitCode: 1, output: `Failed to disable signal: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  if (sub === "revoke") {
    const prefix = args[0];
    if (!prefix) {
      return { exitCode: 1, output: "Usage: cello trust-signals revoke <hash-prefix>" };
    }
    try {
      const result = (await withIpc(lock.socketPath, (client) => client.send("wallet_revoke_signal", { hash_prefix: prefix }))) as {
        ok: boolean;
        signal_hash?: string;
        submission_id?: string;
        queued?: boolean;
        reason?: string;
        guidance?: string;
      };
      if (!result.ok) {
        return { exitCode: 1, output: result.guidance ?? result.reason ?? "failed to revoke signal" };
      }
      // QUEUED, NOT REVOKED — and the daemon's own guidance says what happens next.
      //
      // This printed `Revoked signal <hash>. directory unreachable — tombstone may be pending.` on
      // every success, at exit 0. Three untruths in one line: it was not revoked, no directory was
      // contacted from here, and `directory_results` had stopped existing so `every()` on undefined
      // fell to `false` and the failure branch ran unconditionally. It also DROPPED the daemon's
      // guidance, which is the only place the operator learns that their local copy is kept and how
      // to check the outcome.
      return {
        exitCode: 0,
        output:
          `Revocation queued for ${result.signal_hash}` +
          (result.submission_id ? ` (submission ${result.submission_id.slice(0, 12)}…)` : "") +
          (result.guidance ? `\n${result.guidance}` : ""),
      };
    } catch (err: unknown) {
      return { exitCode: 1, output: `Failed to revoke signal: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  return {
    exitCode: 1,
    output:
      "Usage:\n" +
      "  cello trust-signals list [--all]      — show active signals (--all includes superseded)\n" +
      "  cello trust-signals view <hash>       — decode and display a signal's full payload\n" +
      "  cello trust-signals enable <hash>     — include signal in the default presentation bundle\n" +
      "  cello trust-signals disable <hash>    — exclude signal from the default bundle\n" +
      "  cello trust-signals revoke <hash>     — ask the portal to retract a signal (queued; your copy is kept)\n" +
      "\n" +
      "<hash> can be a prefix (min 8 chars). See 'cello trust-signals list' for hashes.",
  };
}

export async function telegramSetToken(celloDir: string, botToken: string, chatId: string): Promise<CommandResult> {
  const lockFilePath = join(celloDir, "daemon.lock");
  const lock = await readLock(lockFilePath);
  if (!lock) {
    return { exitCode: 1, output: JSON.stringify({ daemon: "stopped" }, null, 2) };
  }
  try {
    const result = (await withIpc(lock.socketPath, async (client) => {
      await client.send("ipc.connect", { clientType: "cli" });
      return client.send("cello_telegram_set_token", { bot_token: botToken, allowlisted_chat_id: chatId });
    })) as { ok: boolean };
    return { exitCode: result.ok ? 0 : 1, output: JSON.stringify(result, null, 2) };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return { exitCode: 1, output: JSON.stringify({ daemon: "unreachable", error: message }, null, 2) };
  }
}
