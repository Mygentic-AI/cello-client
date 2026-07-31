/**
 * LocalSidecarGatewayClient — the daemon's adapter to a gateway running as a local sidecar.
 *
 * Connects to the gateway's Unix domain socket and screens over the length-prefixed JSON
 * protocol. Every call resolves to a terminal verdict within a deadline: a connect failure, a
 * socket error, or a timeout all resolve to a fail-closed `block` (gateway_unavailable) — never
 * a hang and never a silent allow (INV-6 / SI-001 / DB-001).
 *
 * Phase 2's remote gateway is a sibling implementation of SecurityGatewayClient that swaps this
 * Unix socket for an mTLS connection; the daemon code and the message shapes are unchanged.
 */
import { connect, type Socket } from "node:net";
import {
  FrameDecoder,
  encodeFrame,
  SCREEN_OUTBOUND,
  SCREEN_INBOUND,
  type ScreenMethod,
  type WireScreenRequest,
  type WireScreenResponse,
} from "./protocol.js";
import { withProvenance } from "./screen/affordance.js";
import { failClosedVerdict, GOVERNANCE_TIMEOUT, type GatewayMode, type ScreenContext, type ScreenVerdict, type SecurityGatewayClient } from "./types.js";
import type { GatewayLogger } from "./server.js";

const NOOP_LOGGER: GatewayLogger = { info() {}, warn() {}, error() {} };
const DEFAULT_DEADLINE_MS = 5_000;

interface Pending {
  resolve: (verdict: ScreenVerdict) => void;
  timer: ReturnType<typeof setTimeout>;
  direction: "outbound" | "inbound";
  original: Uint8Array;
}

export interface LocalSidecarGatewayClientOptions {
  socketPath: string;
  /** Per-call deadline. A call that does not get a verdict within this window fails closed. */
  deadlineMs?: number;
  logger?: GatewayLogger;
}

export class LocalSidecarGatewayClient implements SecurityGatewayClient {
  /**
   * `enforcing` — and it stays `enforcing` even when the socket is down, because a client whose
   * gateway is unreachable does not start allowing content: it fails closed (`gateway_unavailable`).
   * The mode describes what this client DOES with content, not whether the socket happens to be up.
   */
  readonly mode: GatewayMode = "enforcing";
  readonly #socketPath: string;
  readonly #deadlineMs: number;
  readonly #logger: GatewayLogger;
  #socket: Socket | null = null;
  #connecting: Promise<Socket> | null = null;
  #pending = new Map<number, Pending>();
  #nextId = 1;
  #closed = false;

  /**
   * Why the gateway is unreachable, when the composition root already knows (review F2).
   *
   * Without this, a sidecar that never started surfaced as `gateway_unavailable` on every message
   * — an exit-point label that says "the transport failed, check the gateway is running and
   * retry". But the gateway is not running and never will be, retrying can never work, and the
   * actual cause (a missing key file, a store locked by an orphan, a leftover plaintext store, a
   * missing binary) was logged once at boot and then thrown away. The spawner already captures
   * the child's coded, guided stderr; this is where it survives to the operator.
   */
  #unavailable: { reason: string; guidance: string } | undefined;

  constructor(opts: LocalSidecarGatewayClientOptions) {
    this.#socketPath = opts.socketPath;
    this.#deadlineMs = opts.deadlineMs ?? DEFAULT_DEADLINE_MS;
    this.#logger = opts.logger ?? NOOP_LOGGER;
  }

  /**
   * Record why the sidecar could not be started, so every later refusal names THAT rather than the
   * generic unreachable label. Called by the composition root when the spawn fails.
   */
  setUnavailableCause(reason: string, guidance: string): void {
    this.#unavailable = { reason, guidance };
  }

  screenOutbound(content: Uint8Array, ctx: ScreenContext): Promise<ScreenVerdict> {
    return this.#screen(SCREEN_OUTBOUND, content, ctx);
  }

  screenInbound(content: Uint8Array, ctx: ScreenContext): Promise<ScreenVerdict> {
    return this.#screen(SCREEN_INBOUND, content, ctx);
  }

  async close(): Promise<void> {
    this.#closed = true;
    const sock = this.#socket;
    this.#socket = null;
    if (sock) await new Promise<void>((resolve) => { sock.end(() => resolve()); });
    // Any still-pending calls fail closed rather than hang on a closing client.
    for (const [, p] of this.#pending) {
      clearTimeout(p.timer);
      p.resolve(failClosedVerdict(p.direction));
    }
    this.#pending.clear();
  }

  async #screen(method: ScreenMethod, content: Uint8Array, ctx: ScreenContext): Promise<ScreenVerdict> {
    const direction = method === SCREEN_OUTBOUND ? "outbound" : "inbound";
    if (this.#closed) return failClosedVerdict(direction);

    let socket: Socket;
    try {
      socket = await this.#ensureConnected();
    } catch (err) {
      this.#logger.warn("gateway.connect.failed", {
        direction,
        error: err instanceof Error ? err.message : String(err),
      });
      // The known cause wins over the generic one (F2): "your daemon key file is missing" sends
      // the operator to the right place; "the gateway could not be reached, retry" does not.
      if (this.#unavailable) {
        const verdict = failClosedVerdict(direction, this.#unavailable.reason);
        return { ...verdict, guidance: withProvenance(this.#unavailable.guidance) };
      }
      return failClosedVerdict(direction);
    }

    const id = this.#nextId++;
    const request: WireScreenRequest = {
      id,
      method,
      content: Buffer.from(content).toString("base64"),
      ctx: {
        direction,
        agentName: ctx.agentName,
        sessionId: ctx.sessionId,
        ...(ctx.correlationId !== undefined ? { correlationId: ctx.correlationId } : {}),
        ...(ctx.governanceDecisions !== undefined ? { governanceDecisions: ctx.governanceDecisions } : {}),
      },
    };

    return new Promise<ScreenVerdict>((resolve) => {
      const timer = setTimeout(() => {
        if (this.#pending.delete(id)) {
          this.#logger.warn("gateway.screen.timeout", { direction, deadlineMs: this.#deadlineMs });
          // Connected but no verdict within the deadline → governance_timeout (distinct from the
          // unreachable case). A timeout is a verdict, not a hang (INV-6 / AC-005).
          resolve(failClosedVerdict(direction, GOVERNANCE_TIMEOUT));
        }
      }, this.#deadlineMs);
      if (typeof (timer as { unref?: () => void }).unref === "function") (timer as { unref: () => void }).unref();
      this.#pending.set(id, { resolve, timer, direction, original: content });
      try {
        socket.write(encodeFrame(request));
      } catch (err) {
        if (this.#pending.delete(id)) {
          clearTimeout(timer);
          this.#logger.warn("gateway.write.failed", {
            direction,
            error: err instanceof Error ? err.message : String(err),
          });
          resolve(failClosedVerdict(direction));
        }
      }
    });
  }

  #ensureConnected(): Promise<Socket> {
    if (this.#socket && !this.#socket.destroyed) return Promise.resolve(this.#socket);
    if (this.#connecting) return this.#connecting;

    this.#connecting = new Promise<Socket>((resolve, reject) => {
      const sock = connect(this.#socketPath);
      // L2: bound the CONNECT too — a stalled connect must fail closed, not hang (INV-6 is
      // unconditional). A UDS connect normally settles immediately; this guards the pathological case.
      const connectTimer = setTimeout(() => {
        sock.destroy();
        this.#connecting = null;
        reject(new Error(`gateway connect timed out after ${this.#deadlineMs}ms`));
      }, this.#deadlineMs);
      if (typeof (connectTimer as { unref?: () => void }).unref === "function") (connectTimer as { unref: () => void }).unref();
      const onError = (err: Error) => {
        clearTimeout(connectTimer);
        sock.destroy();
        this.#connecting = null;
        reject(err);
      };
      sock.once("error", onError);
      sock.once("connect", () => {
        clearTimeout(connectTimer);
        sock.off("error", onError);
        this.#connecting = null;
        this.#socket = sock;

        const decoder = new FrameDecoder(
          (obj) => this.#onResponse(obj as WireScreenResponse),
          (err) => {
            this.#logger.warn("gateway.response.decode.failed", { error: err.message });
            sock.destroy();
          },
        );
        sock.on("data", (chunk: Buffer) => decoder.push(chunk));
        // A dropped connection resolves every in-flight call fail-closed — never a hang.
        const onClose = () => {
          if (this.#socket === sock) this.#socket = null;
          for (const [, p] of this.#pending) {
            clearTimeout(p.timer);
            p.resolve(failClosedVerdict(p.direction));
          }
          this.#pending.clear();
        };
        sock.once("close", onClose);
        sock.on("error", (err: Error) => this.#logger.warn("gateway.socket.error", { error: err.message }));
        resolve(sock);
      });
    });
    return this.#connecting;
  }

  #onResponse(res: WireScreenResponse): void {
    const pending = this.#pending.get(res.id);
    if (!pending) return; // already timed out / unknown id
    this.#pending.delete(res.id);
    clearTimeout(pending.timer);

    const wire = res.verdict;
    const verdict: ScreenVerdict = { disposition: wire.disposition };
    if (wire.disposition === "allow") {
      // On allow the gateway omits content to keep the wire small; the daemon acts on the
      // original bytes it submitted.
      verdict.content = wire.content !== undefined ? Buffer.from(wire.content, "base64") : pending.original;
    } else if (wire.content !== undefined) {
      verdict.content = Buffer.from(wire.content, "base64");
    }
    if (wire.reason !== undefined) verdict.reason = wire.reason;
    // Review H3: mark it HERE, not at each of the eight producers. This is the one point every
    // agent-visible verdict crosses, so "every guidance carries the marker" is structural rather
    // than a rule each new guard has to remember (and F10 shipped with four producers that hadn't).
    if (wire.guidance !== undefined) verdict.guidance = withProvenance(wire.guidance);
    if (wire.events !== undefined) verdict.events = wire.events;
    if (wire.terminal !== undefined) verdict.terminal = wire.terminal;
    pending.resolve(verdict);
  }
}
