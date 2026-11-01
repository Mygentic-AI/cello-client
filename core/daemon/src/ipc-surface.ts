/**
 * The handler map as the IPC server sees it — every response rendered for the surface that asked.
 *
 * The daemon is where an operator actually MEETS the tool names. A refused send says "call
 * cello_receive first", and those strings are written with the MCP names, so an MCP caller gets them
 * verbatim while a CLI caller must be told `cello receive` — the thing they can type. Wrapping the
 * map is the ONE choke point that has both the response and the connection's client type; doing it
 * per-handler would mean sixty call sites and the sixty-first would forget.
 *
 * ⚠️ RESOLVED AT DISPATCH, NEVER SNAPSHOTTED. This was once a `for…of` that copied `handlers` into a
 * second map, which made the ORDER of registration load-bearing in a file thousands of lines long:
 * anything registered after that line went into a map nothing dispatched from. The document surface
 * landed below it and every `cello_doc_*` verb answered `method_not_found` — whose guidance blames
 * version skew, so an operator would re-pin, reinstall and restart, and find both sides matching.
 * Late binding makes that unrepresentable rather than forbidden by a comment.
 */
import { createIpcServer, DeferredUntilWritten, type IpcHandler, type IpcServer, type HandlerLookup } from "./ipc-server.js";
import { callerContext } from "./caller-identity.js";
import type { Admission } from "./attendance-guard.js";
import { AsyncLocalStorage } from "node:async_hooks";
import { renderForSurface } from "./vocabulary.js";
import type { Logger } from "./types.js";
import { extractErrorMessage } from "./error-message.js";

export interface IpcSurfaceDeps {
  logger: Logger;
  socketPath: string;
  maxConnections: number;
  /** Read at DISPATCH — see the header. Never copied. */
  handlers: Map<string, IpcHandler>;
  perConnectionState: ReadonlyMap<string, { clientType?: string }>;
  fallbackNoticeStore: AsyncLocalStorage<{ notice?: Record<string, unknown> }>;
  /**
   * ⚠️ A GETTER, AND THE HONEST REASON IS NOT THE OBVIOUS ONE. `stop` is a hoisted `function`
   * declaration, so passing it by value would work TODAY. The getter is there so that turning it
   * into a `const` — which is what every other extraction in this order did to its neighbours —
   * cannot silently break the `shutdown` verb. An earlier version of this comment claimed a crash
   * that cannot happen, which is the wrong lesson: the silent shape is a `let` assigned below.
   */
  getStop: () => (reason: string) => Promise<void>;
  /** M15D: who is calling, and may they act as the agent this call names (`attendance-guard.ts`). */
  admit: (method: string, params: Record<string, unknown> | undefined, connectionId: string, rawCaller: unknown) => Admission;
  /** M15D: how many of the connection slots only the CLI may use. */
  reservedForCli: number;
}

export function createIpcSurface(deps: IpcSurfaceDeps) {
  const { logger, socketPath, maxConnections, handlers, perConnectionState, fallbackNoticeStore, getStop, admit, reservedForCli } = deps;

  let shutdownPromise: Promise<void> | null = null;
  handlers.set("shutdown", async (_params, _connectionId) => {
    if (!shutdownPromise) {
      shutdownPromise = getStop()("logout_requested").catch((err: unknown) => {
        logger.error("daemon.shutdown.failed", {
          signal: "logout",
          error: extractErrorMessage(err),
        });
      });
    }
    return { acknowledged: true };
  });

  // DOD-ONBOARD-HELP-1 §5 — render every response for the surface that asked.
  //
  // The daemon is where an operator actually MEETS the tool names: a refused send says "call
  // cello_receive first". Those strings are written with the canonical MCP names, so an MCP caller
  // gets them verbatim — but a CLI caller must be told `cello receive`, the thing they can type.
  // (P2-7 was the one-off report of this; it is a whole CLASS, and this closes the class.)
  //
  // Wrapping the handler map is the ONE choke point that has both the response and the connection's
  // clientType. Doing it per-handler would mean 60+ call sites, and the 61st would forget.
  //
  // RESOLVED AT DISPATCH, not copied at construction: a snapshot made registration order
  // load-bearing, and every `cello_doc_*` verb registered after it answered `method_not_found`.
  // Reading `handlers` per request makes a handler registered before the first request dispatchable.
  const renderedHandlers: HandlerLookup = {
    get(method: string): IpcHandler | undefined {
      const handler = handlers.get(method);
      if (!handler) return undefined;
      return async (params, connectionId, meta) => {
        // The web endpoint speaks for MCP clients; a connection with no hello renders for the CLI.
        const clientType = perConnectionState.get(connectionId)?.clientType;
        const surface = clientType === "mcp" || clientType === "endpoint" ? "mcp" : "cli";
        const admission = admit(method, params, connectionId, meta?.caller);
        if (!admission.ok) return renderForSurface(admission.response, surface);
        try {
        /**
         * ONE request, ONE store — and the fallback notice is spread in BEFORE `renderForSurface`.
         *
         * `DOD-M15-SELECTION-1` clause 2 first annotated the response out in `ipc-server.ts`, which
         * is downstream of this wrapper and therefore downstream of surface rendering. The notice
         * says *"Run cello_use_agent"*; `isInstructionKey` in `vocabulary.ts` rewrites any key
         * ending in `guidance`, so that WOULD have become `cello use-agent` for a terminal — but it
         * arrived after the rewrite had already run. An operator running `cello inbox` was handed a
         * verb that does not exist in a shell, which is the exact failure the vocabulary layer was
         * built to prevent. Annotating here puts it back in front of the renderer.
         */
        const store: { notice?: Record<string, unknown> } = {};
        const outcome = await callerContext.run(admission.caller, () => fallbackNoticeStore.run(store, () => handler(params, connectionId, meta)));
        const deferred = outcome instanceof DeferredUntilWritten ? outcome : null, result = deferred ? deferred.result : outcome;
        /**
         * ⚠️ **THE NOTICE GOES FIRST, AND THAT ORDERING IS A SECURITY PROPERTY — review F2.**
         *
         * It used to be spread LAST, which reads as harmless because these keys are additive. It is
         * not: `cello_get_quarantined` returns a REFUSED MESSAGE as its final key, and the framing
         * that makes hostile content safe to read has NO CLOSING DELIMITER — the reader's one
         * structural guarantee is that nothing follows the payload. Three keys of genuine
         * CELLO-authored prose landing after it is exactly the shape a forged ending imitates, and
         * once a reader has seen real framing follow the payload, a forged one is credible.
         * Spreading first needs no per-handler knowledge, and every response keeps its own key order
         * at the tail — which is where a payload-terminal key has to stay.
         */
        const annotated =
          store.notice && result !== null && typeof result === "object" && !Array.isArray(result)
            ? { ...store.notice, ...(result as Record<string, unknown>) }
            : result;
        const rendered = renderForSurface(annotated, surface);
        return deferred ? new DeferredUntilWritten(rendered, deferred.afterWrite) : rendered;
        } finally {
          admission.finish();
        }
      };
    },
  };

  // Create and start IPC server
  const ipcServer: IpcServer = createIpcServer(
    { socketPath, maxConnections, reservedForCli, logger },
    renderedHandlers,
  );

  // `renderedHandlers` is not returned: its only consumer is the server constructed here.
  return { ipcServer };
}
