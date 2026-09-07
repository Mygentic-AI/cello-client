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
import { createIpcServer, type IpcHandler, type IpcServer, type HandlerLookup } from "./ipc-server.js";
import { AsyncLocalStorage } from "node:async_hooks";
import { renderForSurface } from "./vocabulary.js";
import type { Logger } from "./types.js";

export interface IpcSurfaceDeps {
  logger: Logger;
  socketPath: string;
  maxConnections: number;
  /** Read at DISPATCH — see the header. Never copied. */
  handlers: Map<string, IpcHandler>;
  perConnectionState: ReadonlyMap<string, { clientType?: string }>;
  fallbackNoticeStore: AsyncLocalStorage<{ notice?: Record<string, unknown> }>;
  /**
   * ⚠️ A GETTER. The daemon's own shutdown is defined BELOW this surface, and the `shutdown` verb
   * calls it. By value it would be `undefined` at construction and the verb would answer with a
   * crash instead of stopping the daemon.
   */
  getStop: () => (reason: string) => Promise<void>;
}

export function createIpcSurface(deps: IpcSurfaceDeps) {
  const { logger, socketPath, maxConnections, handlers, perConnectionState, fallbackNoticeStore, getStop } = deps;

  let shutdownPromise: Promise<void> | null = null;
  handlers.set("shutdown", async (_params, _connectionId) => {
    if (!shutdownPromise) {
      shutdownPromise = getStop()("logout_requested").catch((err: unknown) => {
        logger.error("daemon.shutdown.failed", {
          signal: "logout",
          error: err instanceof Error ? err.message : String(err),
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
  // RESOLVED AT DISPATCH, not copied at construction. This was a `for…of` that snapshotted
  // `handlers` into a second map, which made the ORDER of registration load-bearing in a file
  // 3,500 lines long: anything registered after this line was written into a map nothing
  // dispatched from. The document surface landed 245 lines below it and every `cello_doc_*` verb
  // answered `method_not_found` — whose guidance blames version skew between the shim and the
  // daemon, so an operator would re-pin, reinstall and restart, and find both sides matching.
  //
  // A comment saying "register above this line" would have been one more rule to remember. Late
  // binding makes the ordering unrepresentable instead: the map below reads `handlers` when a
  // request arrives, so a handler registered at any point before the first request is dispatchable.
  const renderedHandlers: HandlerLookup = {
    get(method: string): IpcHandler | undefined {
      const handler = handlers.get(method);
      if (!handler) return undefined;
      return async (params, connectionId) => {
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
        const result = await fallbackNoticeStore.run(store, () => handler(params, connectionId));
        /**
         * ⚠️ **THE NOTICE GOES FIRST, AND THAT ORDERING IS A SECURITY PROPERTY — review F2.**
         *
         * It used to be spread LAST, which reads as harmless because these keys are additive. It is
         * not: `cello_get_quarantined` returns a REFUSED MESSAGE as its final key, and the framing
         * that makes hostile content safe to read has NO CLOSING DELIMITER — the reader's one
         * structural guarantee is that nothing follows the payload. Three keys of genuine
         * CELLO-authored prose landing after it is exactly the shape a forged ending imitates, and
         * once a reader has seen real framing follow the payload, a forged one is credible.
         *
         * Not a corner case: `withIpc` in the CLI never sends `ipc.connect`, so a single-agent
         * daemon takes the sole-online fallback on EVERY plain `cello quarantined` invocation.
         *
         * Spreading first is safe in general and needs no per-handler knowledge: these keys cannot
         * collide with a handler's own (a collision would mean a handler already answered the
         * question the notice exists to answer), and every response then keeps its own key order at
         * the tail — which is where a payload-terminal key has to stay.
         */
        const annotated =
          store.notice && result !== null && typeof result === "object" && !Array.isArray(result)
            ? { ...store.notice, ...(result as Record<string, unknown>) }
            : result;
        // Default to "cli": a connection that never sent ipc.connect has no recorded surface, and
        // the CLI verb is the safe answer — it is at least a real command an operator can run,
        // whereas an MCP tool name is useless in a terminal.
        const surface = perConnectionState.get(connectionId)?.clientType === "mcp" ? "mcp" : "cli";
        return renderForSurface(annotated, surface);
      };
    },
  };

  // Create and start IPC server
  const ipcServer: IpcServer = createIpcServer(
    { socketPath, maxConnections, logger },
    renderedHandlers,
  );

  return { ipcServer, renderedHandlers };
}
