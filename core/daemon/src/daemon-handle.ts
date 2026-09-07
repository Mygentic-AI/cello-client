/**
 * What `startDaemon` hands back: the process's own control surface.
 *
 * It is an interface rather than the daemon object itself because two of its members exist only for
 * tests, and naming them here — with the reason each is a hook — is what stops them being read as
 * ordinary operations. It lived at the top of daemon.ts and was never wiring; 040-DAEMONROOT unit 8
 * moved it out for that reason alone.
 */
import type { DaemonStatusResponse } from "./types.js";
import type { ITransportSelector } from "./transport-selector.js";
import type { IAutoNatService } from "@cello-protocol/transport";
import type { SessionNodeManager } from "./session-node-manager.js";
import type { TypeRegistry } from "./type-registry.js";
import type { IpcHandler } from "./ipc-server.js";

export interface DaemonHandle {
  stop(reason: string): Promise<void>;
  getStatus(): DaemonStatusResponse;
  /**
   * DOD-M12B-CLOSE-SILENT-WAIT-1 test hook: put a session into the state a normal close sits in for
   * up to eleven minutes. Marks the real waiter map the status surface reads and emits the same
   * start-of-wait line, so a test cannot pass against a flag production never sets.
   * Not part of the production API surface.
   */
  markSealInFlightForTest(agentName: string, sessionId: string): void;
  /**
   * AC-016 test hook: exposes the session node manager so integration tests can
   * call registerRelayStream directly and verify the composition root is wired.
   * Not part of the production API surface.
   */
  getSessionNodeManager(): SessionNodeManager;
  /**
   * CELLO-M7-TRANSPORT-001 (AC-010): exposes the composition-root transport
   * selector so integration tests can confirm the adapter is wired (not dead
   * code) and exercise the selection path without "adapter not wired".
   */
  getTransportSelector(): ITransportSelector;
  /**
   * CELLO-M7-TRANSPORT-001 (AC-010): exposes the composition-root AutoNAT service
   * adapter (stub default dialable=false in local/test).
   */
  getAutoNatService(): IAutoNatService;
  /**
   * DOD-REGISTRY-1: the in-memory type registry — classify signal types.
   */
  getTypeRegistry(): TypeRegistry;
  /**
   * DOD-DOC-TOOLS-1 test hook: the LIVE handler map.
   *
   * Dispatch resolves from this map when a request arrives, and the only way to prove that rather
   * than assume it is to register a handler after `start()` has resolved and call it. The property
   * is load-bearing — a snapshot copy here once made every `cello_doc_*` verb unreachable while the
   * whole suite stayed green. Not part of the production API surface; nothing in production mutates
   * it after boot.
   */
  getHandlers(): Map<string, IpcHandler>;
}
