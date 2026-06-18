/**
 * CELLO Daemon — transport-composition.ts (CELLO-M7-TRANSPORT-001)
 *
 * Composition-root selection of the transport adapters by CELLO_ENV. Per CLAUDE.md
 * the daemon composition root instantiates all adapters and fails fast at startup
 * (not at first session) when a production environment is missing required config.
 *
 *   'local' | 'test'                   → in-process stubs (no network).
 *   'dev' | 'staging' | 'production'   → real adapters; require their backing
 *                                         dependencies (a TransportDialer for the
 *                                         selector). Missing config → throw at
 *                                         startup naming what is missing (AC-010).
 */

import {
  LocalTransportSelectorStub,
  TransportSelector,
  type ITransportSelector,
  type TransportDialer,
} from "./transport-selector.js";
import type { Logger } from "./types.js";

export type CelloEnv = "local" | "test" | "dev" | "staging" | "production";

/** Resolve CELLO_ENV. Unknown/undefined defaults to 'local' (in-process stubs). */
export function resolveCelloEnv(raw: string | undefined): CelloEnv {
  switch (raw) {
    case "local":
    case "test":
    case "dev":
    case "staging":
    case "production":
      return raw;
    default:
      return "local";
  }
}

/** True for environments that require real (network-backed) transport adapters. */
export function isProductionVariant(env: CelloEnv): boolean {
  return env === "dev" || env === "staging" || env === "production";
}

/**
 * Build the transport selector for the given environment. Stub for local/test;
 * real TransportSelector for production variants (requires a TransportDialer).
 */
export function createTransportSelector(opts: {
  env: CelloEnv;
  logger: Logger;
  transportDialer?: TransportDialer;
  directDialTimeoutMs?: number;
}): ITransportSelector {
  const { env, logger, transportDialer, directDialTimeoutMs } = opts;
  if (!isProductionVariant(env)) {
    return new LocalTransportSelectorStub();
  }
  if (!transportDialer) {
    throw new Error(
      `CELLO_ENV='${env}' requires a transport dialer (directory/relay-backed) for the ` +
        `transport selector, but none was provided to the daemon composition root. The ` +
        `transport selector cannot dial a counterparty without it — fix the daemon ` +
        `configuration (config.transportDialer) before startup.`,
    );
  }
  return new TransportSelector({ dialer: transportDialer, logger, directDialTimeoutMs });
}

// NOTE (CELLO-M7-TRANSPORT-001): there is no createAutoNatService here. The
// daemon's runtime IAutoNatService is the NodeAutoNatService wrapping the standing
// receiver node — that node is created inside startDaemon (after this composition
// runs), so the AutoNAT service is resolved from SessionNodeManager.
// getStandingReceiverAutoNat() rather than constructed in the composition root.
// config.autoNatService remains an explicit test override.
