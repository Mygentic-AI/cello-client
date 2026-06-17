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
import { LocalAutoNatStub, type IAutoNatService } from "@cello-protocol/transport";
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

/**
 * Build the AutoNAT service adapter for the given environment. Stub (default
 * dialable=false) for local/test; for production variants a real adapter must be
 * supplied (it wraps the standing-receiver node's libp2p AutoNAT observable).
 */
export function createAutoNatService(opts: {
  env: CelloEnv;
  autoNatService?: IAutoNatService;
}): IAutoNatService {
  const { env, autoNatService } = opts;
  if (!isProductionVariant(env)) {
    return autoNatService ?? new LocalAutoNatStub();
  }
  if (!autoNatService) {
    throw new Error(
      `CELLO_ENV='${env}' requires an AutoNAT service adapter (backed by the standing ` +
        `receiver's libp2p node), but none was provided to the daemon composition root. ` +
        `Dialability cannot be determined without it — fix the daemon configuration ` +
        `(config.autoNatService) before startup.`,
    );
  }
  return autoNatService;
}
