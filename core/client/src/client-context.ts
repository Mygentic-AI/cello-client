/**
 * ClientContext — shared dependency interface for manager classes.
 *
 * Provides access to core infrastructure (node, keyProvider, logger, persistence)
 * without managers needing to know about CelloClientImpl internals.
 */

import type { CelloNode } from "@cello-protocol/transport";
import type { KeyProvider } from "@cello-protocol/crypto";
import type { Logger } from "@cello-protocol/interfaces";
import type { ClientStatePersistence } from "./client-state-persistence.js";

export interface ClientContext {
  readonly node: CelloNode;
  readonly keyProvider: KeyProvider;
  readonly logger: Logger;
  readonly persistence: ClientStatePersistence | null;
  getMyPubkeyHex(): string | null;
  setMyPubkeyHex(hex: string): void;
}
