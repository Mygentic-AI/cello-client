import type { KeyProvider } from "@cello-protocol/crypto";
import type { ChannelEpochSealer } from "./channel-epoch-sealer.js";
import type { ChannelEpochSealStore } from "./channel-epoch-seal-store.js";
import type { ChannelLogStore } from "./channel-log-store.js";
import type { IpcHandler } from "./ipc-server.js";
import type { DaemonDatabase } from "./sqlcipher-db.js";
import type { Logger } from "./types.js";

export const SEAL_REQUEST_WINDOW_MS = 60 * 60 * 1000;

export type SealRequestOutcome =
  | { honored: true; epoch_index: number; epoch_root: Uint8Array; leaf_count: number }
  | { honored: false; reason: "rate_limited"; latest_epoch_index: number | null; latest_epoch_root: Uint8Array | null; retry_after_ms: number }
  | { honored: false; reason: "epoch_empty"; latest_epoch_index: number | null; latest_epoch_root: Uint8Array | null }
  | { honored: false; reason: "channel_unknown" | "key_unavailable" };

export class ChannelSealRequestGate {
  constructor(_deps: { sealer: ChannelEpochSealer; sealStore: ChannelEpochSealStore; logger: Logger; now: () => number }) {}

  requestSeal(_channelPubkeyHex: string, _requester: string, _correlationId: string): Promise<SealRequestOutcome> {
    throw new Error("not implemented");
  }
}

export interface ChannelSealHandlerDeps {
  handlers: Map<string, IpcHandler>;
  logger: Logger;
  sessionNodeManager: { getDb(): DaemonDatabase; getChannelLogStore(): ChannelLogStore };
  getKeyProvider: (agentName: string) => KeyProvider | undefined;
  now?: () => number;
}

export function registerChannelSealHandler(_deps: ChannelSealHandlerDeps): void {
  throw new Error("not implemented");
}
