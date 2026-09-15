/**
 * Where a relay is, decided in ONE place.
 *
 * The directory hands this daemon the current relay pool on every signaling connect. Past session
 * rows also carry relay addresses, frozen at whatever the relay advertised when that session began.
 * Those two disagree after any fleet change — on 2026-09-15 a saved row still held the pre-TLS
 * `/ip4/…:4001/ws` address, and the mailbox pull, which read saved rows alone, dialled it 1,904
 * times while three parked messages waited behind it.
 *
 * So the directory's pool comes first, per relay peer id, and saved rows only add relays the
 * directory did not list. Reservation and mailbox pull both use this, so they cannot disagree.
 */
export interface RelayEndpoint {
  relayPeerId: string;
  relayAddrs: string[];
}

export function mergeRelayEndpoints(
  directoryPool: readonly RelayEndpoint[] | undefined,
  persisted: readonly RelayEndpoint[],
): RelayEndpoint[] {
  const merged = new Map<string, RelayEndpoint>();
  for (const ep of [...(directoryPool ?? []), ...persisted]) {
    if (!merged.has(ep.relayPeerId)) merged.set(ep.relayPeerId, ep);
  }
  return [...merged.values()];
}
