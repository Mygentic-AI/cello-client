/**
 * Protocol size limits.
 *
 * MAX_CONTENT_BYTES lived in envelope.ts, which was the M6-era MessageEnvelope module — a v0/v1
 * copy-paste pair with zero production consumers (wire encoding moved to Structure1/Structure2 in
 * M7). It was deleted; this constant was its one live export and moved here rather than dying with it.
 */

/** Hard cap on a single message's content, enforced before any encode. 1 MiB. */
export const MAX_CONTENT_BYTES = 1_048_576;
