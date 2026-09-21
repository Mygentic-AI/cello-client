/**
 * The classifier's score and its provenance, flattened for a daemon log line.
 *
 * Why it exists: on 2026-09-21 an ordinary "got your message" arrived wrapped in a FLAGGED warning
 * and a plain "send it again in different words" was blocked outright, and the daemon log recorded
 * only the outcome — `inbound_injection_blocked` and nothing else. Finding out why took a hand-built
 * offline harness, which is how it emerged that the text being scored was the sender's words PLUS
 * the `[[OVER]]` turn marker CELLO itself appends. Every number an operator needed was computed and
 * then discarded. These fields are that evidence, on the two lines that carry a screening outcome.
 *
 * Flattened rather than nested so `grep score=` and a structured log query both reach it, and a hash
 * + length rather than the text: this goes to a log file, and the conversation stays with its
 * participants. To test a suspected input, sha256 its UTF-8 bytes and compare `copySha256`.
 */
import type { InjectionScanDetail } from "@cello-protocol/gateway";

/**
 * Returns `{}` when no scan ran, and that is the load-bearing half: a message Layer 2 never saw must
 * not acquire a `score: 0`, which reads as "the model looked at it and cleared it". Absent and clean
 * are different facts.
 */
export function scanFields(scan: InjectionScanDetail | undefined): Record<string, unknown> {
  if (scan === undefined) return {};
  return {
    probability: scan.probability,
    score: scan.score,
    verdict: scan.verdict,
    copy: scan.copy,
    copyBytes: scan.copyBytes,
    copySha256: scan.copySha256,
    copiesScanned: scan.copiesScanned,
    ...(scan.degraded !== undefined ? { scanDegraded: scan.degraded } : {}),
    signalMarker: scan.signalMarker,
  };
}
