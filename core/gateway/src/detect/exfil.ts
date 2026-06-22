/**
 * M9-OUT-003 — outbound exfiltration checks.
 *
 * A compromised LOCAL agent must not be able to smuggle data out, nor signal (via leaked
 * injection artifacts) that it was hijacked. This screens egress content:
 *   - strips invisible/smuggled Unicode (symmetric with the inbound IN-001 strip),
 *   - neutralizes zero-click image-exfil URLs (an image whose URL carries query data),
 *   - redacts high-entropy encoded-payload blobs,
 *   - and BLOCKS outright when the output body carries injection artifacts (role markers /
 *     override phrases) — that is a compromise signal, so the whole message is attacker-controlled.
 *
 * Pure, deterministic, no model/network. All patterns use negated character classes / fixed
 * alternations (linear time — no catastrophic backtracking), so no RE2 engine is required here.
 */
import { stripInvisible, highEntropyTokens } from "./sanitize.js";

export interface ExfilEvent {
  category: "exfil:invisible" | "exfil:image_url" | "exfil:encoded" | "exfil:injection_artifact";
  reason: string;
  detail?: string;
}

export interface ExfilResult {
  /** `block` (output hijacked — do not send), `redact` (cleaned, send the result), or `allow`. */
  disposition: "allow" | "redact" | "block";
  /** The egress-cleaned text (for redact/allow). For block the original is returned (it is not sent). */
  text: string;
  events: ExfilEvent[];
}

// Injection artifacts that, in the agent's OWN output, indicate a hijack. Anchored / fixed
// alternations — linear time. (Inbound STRIPS these; outbound BLOCKS, because their presence in
// output means the message body is attacker-controlled, attack-corpus §3.3.)
const ARTIFACT_PATTERNS: RegExp[] = [
  /\[SYSTEM\]|<\|im_(?:start|end)\|>|<<\/?SYS>>|\[\/?INST\]|<\|system\|>|<\|assistant\|>/i,
  /\b(?:ignore|disregard)\s+(?:all\s+)?(?:your\s+)?previous\s+instructions\b/i,
  /\bforget\s+everything\s+above\b/i,
];
function findInjectionArtifact(text: string): string | null {
  for (const re of ARTIFACT_PATTERNS) {
    const m = re.exec(text);
    if (m) return m[0];
  }
  return null;
}

// A markdown image whose URL carries a query string is a zero-click data-exfil vector (the
// renderer auto-fetches it, sending the query to the attacker). Negated char classes → linear.
const MD_IMAGE = /!\[[^\]]*\]\(([^)\s]+)\)/g;

export function screenOutboundExfil(content: Uint8Array): ExfilResult {
  const events: ExfilEvent[] = [];
  let text = new TextDecoder("utf-8", { fatal: false }).decode(content);

  // 1. Injection artifacts in output → BLOCK the whole message (compromise signal).
  const artifact = findInjectionArtifact(text);
  if (artifact) {
    events.push({
      category: "exfil:injection_artifact",
      reason: "the output body contains an injection artifact, indicating the agent's output was hijacked — message not sent",
      detail: artifact,
    });
    return { disposition: "block", text, events };
  }

  // 2. Egress invisible-Unicode strip (symmetric with M9-IN-001).
  const inv = stripInvisible(text);
  if (inv.removed > 0) {
    events.push({ category: "exfil:invisible", reason: `stripped ${inv.removed} invisible/smuggled codepoint(s) on egress` });
    text = inv.text;
  }

  // 3. Zero-click image-exfil: neutralize data-carrying image URLs; leave ordinary links/images.
  text = text.replace(MD_IMAGE, (whole: string, url: string) => {
    if (url.includes("?")) {
      events.push({ category: "exfil:image_url", reason: "neutralized a data-carrying image URL (zero-click exfil vector)", detail: url });
      return "[image removed: possible data-carrying URL]";
    }
    return whole;
  });

  // 4. High-entropy encoded-payload blobs → redact (SI-001: the raw payload must not be emitted).
  for (const token of highEntropyTokens(text)) {
    events.push({ category: "exfil:encoded", reason: "redacted a high-entropy encoded payload (possible exfiltration)" });
    text = text.split(token).join("[redacted: high-entropy data]");
  }

  return { disposition: events.length > 0 ? "redact" : "allow", text, events };
}
