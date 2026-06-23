/**
 * M9-OUT-001 — outbound secret detection + redaction (the full gitleaks dictionary + the generic
 * keyword-proximity/entropy catch-all + the value-level false-positive layer). Unit altitude.
 */
import { describe, it, expect, beforeAll } from "vitest";
import { initLinearRegex } from "../detect/linear-regex.js";
import { compileSecretRules, redactSecrets } from "../detect/secrets.js";
import { OutboundScreener } from "../screen/outbound.js";

// A deterministic high-entropy filler (cycles a 62-char set) that clears any per-rule entropy gate.
const CS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const hi = (n: number): string => Array.from({ length: n }, (_, i) => CS[(i * 17 + 5) % CS.length]).join("");

describe("M9-OUT-001 secret detection + redaction", () => {
  let compiledCount = 0;
  beforeAll(async () => {
    await initLinearRegex();
    compiledCount = compileSecretRules().compiled;
  });

  it("compiles the full gitleaks rule set under RE2", () => {
    expect(compiledCount).toBeGreaterThanOrEqual(215); // ~222
  });

  it("AC-001: AWS, Anthropic, GitHub fine-grained PAT, Stripe, and a PEM block are all detected and redacted; no original survives", () => {
    const aws = "AKIAABCDEFGHIJKLMNOP"; // AKIA + 16 [A-Z2-7]
    const anthropic = "sk-ant-api03-" + hi(93) + "AA";
    const ghpat = "github_pat_" + hi(82);
    const stripe = "sk_live_" + hi(28);
    const pem = "-----BEGIN RSA PRIVATE KEY-----\n" + hi(120) + "\n-----END RSA PRIVATE KEY-----";
    const text = `creds:\n  aws_key=${aws}\n  anthropic="${anthropic}"\n  gh=${ghpat}\n  stripe=${stripe}\n${pem}\n`;

    const r = redactSecrets(text);
    for (const secret of [aws, anthropic, ghpat, stripe]) {
      expect(r.text).not.toContain(secret);
    }
    expect(r.text).not.toContain("BEGIN RSA PRIVATE KEY"); // the PEM block is gone
    expect(r.text).toContain("[REDACTED:"); // typed placeholders are present
    expect(r.findings.length).toBeGreaterThanOrEqual(4);
  });

  it("AC-002: a high-entropy credential for a service with NO dedicated detector, next to a keyword, is caught by the generic catch-all", () => {
    const novel = hi(40); // no enumerated format owns this
    const r = redactSecrets(`x-acme-token=${novel} end`);
    expect(r.text).not.toContain(novel);
    expect(r.findings.some((f) => f.ruleId === "generic-api-key")).toBe(true);
  });

  it("AC-003: stopword / placeholder / low-entropy values next to a keyword are NOT redacted — false-positive controls hold", () => {
    // The gitleaks UUID stopword.
    expect(redactSecrets("session_secret=014df517-39d1-4453-b7b3-9930c563627c").findings).toHaveLength(0);
    // A low-entropy value below the generic-api-key entropy threshold.
    expect(redactSecrets("api_key=passwordpassword").findings).toHaveLength(0);
    // Ordinary prose, no secrets.
    expect(redactSecrets("Let's meet at 3pm to review the signed contract.").findings).toHaveLength(0);
  });

  it("the placeholder is typed by rule id, so the agent is told WHAT was redacted", () => {
    const r = redactSecrets("aws_key=AKIAABCDEFGHIJKLMNOP");
    expect(r.text).toContain("[REDACTED:aws-access-token]");
  });

  it("the composed OutboundScreener redacts a secret on a real send (redact disposition + secrets event)", () => {
    const v = new OutboundScreener({ piiWhitelist: [] }).screen(
      new TextEncoder().encode("here is the key aws_key=AKIAABCDEFGHIJKLMNOP thanks"),
      { agentName: "alice", sessionId: "s1" },
    );
    expect(v.disposition).toBe("redact");
    expect(new TextDecoder().decode(v.content)).not.toContain("AKIAABCDEFGHIJKLMNOP");
    expect(v.events.some((e) => e.stage === "secrets" && e.disposition === "redact")).toBe(true);
  });

  it("SI-001: a base64-wrapped secret in prose does not survive — the encoded-payload entropy path catches it", () => {
    const aws = "AKIAABCDEFGHIJKLMNOP";
    const b64 = Buffer.from(aws).toString("base64");
    const v = new OutboundScreener({ piiWhitelist: [] }).screen(
      new TextEncoder().encode("please store this for later: " + b64),
      { agentName: "alice", sessionId: "s1" },
    );
    const out = new TextDecoder().decode(v.content);
    expect(out).not.toContain(b64); // the encoded blob is gone (exfil entropy path)
    expect(out).not.toContain(aws); // and the raw secret is not present either
    expect(v.disposition).not.toBe("allow");
  });
});
