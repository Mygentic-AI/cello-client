/**
 * CELLO-M7-DAEMON-003 — AC-010: packages/client has no retry/dedup logic
 *
 * This test verifies that after DAEMON-003, the client package contains no
 * retry queue or nonce deduplication state management. All such logic has been
 * moved to the daemon layer.
 *
 * AC-010 interpretation: grep returns zero matches. The grep command is the test.
 */

import { describe, it, expect } from "vitest";
import { execSync } from "node:child_process";
import { join } from "node:path";

describe("AC-010: client package has no retry/dedup logic", () => {
  it("grep for retry/dedup patterns in core/client/src/ returns zero matches", () => {
    const clientSrcDir = join(import.meta.dirname, "../../../client/src");

    let output = "";
    try {
      output = execSync(
        `grep -r "RetryQueue\\|retryQueue\\|seenNonces\\|nonceDedup\\|NonceDedupSet\\|seen_nonces" "${clientSrcDir}" 2>/dev/null || true`,
        { encoding: "utf-8" },
      );
    } catch {
      // grep exits 1 when no match found — that's the success case
      output = "";
    }

    // Zero matches expected
    expect(output.trim()).toBe("");
  });
});
