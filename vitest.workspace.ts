import { defineWorkspace } from "vitest/config";

export default defineWorkspace([
  "core/protocol-types",
  "core/crypto",
  "core/transport",
  "core/test-fixtures",
  "core/adapter-claude-code",
  // daemon + cli were missing since REPOSPLIT-002 — the root `pnpm run test` (and therefore
  // CI's Test step) silently skipped both suites. Their tests are self-contained
  // (127.0.0.1 libp2p, tmpdir SQLite) and must gate every publish.
  "core/daemon",
  "core/cli",
  "core/gateway",
]);
