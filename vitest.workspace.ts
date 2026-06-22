import { defineWorkspace } from "vitest/config";

export default defineWorkspace([
  "core/protocol-types",
  "core/crypto",
  "core/transport",
  "core/test-fixtures",
  "core/client",
  "core/adapter-claude-code",
  "core/gateway",
]);
