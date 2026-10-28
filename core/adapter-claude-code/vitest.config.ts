import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    // The document tools are behind CELLO_DOCUMENTS, and the tool-parity audit compares the shim's
    // registered tools with the daemon's vocabulary, which includes them only when the flag is on.
    env: { CELLO_DOCUMENTS: "1" },
    include: ["src/**/*.test.ts"],
    pool: "threads",
    poolOptions: {
      threads: {
        maxThreads: 1,
        minThreads: 1,
      },
    },
  },
});
