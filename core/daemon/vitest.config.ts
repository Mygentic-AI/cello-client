import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    // 074-DOCSFLAG: the document layer is behind a flag, and its own suite asserts the flag reached
    // the test process. Without this the daemon's document tests assert verbs that were never
    // registered — three of them have been red for anyone whose shell lacks the variable
    // (found 2026-09-17, DOD-M9C-SCREENINSTALL-1).
    env: { CELLO_DOCUMENTS: "1" },
    include: ["src/**/*.test.ts"],
    testTimeout: 30_000,
    poolOptions: {
      threads: {
        maxThreads: 1,
        minThreads: 1,
      },
    },
  },
});
