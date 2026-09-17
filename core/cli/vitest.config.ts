import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    // The registry is assembled at import time and omits the `doc` group unless documents are on,
    // so without this three guards assert a command that was never registered — they have been
    // failing locally for anyone whose shell lacks the flag (DOD-M9C-SCREENINSTALL-1, found 2026-09-17).
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
