import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "cloud-doorbell",
    include: ["*.test.mjs"],
    testTimeout: 10_000,
  },
});
