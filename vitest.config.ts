import { defineConfig } from "vitest/config";
import SkipVisibilityReporter from "./vitest-skip-reporter.js";

/**
 * DOD-M15-CI-SKIPS-SILENT-1.
 *
 * The project list itself stays in `vitest.workspace.ts` (unchanged). This file exists only to add
 * the reporter that says, after the summary, what did not run — see `vitest-skip-reporter.ts` for
 * why a reporter rather than a test or an exit handler, both of which were tried and are invisible.
 */
export default defineConfig({
  test: {
    reporters: ["default", new SkipVisibilityReporter()],
  },
});
