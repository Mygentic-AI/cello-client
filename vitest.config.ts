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
    /**
     * 074-DOCSFLAG — THE TEST SUITE RUNS WITH THE DOCUMENT LAYER ON. THE SHIPPED DEFAULT IS OFF.
     *
     * Collaborative documents are gated off for operators by `CELLO_DOCUMENTS` (see
     * `core/daemon/src/document-flag.ts`). This is a GATE, NOT A REMOVAL: the code stays, and the
     * order's clause 7 is that **every existing document test passes unchanged with the flag on** —
     * which is the clause that keeps the gate from quietly becoming a deletion. Turning the layer on
     * for the suite is what makes "unchanged" literally true: not one of the twenty-odd existing
     * files that exercise a document verb, a document leaf or the reconcile sweep was edited.
     *
     * ⚠️ SO AN OFF-STATE ASSERTION MUST SET ITS OWN ENVIRONMENT. Reading the ambient value and
     * expecting `off` would pass for the wrong reason here. The three `docsflag-2-*` suites each
     * clear the variable themselves — the daemon suite per `startDaemon`, the CLI suite with
     * `vi.resetModules()` before a dynamic import, the MCP suite in the spawned child's env — and
     * `docsflag-2-suite-env` asserts THIS key actually arrived, because a vitest config key that does
     * not exist is ignored in silence and a poisoned default would pass unnoticed.
     */
    env: { CELLO_DOCUMENTS: "1" },
  },
});
