/**
 * DOD-M15-CI-SKIPS-SILENT-1 — say what did not run, where the reader actually looks.
 *
 * Ported from trustless-cello, where the same reporter closes the same defect. Here the gated
 * suites are the live-transport ones (`CELLO_E2E_LIVE`) rather than the Postgres ones, and the
 * stakes differ in one specific way: this repo's CI genuinely runs `pnpm run test`, and its green
 * result gates a publish. A skip whose reason is invisible is indistinguishable from a pass — and
 * here that pass ships a package.
 *
 * WHAT THIS DELIBERATELY DOES NOT DO: fail the run. The sibling repo's guard fails in CI when its
 * suites are inert, which is safe there precisely because nothing automated runs its gate. Turning
 * the same thing on here would red this pipeline on the next push and block publishing — that is a
 * change to release behaviour, not a visibility fix, and it is a separate decision from this one.
 * Visibility first; the hard fail is one line away whenever it is wanted.
 *
 * ─── Why a reporter and not a test ─────────────────────────────────────────────────────────────
 *
 * The first attempt announced this from inside a test with `console.warn`. Measured, it landed
 * 4,851 lines before the end of a 22,418-line run, wedged between transport logs — technically in
 * the output and functionally invisible, because the operator reads the last ten lines. Moving it to
 * a `process.on("exit")` handler did not help either: tests run in worker processes, so the handler
 * fired in a worker and never reached the terminal the summary is printed to.
 *
 * A reporter runs in the MAIN process and `onFinished` is called with the completed run, which is
 * the only place that is both after the results and in front of the person reading them.
 *
 * ─── What it counts ────────────────────────────────────────────────────────────────────────────
 *
 * Vitest's own numbers, not a source scan. The earlier version in the sibling repo derived a count
 * by grepping sources for one skip idiom and reported "64 files skipped" beside vitest's own "38"
 * in the same output — two different measures, one of them claiming authority. A figure the reader
 * cannot reconcile with the line above it is a figure they discount. These are the run's results.
 */

import type { Reporter } from "vitest/node";

interface TaskLike {
  type?: string;
  mode?: string;
  name?: string;
  tasks?: TaskLike[];
  result?: { state?: string };
}

/**
 * Skips and todos counted SEPARATELY, because vitest reports them separately one line above
 * ("595 skipped | 7 todo"). Summing them produced a headline number that matched nothing in the
 * summary it sits under, and a figure the reader cannot reconcile is one they discount.
 */
function countSkipped(
  tasks: TaskLike[] | undefined,
  acc = { skipped: 0, todo: 0 },
): { skipped: number; todo: number } {
  for (const task of tasks ?? []) {
    if (task.type === "test" || task.type === "custom") {
      if (task.mode === "todo") acc.todo++;
      else if (task.mode === "skip" || task.result?.state === "skip") acc.skipped++;
    }
    countSkipped(task.tasks, acc);
  }
  return acc;
}

export default class SkipVisibilityReporter implements Reporter {
  onFinished(files: TaskLike[] = []): void {
    if (process.env["CELLO_E2E_LIVE"]) return;

    const { skipped: skippedTests } = countSkipped(files);
    // A file is fully inert when every test in it was skipped — the ones that read as a green
    // filename in the output while asserting nothing.
    const inertFiles = files.filter((f) => {
      const total = { n: 0 };
      const walk = (ts: TaskLike[] | undefined): void => {
        for (const t of ts ?? []) {
          if (t.type === "test" || t.type === "custom") total.n++;
          walk(t.tasks);
        }
      };
      walk(f.tasks);
      const c = countSkipped(f.tasks);
      return total.n > 0 && c.skipped + c.todo === total.n;
    });

    if (skippedTests === 0) return;

    const line = "─".repeat(78);
    process.stderr.write(
      `\n${line}\n` +
        `NOT EVERYTHING ABOVE RAN. ${skippedTests} tests were skipped, across ${inertFiles.length} files\n` +
        `that asserted nothing at all.\n` +
        `\n` +
        `CELLO_E2E_LIVE is unset, so the live-transport suites did not run. Nothing above asserted\n` +
        `anything about real relay circuits, live signaling reconnection, or NAT reachability —\n` +
        `a green run above is a green run of the unit tests only, and it is what gates a publish.\n` +
        `\n` +
        `  CELLO_E2E_LIVE=1 pnpm run test\n` +
        `${line}\n`,
    );
  }
}
