/**
 * Side-effect entrypoint imported first by `bin/cello.ts` so `enforceNodeRuntime()` runs before
 * any sibling module in the ESM static import graph is evaluated.
 */

import { enforceNodeRuntime } from "./node-runtime-guard.js";

enforceNodeRuntime();
