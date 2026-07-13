/**
 * Test fixture process: take the singleton lock, hold it briefly, release it, exit.
 *
 * This exists to reproduce the ONE thing that cannot be reproduced in-process: a transient holder.
 * `probeSingletonLock` is a writer — it takes the exclusive lock for the millisecond or two it needs
 * to open the file and write the header, then drops it. A daemon whose own acquisition refuses to wait
 * would be killed by that, and would blame a daemon that does not exist.
 *
 * It has to be a separate PROCESS. SQLite's busy handler sleeps inside the native call, so an
 * in-process "hold, then release on a timer" would block the very event loop that has to fire the
 * timer — the release could never happen and the test would deadlock instead of testing anything.
 *
 * Usage: node --import tsx hold-singleton-lock.ts <celloDir> <holdMs>
 * Prints "held" once the lock is taken, then "released" on the way out.
 */

import { acquireSingletonLock } from "../../singleton-lock.js";
import type { Logger } from "../../types.js";

const silent: Logger = { debug() {}, info() {}, warn() {}, error() {} };

const celloDir = process.argv[2];
const holdMs = Number(process.argv[3]);

const lock = acquireSingletonLock(celloDir, silent);
process.stdout.write("held\n");

setTimeout(() => {
  lock.release();
  process.stdout.write("released\n");
  process.exit(0);
}, holdMs);
