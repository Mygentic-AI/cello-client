/**
 * Cross-platform IPC endpoint resolution for the CELLO daemon.
 *
 * POSIX systems (macOS, Linux) use Unix domain sockets at `<celloDir>/daemon.sock`.
 * Windows systems use Windows Named Pipes (`\\\\.\\pipe\\cello-<hash>-daemon`).
 */
import { createHash } from "node:crypto";
import { join, resolve, win32 } from "node:path";

export function getDaemonIpcEndpoint(celloDir: string, platform: NodeJS.Platform = process.platform): string {
  if (platform === "win32") {
    const canonical = win32.resolve(celloDir).toLowerCase().replace(/\//g, "\\");
    const hash = createHash("sha256").update(canonical).digest("hex").slice(0, 12);
    return `\\\\.\\pipe\\cello-${hash}-daemon`;
  }
  return join(celloDir, "daemon.sock");
}
