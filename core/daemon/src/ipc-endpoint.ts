/**
 * Cross-platform IPC endpoint resolution for CELLO daemon and security gateway.
 *
 * POSIX systems (macOS, Linux) use Unix domain sockets at `<celloDir>/daemon.sock` and `<celloDir>/gateway.sock`.
 * Windows systems use Windows Named Pipes (`\\\\.\\pipe\\cello-<hash>-daemon` and `\\\\.\\pipe\\cello-<hash>-gateway`).
 */
import { createHash } from "node:crypto";
import { join, resolve } from "node:path";

export function getDaemonIpcEndpoint(celloDir: string, platform: NodeJS.Platform = process.platform): string {
  if (platform === "win32") {
    const canonical = resolve(celloDir).toLowerCase().replace(/\//g, "\\");
    const hash = createHash("sha256").update(canonical).digest("hex").slice(0, 12);
    return `\\\\.\\pipe\\cello-${hash}-daemon`;
  }
  return join(celloDir, "daemon.sock");
}

export function getGatewayIpcEndpoint(celloDir: string, platform: NodeJS.Platform = process.platform): string {
  if (platform === "win32") {
    const canonical = resolve(celloDir).toLowerCase().replace(/\//g, "\\");
    const hash = createHash("sha256").update(canonical).digest("hex").slice(0, 12);
    return `\\\\.\\pipe\\cello-${hash}-gateway`;
  }
  return join(celloDir, "gateway.sock");
}
