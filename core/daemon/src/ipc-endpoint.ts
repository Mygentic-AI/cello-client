/**
 * Cross-platform IPC endpoint resolution for CELLO daemon and security gateway.
 *
 * POSIX systems (macOS, Linux) use Unix domain sockets at `<celloDir>/daemon.sock` and `<celloDir>/gateway.sock`.
 * Windows systems use Windows Named Pipes (`\\\\.\\pipe\\cello-<hash>-daemon` and `\\\\.\\pipe\\cello-<hash>-gateway`).
 *
 * Windows Security / ACL Invariant (SI-001 equivalent):
 * In Node.js / libuv, Named Pipes created via `net.Server.listen('\\\\.\\pipe\\...')` use `CreateNamedPipeW`
 * with default security attributes (pSecurityAttributes = NULL). Under Windows NT access control,
 * this applies the primary access token's default DACL, granting Full Control to the creator/owner
 * (CREATOR_OWNER / current user SID) and local Administrators, and restricting unauthorized local and network
 * callers. This matches the owner-only access invariant enforced by POSIX `chmod 0o600`.
 */
import { createHash } from "node:crypto";
import { win32, posix } from "node:path";

export function getDaemonIpcEndpoint(celloDir: string, platform: NodeJS.Platform = process.platform): string {
  console.log("getDaemonIpcEndpoint called with celloDir:", celloDir, "platform:", platform, "process.platform:", process.platform);
  if (platform === "win32") {
    const canonical = win32.resolve(celloDir).toLowerCase().replace(/\//g, "\\");
    const hash = createHash("sha256").update(canonical).digest("hex").slice(0, 12);
    const result = `\\\\.\\pipe\\cello-${hash}-daemon`;
    console.log("getDaemonIpcEndpoint win32 resolved to:", result);
    return result;
  }
  return posix.join(celloDir, "daemon.sock");
}

export function getGatewayIpcEndpoint(celloDir: string, platform: NodeJS.Platform = process.platform): string {
  if (platform === "win32") {
    const canonical = win32.resolve(celloDir).toLowerCase().replace(/\//g, "\\");
    const hash = createHash("sha256").update(canonical).digest("hex").slice(0, 12);
    return `\\\\.\\pipe\\cello-${hash}-gateway`;
  }
  return posix.join(celloDir, "gateway.sock");
}
