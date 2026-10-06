import { createHash } from "node:crypto";
import { win32, posix } from "node:path";

export function getGatewayIpcEndpoint(celloDir: string, platform: NodeJS.Platform = process.platform): string {
  if (platform === "win32") {
    const canonical = win32.resolve(celloDir).toLowerCase().replace(/\//g, "\\");
    const hash = createHash("sha256").update(canonical).digest("hex").slice(0, 12);
    return `\\\\.\\pipe\\cello-${hash}-gateway`;
  }
  return posix.join(celloDir, "gateway.sock");
}
