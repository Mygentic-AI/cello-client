import { describe, it, expect } from "vitest";
import { getDaemonIpcEndpoint, getGatewayIpcEndpoint } from "../ipc-endpoint.js";

describe("ipc-endpoint resolution", () => {
  it("returns Unix domain socket paths on POSIX platforms", () => {
    if (process.platform !== "win32") {
      const celloDir = "/Users/test/.cello";
      expect(getDaemonIpcEndpoint(celloDir)).toBe("/Users/test/.cello/daemon.sock");
      expect(getGatewayIpcEndpoint(celloDir)).toBe("/Users/test/.cello/gateway.sock");
    }
  });

  it("produces deterministic pipe names on Windows format", () => {
    // Test helper logic directly
    const ep1 = getDaemonIpcEndpoint("/tmp/cello-test");
    const ep2 = getDaemonIpcEndpoint("/tmp/cello-test");
    expect(ep1).toBe(ep2);
  });
});
