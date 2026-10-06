import { describe, it, expect } from "vitest";
import { getDaemonIpcEndpoint, getGatewayIpcEndpoint } from "../ipc-endpoint.js";

describe("ipc-endpoint resolution", () => {
  it("returns Unix domain socket paths on POSIX platforms (linux and darwin)", () => {
    const celloDir = "/Users/test/.cello";
    expect(getDaemonIpcEndpoint(celloDir, "linux")).toBe("/Users/test/.cello/daemon.sock");
    expect(getGatewayIpcEndpoint(celloDir, "linux")).toBe("/Users/test/.cello/gateway.sock");

    expect(getDaemonIpcEndpoint(celloDir, "darwin")).toBe("/Users/test/.cello/daemon.sock");
    expect(getGatewayIpcEndpoint(celloDir, "darwin")).toBe("/Users/test/.cello/gateway.sock");
  });

  it("produces valid Windows Named Pipe endpoints matching regex format", () => {
    const dir = "C:\\Users\\test\\.cello";
    const daemonEp = getDaemonIpcEndpoint(dir, "win32");
    const gatewayEp = getGatewayIpcEndpoint(dir, "win32");

    expect(daemonEp).toMatch(/^\\\\\.\\pipe\\cello-[a-f0-9]{12}-daemon$/);
    expect(gatewayEp).toMatch(/^\\\\\.\\pipe\\cello-[a-f0-9]{12}-gateway$/);
  });

  it("canonicalizes Windows paths so casing and slashes produce identical pipe names", () => {
    const ep1 = getDaemonIpcEndpoint("c:\\users\\test\\.cello", "win32");
    const ep2 = getDaemonIpcEndpoint("C:\\USERS\\TEST\\.CELLO", "win32");
    const ep3 = getDaemonIpcEndpoint("C:/users/test/.cello", "win32");

    expect(ep1).toBe(ep2);
    expect(ep2).toBe(ep3);
  });

  it("produces distinct pipe names for distinct directories", () => {
    const epA = getDaemonIpcEndpoint("C:\\Users\\alice\\.cello", "win32");
    const epB = getDaemonIpcEndpoint("C:\\Users\\bob\\.cello", "win32");

    expect(epA).not.toBe(epB);
  });
});
