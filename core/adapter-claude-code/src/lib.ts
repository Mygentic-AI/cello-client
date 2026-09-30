/**
 * The library surface of `@cello-protocol/connect`, imported as `@cello-protocol/connect/lib`.
 *
 * `@cello-protocol/mcp-http` (repo `Mygentic-AI/cello-mcp-http`) serves these same tools over
 * Streamable HTTP. It registers them through `registerCelloTools`, so its tool names, descriptions
 * and parameters are the stdio shim's by construction, never a copy.
 */
export { registerCelloTools, type ToolSink, type ToolProxy } from "./cello-tools.js";
export { installDaemonGate } from "./daemon-gate.js";
export { forwardDaemonNotifications } from "./channel-forward.js";
export { logEvent, jsonText, type LogFn } from "./shim-log.js";
export { IpcProxy, type IpcProxyOptions, type IpcProxyResult } from "./ipc-proxy.js";
