/** Startup configuration for `cello-mcp-http`: flag parsing, token file, and the loopback test. */

import { statSync, readFileSync } from "node:fs";

export type McpHttpConfigReason =
  | "no_token"
  | "insecure_bind"
  | "tools_empty"
  | "unknown_tool"
  | "agents_empty"
  | "agent_unknown"
  | "daemon_unreachable"
  | "bad_args"
  | "token_file";

export class McpHttpConfigError extends Error {
  constructor(readonly reason: McpHttpConfigReason, message: string) {
    super(message);
    this.name = "McpHttpConfigError";
  }
}

export function isLoopbackHost(host: string): boolean {
  const h = host.toLowerCase();
  return h === "localhost" || h === "::1" || h === "[::1]" || /^127\.\d+\.\d+\.\d+$/.test(h);
}

/** The token file must be private to its owner, and non-empty once trimmed. */
export function readTokenFile(path: string): string {
  let mode: number;
  try {
    mode = statSync(path).mode;
  } catch (e) {
    throw new McpHttpConfigError("token_file", `cannot read token file ${path}: ${e instanceof Error ? e.message : String(e)}`);
  }
  if ((mode & 0o077) !== 0) {
    throw new McpHttpConfigError(
      "token_file",
      `token file ${path} is readable by group or others (mode ${(mode & 0o777).toString(8)}); run: chmod 600 ${path}`,
    );
  }
  const token = readFileSync(path, "utf8").trim();
  if (token === "") throw new McpHttpConfigError("token_file", `token file ${path} is empty`);
  return token;
}

export interface HttpArgs {
  port: number;
  host: string;
  tokenFile?: string;
  agents?: string[];
  toolsFile?: string;
  tlsCert?: string;
  tlsKey?: string;
  maxSessions: number;
  idleTimeoutS: number;
  help: boolean;
}

export const HTTP_USAGE = `cello-mcp-http — the CELLO MCP tools over Streamable HTTP, in front of your own local daemon.

  cello-mcp-http --port <n> --token-file <path> [options]

  --port <n>              port to listen on (required)
  --host <addr>           bind address (default 127.0.0.1); a non-loopback address requires TLS
  --token-file <path>     file holding the bearer token, mode 0600 (or set CELLO_MCP_HTTP_TOKEN)
  --agents a,b,c          serve only these agents (names or pubkeys; at least one; default: all)
  --tools-file <path>     tools to expose: one name per line, '*' for all, '-name' to remove
                          (default: every tool except cello_config_set, cello_settings_set,
                          cello_set_agent_offline, cello_contact_set_tier)
  --tls-cert <path> --tls-key <path>   serve HTTPS directly (otherwise front it with your own TLS)
  --max-sessions <n>      concurrent MCP sessions (default 16)
  --idle-timeout-s <n>    close a session idle this long (default 900)
`;

export function parseHttpArgs(argv: readonly string[]): HttpArgs {
  const out: HttpArgs = { port: NaN, host: "127.0.0.1", maxSessions: 16, idleTimeoutS: 900, help: false };
  const positive = (flag: string, v: string | undefined): number => {
    const n = Number(v);
    if (!Number.isInteger(n) || n < 0) throw new McpHttpConfigError("bad_args", `${flag} needs a whole number, got "${v ?? ""}"`);
    return n;
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    const v = (): string => {
      const next = argv[++i];
      if (next === undefined) throw new McpHttpConfigError("bad_args", `${a} needs a value`);
      return next;
    };
    switch (a) {
      case "--help": case "-h": out.help = true; break;
      case "--port": out.port = positive(a, v()); break;
      case "--host": out.host = v(); break;
      case "--token-file": out.tokenFile = v(); break;
      case "--agents": out.agents = v().split(",").map((s) => s.trim()).filter((s) => s !== ""); break;
      case "--tools-file": out.toolsFile = v(); break;
      case "--tls-cert": out.tlsCert = v(); break;
      case "--tls-key": out.tlsKey = v(); break;
      case "--max-sessions": out.maxSessions = positive(a, v()); break;
      case "--idle-timeout-s": out.idleTimeoutS = positive(a, v()); break;
      default: throw new McpHttpConfigError("bad_args", `unknown option ${a}`);
    }
  }
  if (!out.help && Number.isNaN(out.port)) throw new McpHttpConfigError("bad_args", "--port is required");
  if ((out.tlsCert === undefined) !== (out.tlsKey === undefined)) {
    throw new McpHttpConfigError("bad_args", "--tls-cert and --tls-key go together");
  }
  return out;
}
