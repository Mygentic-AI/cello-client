/** Small helpers shared by the stdio and HTTP MCP entrypoints. */

export function jsonText(value: unknown): { content: [{ type: "text"; text: string }] } {
  return { content: [{ type: "text" as const, text: JSON.stringify(value) }] };
}

// Structured diagnostics. The shims hold no injected logger (they are thin proxies), so they write
// `domain.noun.verb` events as JSON to stderr — never console.log.
export type LogFn = (event: string, context?: Record<string, unknown>) => void;

export function logEvent(event: string, context: Record<string, unknown> = {}): void {
  process.stderr.write(JSON.stringify({ event, ...context }) + "\n");
}
