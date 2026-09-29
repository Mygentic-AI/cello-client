/** A fake CELLO daemon on a real Unix socket: newline-delimited JSON, the IpcProxy wire. */
import { createServer, type Server, type Socket } from "node:net";
import { join } from "node:path";

export const A = "aa".repeat(32);
export const B = "bb".repeat(32);

export interface Rec { method: string; params: Record<string, unknown> | undefined; conn: number }
export interface Fake {
  path: string;
  calls: Rec[];
  closedConns: Set<number>;
  connCount: () => number;
  roster: Array<{ name: string; pubkey: string; state: string }>;
  close(): Promise<void>;
}

export async function fakeDaemon(dir: string): Promise<Fake> {
  const path = join(dir, "daemon.sock");
  const calls: Rec[] = [];
  const closedConns = new Set<number>();
  const sockets: Socket[] = [];
  const fake: Fake = {
    path, calls, closedConns,
    connCount: () => sockets.length,
    roster: [
      { name: "alice", pubkey: A, state: "online" },
      { name: "bob", pubkey: B, state: "online" },
    ],
    close: async () => { for (const s of sockets) s.destroy(); await new Promise<void>((r) => server.close(() => r())); },
  };
  const server: Server = createServer((socket) => {
    const conn = sockets.push(socket);
    let buf = "";
    socket.on("data", (c: Buffer) => {
      buf += c.toString("utf-8");
      let i: number;
      while ((i = buf.indexOf("\n")) !== -1) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1);
        if (!line.trim()) continue;
        const req = JSON.parse(line) as { id: string; method: string; params?: Record<string, unknown> };
        calls.push({ method: req.method, params: req.params, conn });
        const result = req.method === "cello_list_agents" ? { agents: fake.roster } : { ok: true, method: req.method };
        socket.write(JSON.stringify({ id: req.id, result }) + "\n");
      }
    });
    socket.on("close", () => closedConns.add(conn));
    socket.on("error", () => {});
  });
  await new Promise<void>((r) => server.listen(path, () => r()));
  return fake;
}
