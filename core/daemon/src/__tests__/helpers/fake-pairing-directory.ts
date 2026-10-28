/**
 * A local HTTP server answering the directory's two pairing routes. Polls are verified for real
 * against the daemon key that opened the pairing, so a wrong signature is refused with 401.
 */
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { pairingPollBytes, verifyDaemonSignature } from "@cello-protocol/crypto";

export type Answer = { status: number; body: unknown };

export interface FakeDirectory {
  base: string;
  pairBodies: Array<Record<string, unknown>>;
  pollBodies: Array<Record<string, unknown>>;
  close(): Promise<void>;
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
}

export async function startFakeDirectory(opts: {
  /** The daemon key the polls must be signed by; defaults to the key that opened the pairing. */
  daemonPubkey?: () => string | undefined;
  onPair?: (body: Record<string, unknown>) => Answer;
  /** Called for a poll whose signature verified; `n` counts verified polls from 0. */
  onPoll?: (body: Record<string, unknown>, n: number) => Answer;
}): Promise<FakeDirectory> {
  const pairBodies: Array<Record<string, unknown>> = [];
  const pollBodies: Array<Record<string, unknown>> = [];
  let verified = 0;
  const server = createServer((req, res) => {
    void (async () => {
      const body = await readJson(req);
      let answer: Answer;
      if (req.url === "/pairing") {
        pairBodies.push(body);
        answer = opts.onPair?.(body) ?? {
          status: 201,
          body: { pairing_code: "KQ7M4TXP", expires_at: new Date(Date.now() + 600_000).toISOString(), approve_url: "https://portal.example.test/device?code=KQ7M-4TXP" },
        };
      } else if (req.url === "/pairing/poll") {
        pollBodies.push(body);
        const key = opts.daemonPubkey?.() ?? (pairBodies[0]?.["daemon_pubkey"] as string | undefined);
        const ok = typeof key === "string"
          && verifyDaemonSignature(pairingPollBytes(String(body["pairing_code"]), Number(body["unix_seconds"])), String(body["signature"]), key);
        answer = ok
          ? (opts.onPoll?.(body, verified++) ?? { status: 200, body: { status: "pending" } })
          : { status: 401, body: { error: "bad_signature", guidance: "sign the poll with the daemon key that opened this pairing" } };
      } else {
        answer = { status: 404, body: { error: "not_found" } };
      }
      res.writeHead(answer.status, { "content-type": "application/json" });
      res.end(JSON.stringify(answer.body));
    })();
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const { port } = server.address() as AddressInfo;
  return {
    base: `http://127.0.0.1:${port}`,
    pairBodies,
    pollBodies,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

/** A base nothing listens on. */
export async function closedPortBase(): Promise<string> {
  const s = createServer();
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", () => r()));
  const { port } = s.address() as AddressInfo;
  await new Promise<void>((r) => s.close(() => r()));
  return `http://127.0.0.1:${port}`;
}
