/**
 * Unit 5: `cello_attestations_issued` top-level domain error semantics (`reason` and `guidance`).
 *
 * Every CELLO MCP tool returns `{ ok: false, reason, guidance }` at the top level when a daemon
 * IPC call fails. `cello_attestations_issued` fans out to two IPC verbs (`wallet_list_issued` and
 * `wallet_fetch_results`) and surfaces the primary failure `reason` and `guidance` at the top level
 * alongside per-call `issued_error` / `results_error`.
 *
 * Clauses verified here:
 *   1. When both `wallet_list_issued` and `wallet_fetch_results` succeed (`ok: true`), the tool
 *      returns `ok: true`, merges outcomes by `submission_id` (defaulting to `"pending"`), and
 *      omits `reason`, `guidance`, `issued_error`, and `results_error`.
 *   2. When `wallet_list_issued` fails (`ok: false`), the tool surfaces `issued.reason` and
 *      `issued.guidance` at the top level alongside `issued_error` (and when both fail, `issued`
 *      takes precedence as the primary local prerequisite while `results_error` is also retained).
 *   3. When `wallet_list_issued` succeeds (`ok: true`) and `wallet_fetch_results` fails (`ok: false`),
 *      the tool surfaces `fetched.reason` and `fetched.guidance` at the top level alongside
 *      `results_error` while still returning the local `submissions` and `in_flight` lists.
 *   4. The MCP tool envelope does not set transport-level `isError: true` on domain `{ ok: false }`
 *      responses.
 */

import { describe, it, expect } from "vitest";
import { registerCelloTools, type ToolProxy, type ToolSink } from "../cello-tools.js";

type ToolHandler = (args: Record<string, unknown>) => Promise<{
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}>;

function captureToolHandler(toolName: string, proxy: ToolProxy): ToolHandler {
  let captured: ToolHandler | undefined;
  const sink: ToolSink = {
    tool: ((name: string, _desc: string, _schema: unknown, handler: ToolHandler) => {
      if (name === toolName) {
        captured = handler;
      }
    }) as unknown as ToolSink["tool"],
  };
  registerCelloTools(sink, proxy);
  if (!captured) {
    throw new Error(`Tool ${toolName} was not registered`);
  }
  return captured;
}

describe("cello_attestations_issued error semantics", () => {
  it("1. returns ok: true with merged submissions and no error fields when both IPC calls succeed", async () => {
    const proxy: ToolProxy = {
      async call(method: string) {
        if (method === "wallet_list_issued") {
          return {
            ok: true,
            issued: [
              { submission_id: "sub-1", subject_pubkey: "aa".repeat(32) },
              { submission_id: "sub-2", subject_pubkey: "bb".repeat(32) },
            ],
            in_flight: [{ submission_id: "sub-3", delivery: "retrying" }],
          };
        }
        if (method === "wallet_fetch_results") {
          return {
            ok: true,
            results: [{ submission_id: "sub-1", outcome: "minted", signal_hash: "cc".repeat(32) }],
            unreachable_nodes: ["gcp-euw1"],
          };
        }
        throw new Error(`Unexpected method: ${method}`);
      },
    };

    const handler = captureToolHandler("cello_attestations_issued", proxy);
    const res = await handler({});
    expect(res.isError).toBeUndefined();
    const payload = JSON.parse(res.content[0]!.text) as Record<string, unknown>;

    expect(payload).toEqual({
      ok: true,
      submissions: [
        { submission_id: "sub-1", subject_pubkey: "aa".repeat(32), outcome: "minted", signal_hash: "cc".repeat(32) },
        { submission_id: "sub-2", subject_pubkey: "bb".repeat(32), outcome: "pending" },
      ],
      in_flight: [{ submission_id: "sub-3", delivery: "retrying" }],
      unreachable_nodes: ["gcp-euw1"],
    });
    expect("reason" in payload).toBe(false);
    expect("guidance" in payload).toBe(false);
  });

  it("2. surfaces top-level reason and guidance when wallet_list_issued fails (both alone and on dual failure with distinct reasons)", async () => {
    const issuedErr = {
      ok: false,
      reason: "no_current_agent",
      guidance: "No agent is selected on this connection. Call cello_use_agent first.",
    };
    const fetchedErr = {
      ok: false,
      reason: "directory_unreachable",
      guidance: "Check cello_status and retry when a directory node is reachable.",
    };

    // Case A: only wallet_list_issued fails (results_error must be omitted).
    const singleFailProxy: ToolProxy = {
      async call(method: string) {
        if (method === "wallet_list_issued") return issuedErr;
        if (method === "wallet_fetch_results") return { ok: true, results: [], unreachable_nodes: [] };
        throw new Error(`Unexpected method: ${method}`);
      },
    };
    const singleHandler = captureToolHandler("cello_attestations_issued", singleFailProxy);
    const singleRes = await singleHandler({});
    expect(singleRes.isError).toBeUndefined();
    const singlePayload = JSON.parse(singleRes.content[0]!.text) as Record<string, unknown>;
    expect(singlePayload["ok"]).toBe(false);
    expect(singlePayload["reason"]).toBe("no_current_agent");
    expect(singlePayload["guidance"]).toBe("No agent is selected on this connection. Call cello_use_agent first.");
    expect(singlePayload["issued_error"]).toEqual(issuedErr);
    expect(singlePayload["results_error"]).toBeUndefined();

    // Case B: both fail with distinct reasons -> issued takes precedence at top level, both error objects retained.
    const dualFailProxy: ToolProxy = {
      async call(method: string) {
        if (method === "wallet_list_issued") return issuedErr;
        if (method === "wallet_fetch_results") return fetchedErr;
        throw new Error(`Unexpected method: ${method}`);
      },
    };

    const handler = captureToolHandler("cello_attestations_issued", dualFailProxy);
    const res = await handler({});
    expect(res.isError).toBeUndefined();
    const payload = JSON.parse(res.content[0]!.text) as Record<string, unknown>;

    expect(payload["ok"]).toBe(false);
    expect(payload["reason"]).toBe("no_current_agent");
    expect(payload["guidance"]).toBe("No agent is selected on this connection. Call cello_use_agent first.");
    expect(payload["issued_error"]).toEqual(issuedErr);
    expect(payload["results_error"]).toEqual(fetchedErr);
  });

  it("3. surfaces top-level reason and guidance from wallet_fetch_results when only the network sweep fails, while preserving local submissions", async () => {
    const fetchedErr = {
      ok: false,
      reason: "directory_unreachable",
      guidance: "Check cello_status and retry when a directory node is reachable.",
    };

    const proxy: ToolProxy = {
      async call(method: string) {
        if (method === "wallet_list_issued") {
          return {
            ok: true,
            issued: [{ submission_id: "sub-local", subject_pubkey: "dd".repeat(32) }],
            in_flight: [{ submission_id: "sub-retry", delivery: "retrying" }],
          };
        }
        if (method === "wallet_fetch_results") return fetchedErr;
        throw new Error(`Unexpected method: ${method}`);
      },
    };

    const handler = captureToolHandler("cello_attestations_issued", proxy);
    const res = await handler({});
    expect(res.isError).toBeUndefined();
    const payload = JSON.parse(res.content[0]!.text) as Record<string, unknown>;

    expect(payload["ok"]).toBe(false);
    expect(payload["reason"]).toBe("directory_unreachable");
    expect(payload["guidance"]).toBe("Check cello_status and retry when a directory node is reachable.");
    expect(payload["issued_error"]).toBeUndefined();
    expect(payload["results_error"]).toEqual(fetchedErr);
    expect(payload["submissions"]).toEqual([
      { submission_id: "sub-local", subject_pubkey: "dd".repeat(32), outcome: "pending" },
    ]);
    expect(payload["in_flight"]).toEqual([{ submission_id: "sub-retry", delivery: "retrying" }]);
  });
});
