/**
 * DOD-CLI-PARITY-1 §3 — the bash-adapter contract.
 *
 * This is what makes `cello` a real programmatic interface rather than a human-only UI: any
 * bash-capable agent can drive a CELLO node with `cello <cmd> | jq` + `$?`, with no MCP dependency.
 *
 * The contract, applied identically by every parity command:
 *  - stdout = the daemon's IPC response as JSON, one object per invocation (compact by default —
 *    scripts and agents are the first-class consumer; `--pretty` for humans).
 *  - exit 0 when the response is ok:true; non-zero otherwise.
 *  - a FAILED response goes to stderr, VERBATIM — every field the daemon sent (reason, guidance,
 *    and extras like the read-before-write cursor) survives untouched, and stdout stays EMPTY so a
 *    piping script can never mistake an error body for a result.
 *
 * The verbatim rule is the DOD-SENDRAW-1 / DOD-LOGOUT-WAIT-1 lesson at the CLI surface: report the
 * outcome, never the intent. A command that reports success for a failed IPC call is a lie, and
 * absence of ok:true is NOT evidence of success — an unrecognized shape fails loud rather than
 * being optimistically passed off as a result.
 */

export interface EmittedOutput {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export interface EmitOptions {
  /** Human-readable indented JSON. JSON stays the default so scripts come first. */
  pretty?: boolean;
}

function render(value: unknown, pretty: boolean | undefined): string {
  return pretty ? JSON.stringify(value, null, 2) : JSON.stringify(value);
}

/**
 * Turn a daemon IPC response into the (stdout, stderr, exitCode) triple the contract demands.
 * The response is passed through UNMODIFIED in both directions — this function decides the stream
 * and the exit code, and is never allowed to rewrite, summarize, or invent the body.
 */
export function emitIpcResult(
  result: Record<string, unknown>,
  opts: EmitOptions = {},
): EmittedOutput {
  // The exit code keys on `ok === false`, not on `ok === true`, because the daemon has TWO response
  // conventions and only one of them carries `ok`:
  //   (a) ok-bearing  — { ok: true, … } / { ok: false, reason, guidance }
  //   (b) payload-only — a bare result with NO `ok` at all: cello_list_agents returns { agents: [] },
  //       cello_await_session returns { type: "timeout" | … }.
  // `ok: false` is the daemon's ONE failure convention; a genuine transport/daemon failure THROWS
  // and is handled by the caller as a transport error. So a payload without `ok` is a result, and
  // routing it to stderr would report working commands as broken — `cello agents` would exit 1 on
  // success.
  //
  // This does NOT weaken the no-fabricated-success rule: we never synthesize an ok:true, never
  // rewrite a body, and never swallow an ok:false. We report exactly what the daemon said.
  const failed = result.ok === false;
  if (failed) {
    return { stdout: "", stderr: render(result, opts.pretty), exitCode: 1 };
  }
  return { stdout: render(result, opts.pretty), stderr: "", exitCode: 0 };
}

/**
 * A transport/daemon-level failure (socket unreachable, daemon not running, thrown error) — still
 * a structured, machine-parseable JSON error on stderr, so a bash agent branches on the same shape
 * whether the daemon rejected the call or never received it.
 */
export function emitTransportError(reason: string, guidance: string, opts: EmitOptions = {}): EmittedOutput {
  return {
    stdout: "",
    stderr: render({ ok: false, reason, guidance }, opts.pretty),
    exitCode: 1,
  };
}
