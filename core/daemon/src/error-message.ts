/**
 * Extract a real message from a thrown value. libp2p / cross-package errors are not
 * always `instanceof Error` in this realm (multi-version split), so fall back to a
 * `message` property or JSON — never the useless "[object Object]".
 */
export function extractErrorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (err && typeof err === "object" && typeof (err as { message?: unknown }).message === "string") {
    return (err as { message: string }).message;
  }
  try {
    return JSON.stringify(err);
  } catch {
    return String(err);
  }
}
