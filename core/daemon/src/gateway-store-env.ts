import { join } from "node:path";
import { resolveSessionsDbKey, sessionsDbKeyPath } from "./sqlcipher-db.js";

/**
 * The environment the gateway sidecar needs to open gateway.db, which shares sessions.db's key.
 *
 * The sidecar opens its store at startup, but on a fresh install the key file is only created when
 * the daemon first opens its own database — AFTER the sidecar starts. So the key is resolved here,
 * with the same refusals the daemon applies. The bytes are unused; the child gets the PATH only.
 */
export function prepareGatewayStoreEnv(celloDir: string): { CELLO_GATEWAY_STORE_DB: string; CELLO_GATEWAY_STORE_KEY_FILE: string } {
  const dbPath = join(celloDir, "sessions.db");
  resolveSessionsDbKey(dbPath);
  return { CELLO_GATEWAY_STORE_DB: join(celloDir, "gateway.db"), CELLO_GATEWAY_STORE_KEY_FILE: sessionsDbKeyPath(dbPath) };
}
