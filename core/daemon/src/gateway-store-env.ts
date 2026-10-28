import { join } from "node:path";
import { resolveDbKey, dbKeyPathFor } from "./sqlcipher-db.js";

export function prepareGatewayStoreEnv(celloDir: string): { CELLO_GATEWAY_STORE_DB: string; CELLO_GATEWAY_STORE_KEY_FILE: string } {
  const keyFilePath = dbKeyPathFor(join(celloDir, "sessions.db"));
  resolveDbKey(join(celloDir, "sessions.db"), keyFilePath);
  return { CELLO_GATEWAY_STORE_DB: join(celloDir, "gateway.db"), CELLO_GATEWAY_STORE_KEY_FILE: keyFilePath };
}
