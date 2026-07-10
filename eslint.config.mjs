import tsPlugin from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";

export default [
  {
    files: ["core/*/src/**/*.ts"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: "module",
      },
    },
    plugins: {
      "@typescript-eslint": tsPlugin,
    },
    rules: {
      ...tsPlugin.configs.recommended.rules,
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      // CELLO uses SQLCipher for local storage. Period. `node:sqlite` writes PLAINTEXT to disk and
      // is an experimental Node builtin, so importing it (a) silently drops encryption-at-rest and
      // (b) makes Node print `ExperimentalWarning: SQLite` on every command, on every Node < 24.
      //
      // It keeps getting added by AI coders reaching for a builtin instead of the project's DB
      // layer. This rule is the stop. Use `openEncryptedDatabase` / `openEncryptedDatabaseAtPath`
      // from `core/daemon/src/sqlcipher-db.ts` — SQLCipher can also open a plaintext file, so there
      // is no legacy-read case that needs `node:sqlite` either.
      "no-restricted-imports": ["error", {
        paths: [{
          name: "node:sqlite",
          message:
            "CELLO uses SQLCipher, never node:sqlite — it stores PLAINTEXT and emits an " +
            "ExperimentalWarning. Use openEncryptedDatabase()/openEncryptedDatabaseAtPath() from " +
            "core/daemon/src/sqlcipher-db.ts. Tests may use it for in-memory fixtures.",
        }],
      }],
      // DOD-SENDRAW-1: the signaling seam's sendRaw NEVER throws — it catches internally and
      // resolves {ok:false, reason} on every failure (transport signaling-manager.ts). A bare
      // `await x.sendRaw(...)` that discards the result therefore reports nothing when the send
      // fails, and the classic `try { await sendRaw(); log("sent") } catch { log("failed") }`
      // lies in BOTH directions: the success line always fires, the failure line never can.
      // This shape shipped four times before the rule (session-ceremony offer accept, the seal
      // FROST signature, the ceremony reply, trust_signal_ack). Branch on the result; the
      // existing no-unused-vars rule catches an assigned-but-ignored result.
      "no-restricted-syntax": ["error", {
        selector: 'ExpressionStatement > AwaitExpression > CallExpression[callee.property.name="sendRaw"]',
        message:
          "sendRaw never throws — it resolves {ok:false, reason}. Discarding the result hides " +
          "every send failure. Branch on it: const res = await ...sendRaw(...); if (!res.ok) " +
          "log the failure with res.reason. (DOD-SENDRAW-1)",
      }],
    },
  },
  {
    // KNOWN DEBT — the only production files still importing node:sqlite. Do not add to this list.
    // When it is empty, delete this block; the debt is paid.
    //   - daemon/identity-migration.ts : reads a legacy PLAINTEXT db to migrate it into SQLCipher.
    //       SQLCipher can open plaintext directly, so this is convertible with no migration risk.
    //   - gateway/records/record-store.ts, gateway/config/config-store.ts : these are PRIMARY
    //       stores, writing hash-chained security records + gateway config UNENCRYPTED to disk.
    //       Their header comments justify this with "the daemon opens node:sqlite without a cipher
    //       key today" — false since 2026-06-25, when the daemon moved to SQLCipher. Converting
    //       them needs sqlcipher-db lifted out of core/daemon (core/gateway cannot import it:
    //       daemon depends on gateway, not the reverse) AND a plaintext→encrypted migration for
    //       existing installs.
    files: [
      "core/daemon/src/identity-migration.ts",
      "core/gateway/src/records/record-store.ts",
      "core/gateway/src/config/config-store.ts",
    ],
    rules: { "no-restricted-imports": "off" },
  },
  {
    files: ["core/*/src/__tests__/**/*.ts"],
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
      // Tests never ship, so an in-memory DatabaseSync fixture reaches no operator.
      "no-restricted-imports": "off",
    },
  },
];
