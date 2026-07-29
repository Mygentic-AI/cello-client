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
      // Three selectors close the three discard shapes (review F1): awaited-and-discarded,
      // void-wrapped, and bare-floating. sendSignalingFrame is the same contract one layer up
      // (registration-context wraps sendRaw), so it is covered by the same name regex.
      "no-restricted-syntax": ["error", {
        selector: 'ExpressionStatement > AwaitExpression > CallExpression[callee.property.name=/^(sendRaw|sendSignalingFrame)$/]',
        message:
          "sendRaw never throws — it resolves {ok:false, reason}. Discarding the result hides " +
          "every send failure. Branch on it: const res = await ...sendRaw(...); if (!res.ok) " +
          "log the failure with res.reason. (DOD-SENDRAW-1)",
      }, {
        selector: 'ExpressionStatement > UnaryExpression[operator="void"] > CallExpression[callee.property.name=/^(sendRaw|sendSignalingFrame)$/]',
        message:
          "void does not excuse ignoring sendRaw's result — it resolves {ok:false, reason} " +
          "instead of throwing, so this hides every send failure. Branch on the result. " +
          "(DOD-SENDRAW-1)",
      }, {
        selector: 'ExpressionStatement > CallExpression[callee.property.name=/^(sendRaw|sendSignalingFrame)$/]',
        message:
          "Floating sendRaw call — the result ({ok:false, reason} on failure; it never throws) " +
          "is discarded AND unawaited. Await it and branch on the result. (DOD-SENDRAW-1)",
      }],
    },
  },
  {
    // KNOWN DEBT — the only production file still importing node:sqlite. Do not add to this list;
    // it only ever shrinks. When it is empty, delete this block; the debt is paid.
    //   - daemon/identity-migration.ts : reads a legacy PLAINTEXT db to migrate it into SQLCipher.
    //       SQLCipher can open plaintext directly, so this is convertible with no migration risk.
    // (The two gateway stores left this list on 2026-07-29 — DOD-M9C-STORE-1 gave core/gateway its
    // own SQLCipher opener, keyed by the daemon's key file, so neither store can write plaintext.)
    files: [
      "core/daemon/src/identity-migration.ts",
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
  {
    // A duplicate object key silently discards one of the two values. The config spread only
    // carries `tsPlugin.configs.recommended.rules`, NOT `eslint:recommended`, so core rules like
    // this one are off unless named — and a mechanical 58-file edit left 13 duplicate
    // `securityGateway` keys that typecheck and lint both reported clean (M9 review F8). A gate
    // that cannot see the corruption a bulk edit causes is not covering bulk edits.
    files: ["core/*/src/**/*.ts"],
    rules: { "no-dupe-keys": "error" },
  },
];
