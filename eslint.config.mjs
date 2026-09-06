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
      // ─── THE RATCHET (036-GODFILE) — a file this big stops being reviewable ────────────────────
      //
      // WHY A CEILING AT ALL, because the argument is a measurement and not a preference. In
      // mid-July nine commits took `daemon.ts` apart, from ~6.5k lines to 2,081 on 14 July. It is
      // 6,080 today — fully regrown in under two months, because nothing stood in the way. A split
      // with no ratchet behind it buys about six weeks. This rule is what stands in the way.
      //
      // 3,000 IS MEASURED, NOT CHOSEN. The largest production file that is not grandfathered below
      // is `document-handlers.ts` at 2,415, so 3,000 is a real cap with working headroom rather
      // than a number that fits whatever exists. It sits deliberately BELOW 036-GODFILE's own
      // 4,000 pass bar, so the target of that split lands inside the ordinary ceiling instead of
      // needing a permanent exemption. No test file exceeds it either (largest: 2,248), so tests
      // are covered by the same rule — one mechanism, per the pattern this file already follows.
      //
      // ⚠️ COMMENTS AND BLANK LINES COUNT, AND THAT IS THE DELIBERATE TRADE. `skipComments` is
      // tempting here: half of `session-node-manager.ts` is prose, that prose is an asset, and this
      // rule charges for it. It stays off anyway, because the status line for the split is
      // `wc -l` — if the rule counted a different number than the command everyone runs, the two
      // would disagree at exactly the moment someone is deciding whether a file passed. One
      // measure. If a file is genuinely large because of load-bearing prose, split it into modules
      // that each carry their own prose; that is the outcome this rule is for.
      "max-lines": ["error", { max: 3000, skipBlankLines: false, skipComments: false }],
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
    // (The two gateway stores left this list on 2026-07-29 — DOD-M9B-STORE-1 gave core/gateway its
    // own SQLCipher opener, keyed by the daemon's key file, so neither store can write plaintext.)
    files: [
      "core/daemon/src/identity-migration.ts",
    ],
    rules: { "no-restricted-imports": "off" },
  },
  {
    // ─── GRANDFATHERED SIZE — TWO ENTRIES, AND BOTH ONLY EVER SHRINK ───────────────────────────
    //
    // Same contract as the KNOWN DEBT list above: a visible allowlist, no second mechanism, and a
    // number that is never raised. Raising one of these is not a fix; it is the regrowth this rule
    // exists to catch, spelled with a config change.
    //
    //   - session-node-manager.ts — 036-GODFILE's subject. LOWER THIS NUMBER AFTER EVERY PART
    //       LANDS. The rule is what holds the ground each part takes: without it the file can drift
    //       back between parts and nothing notices. When the split is finished the number is set to
    //       the final size, which is below the ordinary 3,000 ceiling — so this entry ends up
    //       STRICTER than the default, which is the point of a ratchet.
    //   - daemon.ts — OWED, and explicitly not 036-GODFILE's work. It needs the same treatment for
    //       the same reason: it is the file that already proved a split without a ratchet does not
    //       hold. It is grandfathered here only so this rule can land today instead of waiting on a
    //       second refactor. (`directory-node.ts`, ~7.4k lines, is the third of these and lives in
    //       the trustless-cello repo, outside this config's reach — no gate here keeps a precise
    //       count of it true, so it is deliberately given as a magnitude rather than a figure that
    //       silently rots.)
    files: ["core/daemon/src/session-node-manager.ts"],
    rules: { "max-lines": ["error", { max: 14759, skipBlankLines: false, skipComments: false }] },
  },
  {
    files: ["core/daemon/src/daemon.ts"],
    rules: { "max-lines": ["error", { max: 6080, skipBlankLines: false, skipComments: false }] },
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
