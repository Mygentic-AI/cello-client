# NIST ACVP known-answer vectors — vendored, trimmed

Source: https://github.com/usnistgov/ACVP-Server, commit
`975de31eb83d87039ec88934fdc47d8c312b892d`, directory `gen-val/json-files/`, file
`internalProjection.json` in each of the four folders below.

Trimming: only the groups listed are kept, and within each test only the fields the tests read.
Every kept value is byte-for-byte the upstream value; nothing is regenerated.

| File | Upstream folder | Groups kept | Fields kept |
|---|---|---|---|
| `ML-KEM-keyGen-FIPS203.json` | `ML-KEM-keyGen-FIPS203` | `tgId 2` (ML-KEM-768, AFT, 25) | `tcId d z ek` |
| `ML-KEM-encapDecap-FIPS203.json` | `ML-KEM-encapDecap-FIPS203` | `tgId 5` (ML-KEM-768 decapsulation VAL, 10); `tgId 10` (ML-KEM-768 encapsulationKeyCheck, 10) | `tcId dk c k reason`; `tcId testPassed ek reason` |
| `ML-DSA-keyGen-FIPS204.json` | `ML-DSA-keyGen-FIPS204` | `tgId 1` (ML-DSA-44, AFT, 25) | `tcId seed pk` |
| `ML-DSA-sigVer-FIPS204.json` | `ML-DSA-sigVer-FIPS204` | `tgId 1` (ML-DSA-44, external, pure, 15) | `tcId testPassed pk message context signature reason` |

Group-level metadata (`tgId`, `testType`, `parameterSet`, `function`, `signatureInterface`, `preHash`)
is kept as upstream.
