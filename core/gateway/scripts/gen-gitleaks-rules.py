import tomllib, json, sys

with open("/tmp/gitleaks_m9.toml","rb") as f:
    data = tomllib.load(f)

rules = []
for r in data.get("rules", []):
    rules.append({
        "id": r["id"],
        "regex": r.get("regex",""),
        "keywords": [k.lower() for k in r.get("keywords",[])],
        "entropy": r.get("entropy", 0),
    })

al = data.get("allowlist", {}) or {}
# value-level false-positive suppression (NOT the git file-path list, which is irrelevant to message text)
stopwords = [s for s in al.get("stopwords", [])]
allow_regexes = [s for s in al.get("regexes", [])]

# stats
no_keyword = sum(1 for r in rules if not r["keywords"])
with_entropy = sum(1 for r in rules if r["entropy"])
print(f"# rules={len(rules)} no_keyword={no_keyword} with_entropy={with_entropy} stopwords={len(stopwords)} allow_regexes={len(allow_regexes)}", file=sys.stderr)

out = []
out.append("/**")
out.append(" * GENERATED from gitleaks' canonical config (github.com/gitleaks/gitleaks, MIT) — the full")
out.append(" * 222-detector secret dictionary. Do not hand-edit; regenerate from config/gitleaks.toml.")
out.append(" * File-path allowlists are dropped (CELLO scans message TEXT, not git files); the value-level")
out.append(" * stopwords + allow-regexes are kept for the false-positive layer (M9-OUT-001 AC-003).")
out.append(" */")
out.append("export interface GitleaksRule { id: string; regex: string; keywords: string[]; entropy: number }")
out.append("")
out.append("export const GITLEAKS_RULES: GitleaksRule[] = [")
for r in rules:
    out.append("  { id: %s, regex: %s, keywords: %s, entropy: %s }," % (
        json.dumps(r["id"]), json.dumps(r["regex"]), json.dumps(r["keywords"]), json.dumps(r["entropy"])
    ))
out.append("];")
out.append("")
out.append("/** Value-level stopwords: if a candidate secret contains one of these, it is a false positive. */")
out.append("export const GITLEAKS_STOPWORDS: string[] = %s;" % json.dumps(stopwords))
out.append("")
out.append("/** Value-level allow regexes: a candidate matching one of these is NOT a secret. */")
out.append("export const GITLEAKS_ALLOW_REGEXES: string[] = %s;" % json.dumps(allow_regexes))
out.append("")
print("\n".join(out))
