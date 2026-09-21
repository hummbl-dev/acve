# ACVE — Agentic Configuration Vulnerability Enumeration

A CVE-style registry format for **resolved AI agent configurations** — not
just components, but the composed unit: harness + model + goal + tools +
permissions + policy.

```
agent contract (package.json)  ->  agent-lock (package-lock.json)  ->  ACVE record (CVE entry)
   declares intent                  what actually resolved             "configs shaped like X
                                                                         are vulnerable to Y"
```

Zero dependencies. Python 3.11+ stdlib only. Everything here runs offline.

## Quick start

```bash
# validate a lockfile or record against its schema
python -m acve validate examples/agent-lock.example.json agent-lock
python -m acve validate records/ACVE-2026-00001.json agent-vulnerability

# compute (or verify) a lockfile's unit identity
python -m acve hash examples/agent-lock.example.json --verify

# is a deployment affected by anything in the registry?
python -m acve match examples/agent-lock.example.json records/
python -m acve match examples/agent-lock.example.json examples/feed.example.jsonl

# build the JSONL feed (validates every record as a side effect)
python -m acve build-feed records -o dist/feed.jsonl
```

## The pieces

| File | What it is |
|------|-----------|
| `schemas/agent-lock.schema.json` | The resolved configuration unit — the "package-lock.json for agents" |
| `schemas/agent-vulnerability.schema.json` | The AVR record — the CVE-style advisory unit (JSONL feed) |
| `records/ACVE-*.json` | The registry: one file per record, git-diffable, PR-per-advisory |
| `acve/` | Stdlib-only implementation: schema-subset validator, JCS canonicalizer + `config_sha256`, affected-matcher, feed builder |
| `SPEC.md` | Semantics: unit identity, versioning discipline, matching rules, prior-art landscape |
| `examples/` | A complete example lockfile + a 2-record example feed |

## What's different here

Existing systems name *components* or *behaviors*: CVE names a product+version,
AVE names a behavioral class of agentic component, a BOM lists inventory.
ACVE adds the missing layer — the **resolved configuration** as a
first-class, hash-addressed object:

- `provenance.config_sha256` — SHA-256 of the canonical lockfile = the unit
  identity. Two deployments with the same hash are the same configuration.
- `affected[].unit: "configuration"` — vulnerability records can express
  *predicates over the composition* ("unrestricted exec AND floating model
  pin AND code-editing goal"), not just version ranges. This is the
  lethal-trifecta pattern: the vulnerability lives in the wiring.
- `model.pin` + `window` — hosted model identity is temporal; the schema
  makes the pin discipline (`weights`/`snapshot`/`alias`/`floating`)
  explicit instead of pretending `version` means one thing.

See `SPEC.md` §Prior art for the full landscape (AVE, AVID, AIVSS, CVE AI
WG, agent-bom, SPDX/CycloneDX AI profiles) and exactly what's uncovered.

## Conventions

- One record per file under `records/`, named `ACVE-YYYY-NNNN.json`.
  Reviewable in git; feed.jsonl is a build artifact.
- `ACVE-` is this registry's namespace — `CVE-` belongs to MITRE; foreign
  IDs go in `aliases`.
- Schemas are SemVer-frozen; breaking changes bump the format version
  (`agent-lock/1.0.0`, `avr/1.0.0`).
- Records are data, not code: `database_specific` holds extensions.

## Testing

```bash
python -m unittest discover -s tests -v   # 14 tests, zero deps
```

## License

Apache-2.0 — see LICENSE.
