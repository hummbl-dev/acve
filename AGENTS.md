# AGENTS.md — acve

## Project

**acve** — Agentic Configuration Vulnerability Enumeration. A CVE-style
registry format and zero-dependency tooling for resolved AI agent
configurations (the "package-lock.json" unit for agents + the advisory
record that references it).

## Scope

- In scope: the two schemas (`schemas/`), the stdlib-only toolkit
  (`acve/`), registry records (`records/`), examples, tests, SPEC.md
- Out of scope: a hosted registry service, a scanner/discovery agent
  (lockfile generation lives elsewhere), CVE/AVE/GHSA record sync

## Testing

```bash
python -m unittest discover -s tests -v
```

## Conventions

- Python 3.11+ required
- Zero third-party runtime dependencies (stdlib only) — this is a hard
  invariant; a registry spec must be verifiable with no supply chain
- The validator implements a documented subset of JSON Schema 2020-12;
  schemas MUST stay inside it (type, required, properties, enum, pattern,
  minimum, maximum, minLength, maxLength, minItems, maxItems, items,
  additionalProperties, const, oneOf, anyOf). No `$ref`/`$defs`.
- Schemas are frozen per format version; breaking changes bump the
  `agent-lock/X.Y.Z` / `avr/X.Y.Z` const, never edit in place
- `records/` holds one file per ACVE id; `feed.jsonl` is a build artifact
- Commit format: Conventional Commits (`feat:`, `fix:`, `chore:`, ...)
- Apache-2.0 license
- Never commit secrets, internal hostnames, or private infrastructure
  details — this repo is intended to be publishable
