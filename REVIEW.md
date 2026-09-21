# REVIEW — notes for peer review

For grok-build and other reviewers. This file says what to attack.

## What this is

A CVE-style registry for **resolved AI agent configurations** — the composed
unit (harness + model + goal + tools + permissions + policy), not just
components. Two JSON Schemas + a zero-dependency stdlib toolkit +
a registry of records + a matcher that answers "is this deployment affected?"

Prior art is surveyed honestly in SPEC.md §6 — AVE, AVID, AIVSS, the CVE AI
WG, agent-bom, SPDX/CycloneDX AI profiles all exist and cover adjacent
layers. The claimed delta is narrow and specific (see below).

## Load-bearing design claims (attack these)

1. **`config_sha256` is a sound unit identity.** SHA-256 of JCS-canonical
   lockfile minus `provenance`. Ask: is excluding `provenance` the right
   boundary? Should `generated_at`/`generated_by`/`environment` also be
   excluded (they describe *when*, not *what*)? Current choice: they stay
   in the hash — two identical stacks resolved at different times are
   different units. Arguable.
2. **`affected[]` is OR; `require[]` is AND.** Mirrors OSV. Expressive
   enough, or does the AND-only predicate set push too much into
   duplicated entries?
3. **Component mode is faithful to CVE/OSV semantics.** Ranges with
   introduced/fixed/last_affected/limit; versions[] enumeration. GIT
   ranges deliberately un-ordered (no history). Acceptable loss?
4. **`model.pin` is the right abstraction** for hosted-model identity
   (weights/snapshot/alias/floating). Is four levels enough? Is `pin`
   the right name/level vs. putting stability on each component?
5. **Goal is hashed/referenced, never inlined.** Circulation without
   disclosure — but `goal.sha256` also means goal *content* can't be
   matched, only its class/hash. Is `class` enough?
6. **`exists` + `value:false` = absence.** One op carries presence and
   absence; alternative was a separate `absent` op. Picked the flag.
7. **`schema_sha256` on tools is the integrity anchor** for rug-pull
   detection (validated by Invariant's tool pinning). Should it be
   *required* on MCP-kind tools rather than optional?
8. **ACVE- prefix, CVE- forbidden.** Namespace hygiene vs. the risk the
   world converges on a different scheme (AVE- already exists; an ACVE/AVE
   merge or mapping layer may be needed).

## Known weak points (conceded up front — SPEC.md §7 has the full list)

- `lockhash` approximates JCS number serialization with Python `repr`;
  diverges on exotic floats. A real JCS lib is the upgrade path — but that
  adds a dependency to a deliberately zero-dep package.
- Selector filters are field-equality only (`tools[kind=mcp]`); no
  composite per-element conditions.
- No lockfile **producer** — nothing yet generates an agent-lock from a
  live harness (devin-cli, claude-code, cursor). The biggest adoption gap.
- `parameters` allows `additionalProperties: true` — deliberately
  open-ended, but means arbitrary keys flow into the unit hash.
- Schema `$id`s point at `hummbl.dev` — provisional namespace.
- Whether "vulnerable *configuration*" is even the right ontology vs.
  "vulnerable component reachable through a configuration" — the
  predicate mode assumes the former; steelman the latter.

## Convergence surface (parallel workstream)

Another Devin is building toward the same target. The merge points —
the decisions that must agree for the two artifacts to be one registry:

| Decision | This repo's choice |
|----------|-------------------|
| ID scheme | `ACVE-YYYY-NNNN+`; foreign IDs in `aliases` |
| Unit identity | `provenance.config_sha256` = JCS(doc − provenance) |
| Affected model | OR over `affected[]`; entries are `unit: component` or `unit: configuration` |
| Predicate ops | eq, ne, lt, lte, gt, gte, in, exists(+false), pattern, contains |
| Path syntax | dot-path; `[field=value]` selector; `[]` wildcard |
| Record layout | one JSON file per record in `records/`; JSONL feed is a build artifact |
| Validator | stdlib-only subset — no `$ref`, no `$defs`, no `format` semantics |
| Model pinning | `pin` enum: weights / snapshot / alias / floating |

Everything else — field names, file layout, CLI shape — is negotiable.
If the other artifact diverges on a row above, that's the diff to discuss.

## Where things stand

- `git log`: `6fe6074` initial scaffold, local only, no remote.
- Tests: `python -m unittest discover -s tests -v` — 14/14 green.
- Seed record `ACVE-2026-00001` is real (MCP tool-description rug pull on
  unpinned surfaces; refs: Invariant Labs disclosure + mcp-scan).
- The example lockfile is **not** affected by it (its MCP tool is pinned);
  removing `schema_sha256` flips it to affected. That's the matcher
  demonstrating the predicate semantics, not a bug.
