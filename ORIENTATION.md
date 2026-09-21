# ORIENTATION — for collaborators arriving fresh

~5 minutes. `SPEC.md` is the full design; `REVIEW.md` is the attack
surface; this file is the map between them.

## What ACVE is

A CVE-style registry for **resolved AI agent configurations**. The affected
unit is not a package — it is the conjunction of harness ∧ model ∧ goal ∧
tools ∧ permissions ∧ policy that actually resolved at run time.

Two artifacts:

- `schemas/agent-lock.schema.json` — the lockfile ("package-lock.json for
  an agent"). `provenance.config_sha256` — SHA-256 of the JCS
  canonicalization of the document *minus* `provenance` — is the unit's
  content-addressed identity.
- `schemas/agent-vulnerability.schema.json` — the AVR record. `affected[]`
  entries are either component version ranges (CVE-style) or `require[]`
  predicate clauses over the resolved configuration. A record is an OR of
  entries; an entry's predicates are ANDed.

`acve/` is a zero-dependency stdlib toolkit: schema-subset validator, JCS
canonicalizer + `config_sha256`, the affected-matcher, the feed builder.
`records/` holds one JSON file per ACVE id; `feed.jsonl` is a build
artifact, not hand-edited.

## Why it exists

CVE assigns to software products. AVE fingerprints component *types*. BOMs
inventory what is present. None of them can say "this deployment is exposed
because `exec` + `credential_access` + `network_egress` resolved together
with no human gate" — the toxic-flow / lethal-trifecta shape where the
vulnerability lives in the *combination* and has no package and no version.

`SPEC.md` §6 surveys prior art honestly (AVE, AVID, AIVSS, the CVE AI
Working Group, agent-bom, SPDX/CycloneDX AI profiles). The claimed delta is
narrow on purpose: a content-addressed unit of configuration, predicate
matching over it, and pin-discipline semantics for hosted models.

**Since the spec was drafted**, `pickbitsai/acve` (agentcve.org) shipped a
public registry + `npx @pickbitsai/acve` CLI with OSV-compatible
advisories and living campaign records — the same "layer over CVE, not a
replacement" framing. Whether to converge, interop via `aliases`, or stay
independent is an open strategic question (see open issues).

## What is decided vs. open

Decided and load-bearing (the convergence table in `REVIEW.md` is the
contract):

- `ACVE-YYYY-NNNN+` IDs; foreign IDs live in `aliases`; `CVE-` is never
  minted here
- Unit identity = `config_sha256` of JCS(document − `provenance`)
- `affected[]` is an OR; `require[]` is an AND; predicate ops fixed
  (eq, ne, lt, lte, gt, gte, in, exists(+false), pattern, contains)
- Path syntax: dot-path, `[field=value]` selector, `[]` wildcard
- stdlib-only, schemas frozen per version, one file per record

Open — where external judgment changes the design:

1. **Ontology.** "Vulnerable configuration" vs. "vulnerable component
   reachable through a configuration." The predicate mode assumes the
   former; the steelman for the latter changes what records look like.
2. **`config_sha256` boundary.** `provenance` is excluded;
   `generated_at`/`generated_by`/`environment` stay in the hash — the same
   stack resolved at different times is a different unit. Right call?
3. **`model.pin`.** Four levels (weights / snapshot / alias / floating) for
   hosted-model identity. Enough? Is `pin` the right name vs. stability on
   each component?
4. **Namespace.** `ACVE-` prefix vs. converging on AVE or building a
   mapping layer — AVE already exists, and now pickbitsai does too.
5. **Registry model.** Content-addressed lockfile units (here) vs. a
   hosted canonical registry (pickbitsai's). Orthogonal to the schema but
   shapes everything downstream.

## Known weak points (conceded)

Full list in `SPEC.md` §7. The big ones: JCS `repr` float edge in
`lockhash`; **no lockfile producer yet** — nothing generates an agent-lock
from a live harness, which is the real adoption gap; selector filters are
field-equality only.

## Conventions

- Python 3.11+, **stdlib only** — hard invariant; a registry spec must
  verify with no supply chain.
- Schemas are frozen per format version; breaking changes bump the
  `agent-lock/X.Y.Z` / `avr/X.Y.Z` const, never edit in place.
- `records/`: one file per ACVE id, PR-reviewed; `feed.jsonl` is built.
- Conventional Commits. `python -m unittest discover -s tests -v` must
  stay green — the pre-push hook enforces it.
