# ACVE Specification

**Agentic Configuration Vulnerability Enumeration** — a CVE-style unit for
AI agent configurations. Two artifacts:

| Artifact | Analogy | Schema | Format |
|----------|---------|--------|--------|
| **Agent lockfile** | `package-lock.json` | `schemas/agent-lock.schema.json` | JSON, one per resolved deployment |
| **Agentic Vulnerability Record (AVR)** | CVE entry / OSV record | `schemas/agent-vulnerability.schema.json` | one file per record under `records/`; JSONL feed built from them |

An agent *contract* declares intent (`package.json`). The lockfile records
what actually resolved at run time. The AVR says "configurations shaped
like X are vulnerable to Y" — where X can be a component version range
**or** a predicate over a resolved configuration.

## 1. The unit

`provenance.config_sha256` is the identity of the configuration **unit**:
SHA-256 over the RFC 8785 (JCS) canonicalization of the document with
`provenance` excluded. For JSON containing only ASCII strings, integers,
and ordinary floats, JCS reduces to:

```python
json.dumps(doc_without_provenance, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
```

(`acve.lockhash` implements this.) Two deployments with the same
`config_sha256` are the same configuration; a vulnerability that affects
one affects the other. `transitive_tools_sha256` offers a coarser identity
over just the tool (name, version, schema_sha256) triples.

## 2. "What exact versions?"

Different components pin differently — the schema makes the discipline
explicit rather than pretending `version` means one thing:

- **harness** — `version` + `channel` + `revision` + `purl`;
  `config_sha256` covers the effective settings so two installs at the
  same version but different flags are different units.
- **model** — `pin` declares the identity anchor: `weights`
  (content-addressed; `weights_sha256` required — the only unspoofable
  pin), `snapshot` (dated provider snapshot), `alias` (mutable, e.g.
  `-latest`), `floating` (drifts, unknowable). Hosted models are never
  truly versioned; `pin` says how much confidence a match can have, and
  AVR `window` bounds handle drift.
- **tools** — `version` + `purl` + `server.version` (MCP) +
  `schema_sha256`. The schema hash matters because a tool's callable
  signature can mutate at a constant package version (tool poisoning /
  rug pull — cf. Invariant mcp-scan "Tool Pinning").
- **goal** — `summary` (public-safe) + `sha256`/`ref` (authoritative text
  is hashed or referenced, never inlined) + `class` (whole goal
  categories can be named affected).
- **skills/prompts/policy** — `sha256` of resolved content.
- **parameters** — inference params are part of the unit: identical
  components under different `temperature`/`reasoning_effort` are
  different configurations.

## 3. Matching

A lockfile is affected by an AVR if **any** `affected[]` entry matches.
Implemented in `acve/match.py`.

### Component mode

CVE-style: a component `name` (and `purl` if given) exists in the
lockfile's slot for that `kind` (harness/model/tool/skill/prompt/policy/
package), and its `version` is inside a `ranges[]` interval or listed in
`versions[]`.

Range semantics: `introduced` (`"0"` = always) ≤ version < `fixed`;
`last_affected` ≤ version; `limit` > version. SEMVER compares
version-tuples; DATE compares ISO strings; GIT only matches via
`versions[]` (ordering needs history the format doesn't carry).

### Configuration mode

The agentic part. A lockfile matches if:

- `config_sha256[]` fast path: `provenance.config_sha256` is listed, **or**
- ALL `require[]` predicates hold, and `window` bounds hold vs
  `generated_at`.

**Paths** are dot-paths over the lockfile. `tools[kind=exec]` selects
array elements by field equality; `tools[]` selects all elements.
Non-exists ops are existential: the predicate holds if *any* resolved
value satisfies it.

| op | meaning |
|----|---------|
| `eq` / `ne` | JSON equality (type-aware: `true` ≠ `1`) |
| `lt`/`lte`/`gt`/`gte` | ordered compare — numeric if both numbers; version-tuple if both strings start with a digit; else lexicographic |
| `in` | resolved value ∈ `value` array |
| `exists` | path resolves non-empty; `value:false` requires *absence* |
| `pattern` | regex `search` on a string value |
| `contains` | element in array value, or substring in string value |

**Window**: `introduced_at` ≤ `generated_at` < `fixed_at` (or ≤
`last_affected_at`). Required because hosted-model identity is temporal:
`pin: alias` means "whatever the provider serves today."

## 4. Records & feed

`records/ACVE-YYYY-NNNN.json` — one file per record, PR-reviewable.
`python -m acve build-feed records -o feed.jsonl` validates every record
and emits the JSONL feed. Lifecycle via `status`: draft → published →
rejected | withdrawn (withdrawn/rejected records never match).

IDs are `ACVE-YYYY-NNNN+`. `CVE-` is MITRE's namespace — foreign IDs go in
`aliases` (CVE/GHSA/AVE all valid alias values).

## 5. Interop

- `aliases` carries CVE-*, GHSA-*, AVE-* cross-references.
- `attack_class`: `primary` enum + `owasp_asi`, `owasp_mcp` (the anchor AVE
  requires of active records — direct crosswalk), `mitre_atlas`, `cwe`.
- `severity`: `CVSS_V3`, `CVSS_V4`, `AIVSS`, `QUALITATIVE` vectors.
- `component.purl` + `ranges.SEMVER` makes component-mode records
  mechanically translatable to OSV/CSAF for downstream tooling.

## 6. Prior art, honestly

The space is not empty. Landscape as of 2026-09, by layer:

| Layer | What exists | What it does | What it does NOT do |
|-------|-------------|--------------|---------------------|
| **AI software vulns in CVE** | CVE AI Working Group (est. Aug 2024); HiddenLayer CNA (46+ AI/ML CVEs); NVIDIA guidance | CVEs assign to AI *software*: MLflow, Chroma, mindsdb deserialization, prompt injection when it produces a security-policy violation in a product | CVE scope ends at the product boundary — "statistical behaviors of models" and config composition are explicitly out |
| **Agentic component advisories** | **AVE** (bawbel/ave, aveproject.org) — schema v1.1.0, AVE-YYYY-NNNNN IDs, `behavioral_fingerprint`, AIVSS v0.8 scores, OWASP MCP Top 10 anchors; PiranhaDB backend + weekly Smithery registry scans (~500 servers, ~19% flaw rate) | Closest existing "CVE for AI agents": stable IDs for behavioral classes in skills, MCP servers, prompts, plugins | Fingerprints component *types*, not resolved deployments; no composition identity; a record describes a class of component, not "this wiring" |
| **Failure/incident databases** | AVID (avidml.org — reports + vulns with eval evidence); Agent Incident Registry (arXiv 2609.11030 — 487 records); AREDB (OWASP-ASI-indexed incident registry); AIID | Curated evidence of AI failures and recurring failure modes | Post-hoc records, not deployment matching — they answer "what has gone wrong," not "is MY config affected" |
| **Scoring & taxonomy** | OWASP AIVSS v0.8 (10 agentic core risks + amplification scoring on CVSS v4 base); OWASP ASI Top 10; MITRE ATLAS; unified threat-vector taxonomies (arXiv 2511.21901) | Severity scoring and attack classification | Scores and classifies; no identity or matching semantics |
| **Composition inventory** | SPDX 3.0 AI Profile; CycloneDX ML-BOM (ECMA-424); academic AIBOM→CSAF-VEX frameworks; **agent-bom** (CVE → package → MCP server → agent → credentials blast-radius mapping) | Lists what an AI system is made of; agent-bom correlates known CVEs through a discovered agent/MCP topology | BOMs are inventory, not a *vulnerability-matching unit*; agent-bom resolves composition at scan time but emits no portable, hash-addressed config artifact and no predicate-based "affected" semantics |
| **Tool mutation detection** | Invariant mcp-scan "Tool Pinning" — hashes MCP tool descriptions to detect rug pulls | Validates the `schema_sha256` mechanism independently | Detects drift; doesn't express the result as a vulnerability record |

### What remains genuinely uncovered — what ACVE adds

1. **A content-addressed unit of configuration.** `config_sha256` makes a
   resolved harness+model+goal+tools+permissions+policy composition a
   first-class, comparable object — the thing a vulnerability record can
   *point at*. BOMs list components; nobody else defines a canonical hash
   identity for the resolved whole.
2. **Configuration-predicate matching.** CVE and AVE name artifacts or
   behavioral classes; neither expresses "affected = any deployment where
   `exec.allowed=true` AND `model.pin ∈ {alias, floating}` AND
   `goal.class=code-editing`." This is the toxic-flow / lethal-trifecta
   pattern (Simon Willison / Invariant): the vulnerability lives in the
   *combination*, which has no package and no version.
3. **Pin-discipline semantics for hosted models.** `model.pin`
   (weights/snapshot/alias/floating) plus AVR `window` bounds encode that
   model identity is temporal — a fact CVE's product/version model and
   BOM inventories both flatten.

**Claim assessment**: "there is no CVE for AI agent configurations" is
accurate at the configuration-unit level — no registry attaches advisories
to a canonical resolved-config identity or matches by capability
predicate. Read as "nothing exists for agentic AI security," it is false:
AVE, AIVSS, AVID, the CVE AI WG, and agent-bom each cover adjacent layers.
ACVE interops rather than replaces.

## 7. Known limitations

- Predicates are AND-ed within a `configuration` entry; OR requires
  multiple entries (deliberate — mirrors OSV).
- Selector filters support field equality only (`[kind=mcp]`); per-element
  composite conditions ("a tool where kind=mcp AND schema_sha256 absent")
  approximate at lockfile granularity.
- `lockhash` approximates JCS number serialization with Python `repr`;
  fine for typical JSON, and flagged in-code for the edge cases.
- GIT ranges don't order commits without external history.
- No PURL parsing/validation beyond prefix matching.
