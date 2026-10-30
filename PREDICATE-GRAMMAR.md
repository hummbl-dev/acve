# ACVE Predicate Grammar

**Status:** DRAFT (2026-10-11) — normative companion to `SPEC.md` §3.
**Format anchor:** `avr/1.0.0` / `agent-lock/1.0.0`.
**Reference implementation:** `acve/match.py` (this repo); fleet-side mirror
`agents/docs/schemas/acve/acve_match.py`.

This document specifies the machine grammar of the **configuration-mode**
`affected[]` entry: the predicate language an AVR uses to say
"configurations shaped like X are vulnerable to Y." Component-mode (CVE/OSV-style)
matching is specified in §3 of `SPEC.md` and summarized here only for contrast.

The grammar is intentionally small. Everything below is derivable from the
schema (`schemas/agent-vulnerability.schema.json`) and `acve/match.py`; this
document adds no new semantics.

---

## 1. Two matching modes

An `affected[]` entry is a tagged union on `unit`:

- `unit: "component"` — a versioned artifact (`component.kind` + `name` +
  `ranges[]`/`versions[]`). CVE/OSV semantics.
- `unit: "configuration"` — a predicate over the resolved **agent-lock** unit.

A lockfile matches a record iff **any** `affected[]` entry matches (OR). A
`configuration` entry matches iff its `config_sha256[]` fast path contains the
lockfile's `provenance.config_sha256`, **or** all `require[]` predicates hold
**and** any `window` bounds hold against the lockfile's `generated_at`.

Records with `status ∈ {rejected, withdrawn}` never match.

## 2. Grammar (EBNF)

```ebnf
affected_entry = component_entry | configuration_entry ;

component_entry = "{" , '"unit"' , ":" , '"component"' , "," , '"component"' , ":" , component_body , "}" ;
component_body  = "{" , '"kind"' , ":" , kind , "," , '"name"' , ":" , name , [ "," , '"purl"' , ":" , purl ] , [ "," , '"ranges"' , ":" , ranges ] , [ "," , '"versions"' , ":" , versions ] , "}" ;
kind           = '"harness"' | '"model"' | '"tool"' | '"skill"' | '"prompt"'
               | '"policy"' | '"protocol"' | '"package"' ;

configuration_entry = "{" , '"unit"' , ":" , '"configuration"' , "," , '"configuration"' , ":" , config_body , "}" ;
config_body         = "{" , [ config_sha256_list ] , [ require_list ] , [ window_wrapper ] , "}" ;
config_sha256_list  = '"config_sha256"' , ":" , "[" , hash , { "," , hash } , "]" ;
require_list        = '"require"' , ":" , "[" , predicate , { "," , predicate } , "]" ;   (* AND *)
window_wrapper      = '"window"' , ":" , "{" , [ window_bounds ] , "}" ;
window_bounds       = window_member , { "," , window_member } ;
window_member       = ( '"introduced_at"' | '"fixed_at"' | '"last_affected_at"' ) , ":" , iso_datetime ;   (* each name at most once — duplicates are invalid *)
iso_datetime        = '"' , /[^"]+/ , '"' ;   (* non-empty quoted string; §5 compares the text *)

predicate  = "{" , "path" , ":" , path , "," , "op" , ":" , op ,
             [ "," , "value" , ":" , json ] , "}" ;
op         = "eq" | "ne" | "lt" | "lte" | "gt" | "gte"
           | "in" | "exists" | "pattern" | "contains" ;

path       = segment , { "." , segment } ;
segment    = identifier , [ selector ] ;
selector   = "[" , field , "=" , selector_value , "]"    (* equality filter *)
           | "[]" ;                                      (* wildcard *)
identifier = /[A-Za-z_][A-Za-z0-9_]*/ ;
field      = /[A-Za-z_][A-Za-z0-9_]*/ ;
selector_value = /[^\]]*/ ;   (* literal; no nesting or escaping *)

hash       = /[0-9a-f]{64}/ ;
```

> `prototype` note: `selector_value` is a raw bracket-literal matched against
> `str(field_value)`. It is not JSON and does not support `]`, escapes, or
> nested selectors — see §6.

## 3. Path resolution

`path` is a dot-path into the agent-lock document. Resolution is **set-valued**:
a path resolves to a *list* of candidate values, not a single value.

| Segment | Behaviour (per current value `v`) |
|---|---|
| `name` | if `v` is an object and has `name`, yield `v["name"]`; if `v` is a list of objects, yield `x["name"]` for each |
| `coll[field=val]` | if `v` has list `coll`, yield each element `x` with `str(x.get(field)) == val` |
| `coll[]` | if `v` has list `coll`, yield all elements |

The initial value is the whole lockfile. Missing keys resolve to the empty set.

**Operand semantics depend on the resolved type**, so the same path can yield a
scalar, a list, or nothing depending on the lockfile.

## 4. Operators

| op | Meaning | Type behaviour |
|---|---|---|
| `eq` | JSON equality | type-aware: `true ≠ 1` |
| `ne` | negated `eq` | |
| `lt` `lte` `gt` `gte` | ordered compare | numeric if both numbers; version-tuple if both strings start with a digit; else lexicographic; incomparable → no match |
| `in` | membership in `value` array | `any(eq(v, x) for x in value)` |
| `exists` | path resolves non-empty | `value:false` requires **absence**; omitted/`true` requires presence |
| `pattern` | `re.search(value, resolved)` on strings | regex, unanchored |
| `contains` | element-in-array or substring-in-string | array: `any(eq)`; string: substring |

**Evaluation model for non-`exists` ops is existential**: the predicate holds
if **any** resolved value satisfies it. Within `require[]`, predicates are
AND-ed; OR is expressed with multiple `affected[]` entries.

`exists` is the exception — it tests the resolution set itself
(`bool(resolved) == want_present`), not any element.

## 5. Window semantics

`window` bounds matching by the lockfile's `generated_at` (ISO-8601 string
compare). `iso_datetime` is a non-empty quoted string. `acve/match.py`
compares that text and does not parse a datetime:

| Bound | Condition to remain matched |
|---|---|
| `introduced_at` | `generated_at >= introduced_at` |
| `fixed_at` | `generated_at < fixed_at` |
| `last_affected_at` | `generated_at <= last_affected_at` |

Required because hosted-model identity is temporal: `model.pin: alias` means
"whatever the provider serves today."

## 6. Worked examples

Unrestricted exec **and** a drifting model pin **and** a code-editing goal —
the lethal-trifecta shape:

```json
{
  "unit": "configuration",
  "configuration": {
    "require": [
      { "path": "tools[kind=exec].permissions.exec.allowed", "op": "eq", "value": true },
      { "path": "model.pin", "op": "in", "value": ["alias", "floating"] },
      { "path": "agent.goal.class", "op": "eq", "value": "code-editing" }
    ],
    "window": { "introduced_at": "2026-09-01T00:00:00Z" }
  }
}
```

MCP tool whose callable signature was not pinned (rug-pull surface):

```json
{
  "unit": "configuration",
  "configuration": {
    "require": [
      { "path": "tools[kind=mcp].schema_sha256", "op": "exists", "value": false }
    ]
  }
}
```

## 7. Component-mode summary (contrast)

`component` matches when the kind's slot in the lockfile has the same `name`
(and `purl`, if given), and the slot `version` is inside a `ranges[]` interval
or listed in `versions[]`. Range bounds: `introduced` (`"0"` = always) ≤
version `< fixed`; version ≤ `last_affected`; `limit` > version. `SEMVER`
compares version-tuples, `DATE` compares ISO strings, `GIT` matches only via
explicit `versions[]` (no commit ordering).

## 8. Unit identity (why configuration mode is well-defined)

`provenance.config_sha256` = SHA-256 over the RFC 8785 (JCS) canonicalization of
the lockfile **with `provenance` excluded**:

```python
json.dumps(doc_without_provenance, sort_keys=True,
           separators=(",", ":"), ensure_ascii=True)
```

Two deployments with the same hash are the same configuration. `generated_at`,
`generated_by`, and `environment` **remain inside** the hash (they describe
*when/how*, and are treated as part of the unit — see `REVIEW.md` claim 1).

## 9. Convergence surface (must agree for interop)

These are the decisions a second implementation must match to be the same
grammar (from `REVIEW.md`):

| Decision | Choice |
|---|---|
| Affected model | OR over `affected[]`; entries tagged `unit: component \| configuration` |
| Predicate ops | eq, ne, lt, lte, gt, gte, in, exists(+false), pattern, contains |
| Path syntax | dot-path; `[field=value]` selector; `[]` wildcard |
| Predicate combination | AND within `require[]`, OR across entries |
| Fast path | `config_sha256[]` membership short-circuits `require[]` |
| Window | `introduced_at`/`fixed_at`/`last_affected_at` vs `generated_at` |
| Unit identity | `config_sha256` = JCS(doc − `provenance`) |

## 10. Conformance

A conforming implementation MUST pass the cases exercised by `tests/test_acve.py`
and SHOULD satisfy the following derived corpus:

- selector `[k=v]` compares via `str()` without case normalization:
  `[field=True]` matches Boolean `True`, while `[field=true]` does not
  (Python `str(True) == "True"`; this is a documented sharp edge, see §11).
- non-`exists` ops are existential over the resolution set.
- `incomparable` ordered compares return no match (not false-y errors).
- each `window` member name MUST appear at most once; a document that
  repeats a member name is invalid (parsers that silently keep the last
  duplicate value would disagree on the effective bound).
- `iso_datetime` is a non-empty quoted string. An empty production is not
  a timestamp. The matcher compares the text with `generated_at`.
- rejected/withdrawn records match nothing.

## 11. Known limitations (inherited from `SPEC.md` §7 / `REVIEW.md`)

- Predicates are AND-ed within an entry; OR requires multiple entries.
- Selectors are field-equality only; no per-element composite conditions.
- `selector_value` is a raw literal; no `]`/escapes; `str()`-based compare
  means booleans and their title-case strings can collide.
- `GIT` ranges do not order commits.
- No PURL parsing/validation beyond prefix matching.
- `lockhash` approximates JCS number serialization with Python `repr`; exotic
  floats may diverge.

---

**Provenance:** derived 2026-10-11 from `SPEC.md` §3, `schemas/agent-vulnerability.schema.json`,
`acve/match.py`, and `examples/agent-lock.example.json` (all read in-session).
No claim here exceeds those sources. This spec does not alter the schema or the
matcher; it documents the grammar they already implement.
