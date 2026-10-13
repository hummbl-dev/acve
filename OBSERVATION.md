# Execution observations: 0.1.0 candidate

This additive, offline profile records what evidence an evaluation actually used.
It does not change native agent-lock or advisory formats, authenticate identity,
decide authorization, or assert that a deployment is safe.

Both `hummbl-dev/acve` and `hummbl-io/hummbl-acve` remain active. They implement
this profile independently and share the structural schema and conformance corpus.
No repository is archived or assigned sole ownership by this implementation.

## Evaluate evidence

```python
from acve.observation import seal_observation, load_observation, evaluate_observation

# unsigned_document must meet schemas/observation.schema.json AND the semantic
# constraints below. Sealing is a content checksum, not a signature.
sealed = seal_observation(unsigned_document)
result = evaluate_observation(
    sealed,
    {"eq": {"path": "/runtime/model", "value": "example-model"}},
    at="2026-01-01T12:30:00Z",
)
```

For existing sealed files:

```sh
python -m acve observation-check observation.json query.json --at 2026-01-01T12:30:00Z
```

Exit codes: **0 true**, **1 false**, **2 invalid/unavailable input**, **3 unknown**.
An unknown result is not a no-hit. An invalid document never becomes false.
The CLI reads bounded local files, does not fetch references, and prints redacted
errors. Successful output contains the observation/session/execution bindings.

## Contract

Every observation has a unique caller-assigned ID, an explicit validity interval,
subject (agent, host, surface, session, execution and configuration epoch),
source (qualified repository, commit revision and relative path), assertions,
reference-only links, separate receipts and integrity metadata.

Assertions use exact escaped JSON Pointers. Each has `status`, `basis`, and an
opaque `evidence_ref`. `value` is present exactly when status is `known`.
Statuses are known, unknown, invalid, unavailable; bases are observed, configured,
inferred. Only known observed assertions can evaluate true or false. Missing
evidence remains unknown, including an `exists=false` query. Known null exists.
Booleans are not integers, including inside arrays and objects.

Queries contain one operator per node: nonempty `all` or `any` arrays, or
`eq`/`exists` objects with exactly `path` and `value`. `exists.value` is Boolean.
There is no regex, selector, wildcard, dynamic evaluation, or network access.
False dominates `all`; true dominates `any`; otherwise unknown propagates.
Reasons from every leaf remain visible even when another operand decides the
answer. Evaluation before observed_at or at/after valid_until is unknown.

Nonempty identifiers must contain a non-whitespace character. Repository names
are ASCII `owner/name` components using letters, digits, underscore, dot or dash,
or `scheme:value` with a letter-led scheme and whitespace-free nonempty value.
Source revisions are 40 lowercase hex characters. Paths are relative POSIX
paths without empty, dot or parent segments, backslashes, colons or controls.
No source path or evidence reference is dereferenced by the evaluator.

Timestamp syntax is RFC3339's date/time/offset form without leap seconds.
Fractions are compared exactly, including beyond microseconds. Offsets are
required. The schema is structural only: call the Python semantic validator to
check calendar validity, limits, value presence, unique pointers and integrity.

Canonical hashing is named `acve-observation-json/0.1.0`, **not JCS**: JSON sorted
by Unicode scalar key order, ASCII escapes, compact separators, ASCII bytes.
Values are null, Boolean, scalar strings, safe signed integers, arrays and
string-keyed objects. No floats, nonfinite numbers, lone surrogates or duplicate
JSON keys. Digest input excludes the entire integrity member; all other content,
including timestamps and receipts, is bound. Existing integrity metadata must
have valid shape/algorithm before resealing replaces its digest.

Limits: 1 MiB serialized observation or query, 32 container levels (root=1),
10,000 values/containers (keys excluded), 512 assertions, and query trees with
at most 1,024 expression nodes and 16 expression levels.

`validate_observation(document)` returns bounded fixed-path diagnostics;
`load_observation(bytes)` parses and verifies; `seal_observation(document)`
deep-copies and hashes; `evaluate_observation(document, query, at=...)` revalidates
on every call. The latter three raise `ObservationError` on invalid input.

## Identity, context and limits

The result binds observation SHA-256, observation ID, session, execution and
configuration epoch. Caller-reported identity is not authentication. A digest
does not prove that working files match the named source commit.

Links can reference objective, authorization, capacity, capability, taxonomy,
Base120, factory admission, policy and evaluation records. A link is not a grant
of authority, a human readiness assessment, or a completed admission gate.
Keep human narratives in their designated private stores; use reference-only
operational projections here.

Invocation, transport, durability and evaluation receipts are separate states.
Never turn a process exit zero or native `ok` field into aggregate success.
Native advisory matching remains a separate API with its existing semantics.

## Cross-repository verification

From the enterprise checkout, supplying trusted local source checkouts:

```sh
python -B tools/check_alignment.py --personal-root ../acve --summary
python -B tools/replay_capability_demo.py --personal-root ../acve --fleet-root ../agents
```

The first checks schema/corpus byte identity, source bindings, case completeness,
explicit expected outcomes and independent consumer agreement. The second uses
synthetic lifecycle reports only; it does not invoke lifecycle skills or read
personal check-ins. Its context links demonstrate interoperability, not RSI.

## Packaging

`schemas/` remains the canonical authoring location. The build copies those
unchanged bytes into wheel resources. Source checkouts, installed packages and
zip-imported wheels can load schemas; no duplicate source schema is maintained.
The runtime remains Python 3.11+ standard library only.
