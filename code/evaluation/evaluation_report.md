# Evaluation report

Last verified: 2026-10-24. These are final measurements, not provisional baseline claims.

The solution generated all 518 required rows. Public-sample deletion-status accuracy is 32/32. All 41 expected sample findings and all 41 expected remediation actions are covered. Full ordered answers are exact on 14/32 samples; missing verification coverage remains a documented limitation. Hidden full-dataset canonical accuracy is unknown.

## Final strict public-sample metrics

These measurements come from the independent evaluator, code/evaluation/main.py, against all 32 public samples. They retain step numbers and array order.

| Metric | Final result |
|---|---:|
| Sample request coverage | 32/32 — 100% |
| Case-level deletion-status accuracy | 32/32 — 100% |
| Full-row exact accuracy | 14/32 — 43.8% |
| Full-sequence exact accuracy | 14/32 — 43.8% |
| Strict step-set precision, all seven fields | 122/168 — 72.6% |
| Strict step-set recall, all seven fields | 122/193 — 63.2% |
| All-seven-fields accuracy | 999/1372 — 72.8% |

Missing or additional earlier steps shift subsequent step_no values, so these strict measurements deliberately penalize those differences. They are not replaced by the supplementary semantic measurements below.

## Additional semantic step metrics

The following comparison ignores ONLY step_no. It retains phase, operation, system_id, resource_id, state, and evidence_id. It helps distinguish missed violations from missing verification rows and numbering shifts.

| Phase | Matched | Predicted | Expected | Precision | Recall |
|---|---:|---:|---:|---:|---:|
| FINDING | 41 | 42 | 41 | 97.62% | 100% |
| REMEDIATION | 41 | 42 | 41 | 97.62% | 100% |
| VERIFICATION | 83 | 84 | 111 | 98.81% | 74.77% |
| Overall | 165 | 168 | 193 | 98.21% | 85.49% |

There are no missing expected sample findings or remediation actions. The three additional semantic steps are one finding, one deletion action, and one future verification for an earlier observed owned attachment. All 28 missing semantic rows are verifications.

## Final full-dataset verification

A fresh run generated exactly 518 sorted, unique request rows with the exact header case_id,deletion_status,steps_json and LF line endings. The output passed the independent structural validator.

| Status | Rows |
|---|---:|
| INCOMPLETE | 351 |
| COMPLETE | 157 |
| NOT_APPLICABLE | 10 |
| Total | 518 |

An independent fresh run reproduced output.csv byte for byte: 535,009 bytes, SHA-256 305a9cbaf551be1b85bb7ee41b57052f9ea1d59869ee671ec66d886559c419c4. That independent run took 20.869 seconds on the disposable 2-core/8-GB Codespace. Wall-clock time is a machine-specific observation, not an API-cost estimate.

Validation included exact coverage and ordering, JSON decoding, allowed phase/operation/state combinations, consecutive step numbers, valid evidence references, empty evidence IDs for proposed future actions/checks, and verification-only COMPLETE answers. Compilation, all 11 actual-engine domain fixtures, structural self-checks, whitespace checks, and unchanged official inputs passed.

## Evidence and retrieval diagnostics

The final full run emitted zero parser warnings and normalized 3,240 observations:

| Observation source | Count |
|---|---:|
| Resource-scoped log traces/readbacks | 1,071 |
| JSON records/readbacks | 948 |
| Explicit text handover records | 41 |
| Screenshot resource observations | 18 |
| SQL record observations | 891 |
| Complete SQL table-scope observations | 268 |
| PDF resource observations | 2 |
| Catalog-to-media ownership/object join | 1 |
| Total | 3,240 |

All 11 images and all 4 PDFs were read. The independent runtime instrumentation recorded 11 Tesseract calls, 4 pdftotext calls, and 4 pdfinfo calls; no PDF OCR fallback was needed. Some business documents provide context without an explicit auditable resource ID, so document-read counts differ from normalized-resource counts.

The full run used 37 unique temporal candidate-discovery hints; the public-sample run used 7. A unique operation target close to a workflow report can discover a candidate when a deleted/anonymous record no longer contains an identifier. The operation claim is never accepted as proof of the target's current state. State still requires an independently eligible read, snapshot, or visible artifact. This heuristic is a documented identity-resolution limitation.

The prediction code never reads sample_output.csv. Public expected answers are read only by evaluation.

## Actual-engine custom cases: 11 passing fixtures

Seven executable cases in code/evaluation/domain_cases.py call the actual audit engine:

1. A historical email identifies a resource whose later compliant anonymous row contains no direct identifiers.
2. A disable observation after audit_at cannot make an active data flow compliant in an earlier audit.
3. A deleted-account tombstone may retain its stable internal user reference when its direct identifiers are removed.
4. A solo-owned support attachment is deleted rather than treated as a shared conversation requiring redaction.
5. A clean primary does not hide a remaining copy in a failover replica.
6. Explicitly negated deletion remains NOT_APPLICABLE.
7. A repeated deletion request retains absence verification for the sole already-deleted account, even when a fresh retained security record also exists.

Four independently authored fixtures are available through code/evaluation/main.py --engine-fixtures:

1. Historical-email alias resolution identifies a remaining record.
2. Future proof cannot override the state at audit_at.
3. A redacted tombstone and policy-required retained audit record verify correctly.
4. Active synchronization and restore paths produce ordered disable/block actions and final checks.

Structural self-checks additionally exercise valid statuses and invalid mutations, including non-empty future evidence IDs and non-empty NOT_APPLICABLE plans. These are output-contract tests, separately distinguished from the 11 actual-engine domain cases above.

## Failures found and improvements made

The first development baseline associated all resource mentions in a matching file with a subject. It over-attributed unrelated records and could not establish completion. That baseline was replaced rather than submitted.

The final implementation:

- parses individual records and correlation-scoped readbacks instead of matching whole files;
- uses authoritative data categories before resource-name prefixes, including secondary-identifier records stored in support or analytics systems;
- resolves exact current/historical email, phone, hash, stable user ID, and collision-aware complete names;
- keeps query context distinct from stored personal fields so an anonymized response is not mistaken for identifiable data merely because the lookup used an email;
- preserves raw systems rather than confusing collector/wrapper services with the system being audited;
- separates mutation acknowledgements from actual state reads;
- applies source availability and observation cutoffs, including later exported bundles with older embedded snapshots;
- uses complete SQL scopes for grounded negative proof and keeps primary/replica state separate;
- links an exact visible object filename to a timestamped catalog ownership record without deriving IDs from case/user numeric suffixes;
- distinguishes shared-message redaction, solo-attachment deletion, analytics anonymization, tombstone redaction, required retention, data-flow disabling, and restore blocking;
- orders phases and operations by the published enumerations and regenerates step numbers deterministically.

Old PRESENT evidence is not arbitrarily expired. An already-ABSENT prior account can be omitted as prior-lifecycle verification noise only when a different current primary-account resource has direct subject-linked proof. A sole already-absent account remains covered; its regression fixture passed.

## Remaining limitations and conservative choices

Completely identifier-free anonymous/absent resources are not assigned to a subject merely because they occur near another resource in a file, have a convenient numeric suffix, or resemble a sample answer. Some missing verification rows therefore remain unlinked.

Evidence availability can also limit historical verification. For example, a security record in a September 17 exported bundle is not admitted to a September 15 audit simply because the inner snapshot is older. The manifest/export availability guard remains active.

The additional old attachment finding is intentional. A visible object listing and an explicit catalog ownership link establish its earlier presence and ownership. A later deletion request or successful workflow claim does not prove that this separate old copy disappeared. The public canonical answer omits that copy in a later audit; the engine conservatively retains the risk rather than introducing an undocumented age-based expiry solely to match the label.

Perfect sample status accuracy does not imply perfect sequence accuracy or a perfect hidden score. The strict and semantic measurements above make that difference explicit.

## Safety and reproducibility

Each SQL capture is processed in a new disposable in-memory SQLite connection. Temporary storage stays in memory. Extension loading is disabled or unavailable. A restrictive authorizer and instruction-progress budget deny attached databases, external database access, triggers, virtual tables, and arbitrary functions; only the built-in json_valid function needed by supplied CHECK constraints is permitted. Supplied SQL is never run against a persistent or valuable database.

Media extraction invokes installed Poppler/Tesseract with shell disabled, bounded input size, and execution time limits. Manifest paths must resolve inside the dataset directory. Evidence content is never executed as shell instructions.

The deterministic inference path makes no LLM/API calls. Local Tesseract LSTM inference and token/cost accounting are described separately in usage_report.md.

## Reproduce the checks

Run from the repository root:

    python3 code/main.py
    python3 code/evaluation/main.py output.csv
    python3 code/main.py --requests dataset/sample_deletion_requests.csv --output /tmp/ghost-sample.csv
    python3 code/evaluation/main.py --sample /tmp/ghost-sample.csv
    python3 code/evaluation/domain_cases.py
    python3 code/evaluation/main.py --engine-fixtures
    python3 code/evaluation/main.py --self-check

See code/README.md for dependencies and execution details.
