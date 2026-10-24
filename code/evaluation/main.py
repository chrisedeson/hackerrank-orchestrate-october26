#!/usr/bin/env python3
"""Independent, standard-library-only validator for Ghost Data outputs.

Run from any directory with:
    python3 code/evaluation/main.py [--repo-root PATH]
    python3 code/evaluation/main.py --self-check

This checks output shape, case coverage, enum legality, ordering, and evidence
reference syntax/existence. It does not assess whether a cited artifact proves
its claimed state; that remains a human/domain review.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path
from typing import Iterable

OUTPUT_FIELDS = ["case_id", "deletion_status", "steps_json"]
STEP_FIELDS = {
    "step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"
}
STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OPERATIONS = {
    "FINDING": [
        ("REPORT_REMAINING_RECORD", "PRESENT"),
        ("REPORT_EXPOSED_PII", "PRESENT"),
        ("REPORT_ACTIVE_DATA_FLOW", "ACTIVE"),
        ("REPORT_RESTORE_RISK", "ACTIVE"),
    ],
    "REMEDIATION": [
        ("DISABLE_DATA_FLOW", "DISABLED"),
        ("BLOCK_RESTORE", "BLOCKED"),
        ("DELETE_RECORD", "ABSENT"),
        ("REDACT_RECORD", "REDACTED"),
        ("ANONYMIZE_RECORD", "ANONYMIZED"),
    ],
    "VERIFICATION": [
        ("VERIFY_RECORD_ABSENT", "ABSENT"),
        ("VERIFY_RECORD_PRESENT", "PRESENT"),
        ("VERIFY_RECORD_REDACTED", "REDACTED"),
        ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
        ("VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
        ("VERIFY_RESTORE_BLOCKED", "BLOCKED"),
    ],
}
OP_INDEX = {
    (phase, operation): index
    for phase, entries in OPERATIONS.items()
    for index, (operation, _state) in enumerate(entries)
}
EVIDENCE_PATTERN = re.compile(r"^(?:evidence|activity|audit)_[A-Za-z0-9-]+$")


class ValidationError(Exception):
    pass


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8-sig") as source:
        return list(csv.DictReader(source))


def reference_ids(repo_root: Path) -> set[str]:
    refs: set[str] = set()
    sources = [
        (repo_root / "dataset/evidence_files.csv", "file_id"),
        (repo_root / "dataset/system_activity.csv", "activity_id"),
        (repo_root / "dataset/user_audit_log.csv", "audit_id"),
    ]
    for path, field in sources:
        if not path.exists():
            continue
        refs.update(row[field] for row in read_csv(path) if row.get(field))
    return refs


def validate_steps(case_id: str, status: str, serialized: str, refs: set[str]) -> list[str]:
    errors: list[str] = []
    try:
        steps = json.loads(serialized)
    except (json.JSONDecodeError, TypeError) as exc:
        return [f"{case_id}: steps_json is invalid JSON ({exc})"]
    if not isinstance(steps, list):
        return [f"{case_id}: steps_json must be a JSON array"]
    if status == "NOT_APPLICABLE":
        return [] if steps == [] else [f"{case_id}: NOT_APPLICABLE requires []"]

    phase_seen: list[int] = []
    sort_keys: list[tuple[int, int, str, str]] = []
    phases_present: set[str] = set()
    for expected_no, step in enumerate(steps, 1):
        prefix = f"{case_id}: step {expected_no}"
        if not isinstance(step, dict):
            errors.append(f"{prefix} must be an object")
            continue
        if set(step) != STEP_FIELDS:
            errors.append(f"{prefix} fields must be exactly {sorted(STEP_FIELDS)}")
        if step.get("step_no") != expected_no or isinstance(step.get("step_no"), bool):
            errors.append(f"{prefix} step_no must be {expected_no}")
        phase = step.get("phase")
        operation = step.get("operation")
        state = step.get("state")
        if phase not in OPERATIONS:
            errors.append(f"{prefix} has invalid phase {phase!r}")
            continue
        phases_present.add(phase)
        phase_num = PHASE_ORDER[phase]
        phase_seen.append(phase_num)
        allowed = dict(OPERATIONS[phase])
        if operation not in allowed:
            errors.append(f"{prefix} has invalid operation {operation!r} for {phase}")
            operation_num = 999
        else:
            operation_num = OP_INDEX[(phase, operation)]
            if state != allowed[operation]:
                errors.append(f"{prefix} state must be {allowed[operation]!r} for {operation}")
        system = step.get("system_id")
        resource = step.get("resource_id")
        if not isinstance(system, str) or not system or not isinstance(resource, str) or not resource:
            errors.append(f"{prefix} requires non-empty system_id and resource_id strings")
            system = str(system or "")
            resource = str(resource or "")
        sort_keys.append((phase_num, operation_num, system, resource))
        evidence = step.get("evidence_id")
        future = status == "INCOMPLETE" and phase in {"REMEDIATION", "VERIFICATION"}
        if future:
            if evidence != "":
                errors.append(f"{prefix} future {phase.lower()} evidence_id must be empty")
        else:
            if not isinstance(evidence, str) or not EVIDENCE_PATTERN.fullmatch(evidence):
                errors.append(f"{prefix} must cite a file_id, activity_id, or audit_id")
            elif refs and evidence not in refs:
                errors.append(f"{prefix} cites unknown evidence {evidence!r}")
        if status == "COMPLETE" and phase != "VERIFICATION":
            errors.append(f"{prefix} COMPLETE cases may contain verification steps only")

    if phase_seen != sorted(phase_seen):
        errors.append(f"{case_id}: phases are not ordered FINDING, REMEDIATION, VERIFICATION")
    if sort_keys != sorted(sort_keys):
        errors.append(f"{case_id}: steps do not follow phase/operation/system/resource ordering")
    if status == "INCOMPLETE":
        for required in ("FINDING", "REMEDIATION", "VERIFICATION"):
            if required not in phases_present:
                errors.append(f"{case_id}: INCOMPLETE requires at least one {required} step")
    if status == "COMPLETE" and not steps:
        errors.append(f"{case_id}: COMPLETE requires evidence-backed verification")
    return errors


def validate_rows(requests: list[dict[str, str]], outputs: list[dict[str, str]], refs: set[str]) -> list[str]:
    errors: list[str] = []
    expected_ids = [row.get("case_id", "") for row in requests]
    output_ids = [row.get("case_id", "") for row in outputs]
    if len(expected_ids) != len(set(expected_ids)):
        errors.append("input requests contain duplicate case_id values")
    if len(output_ids) != len(set(output_ids)):
        errors.append("output contains duplicate case_id values")
    if len(outputs) != len(requests):
        errors.append(f"output has {len(outputs)} rows; expected {len(requests)}")
    if output_ids != sorted(output_ids):
        errors.append("output rows are not sorted by case_id")
    if set(output_ids) != set(expected_ids):
        missing = sorted(set(expected_ids) - set(output_ids))
        extra = sorted(set(output_ids) - set(expected_ids))
        errors.append(f"case_id coverage mismatch: missing={missing[:8]}, extra={extra[:8]}")

    for row in outputs:
        case_id = row.get("case_id", "")
        status = row.get("deletion_status", "")
        if status not in STATUSES:
            errors.append(f"{case_id}: invalid deletion_status {status!r}")
            continue
        errors.extend(validate_steps(case_id, status, row.get("steps_json", ""), refs))
    return errors


def fixture(case_id: str, status: str, steps: list[dict[str, object]]) -> dict[str, str]:
    return {"case_id": case_id, "deletion_status": status, "steps_json": json.dumps(steps)}


def make_step(no: int, phase: str, system: str, resource: str, operation: str, state: str, evidence: str) -> dict[str, object]:
    return {"step_no": no, "phase": phase, "system_id": system, "resource_id": resource,
            "operation": operation, "state": state, "evidence_id": evidence}


def self_check() -> list[str]:
    """Exercise one valid example per status and reject two invalid mutations."""
    refs = {"evidence_01", "activity_07", "audit_03"}
    complete = fixture("case_a", "COMPLETE", [
        make_step(1, "VERIFICATION", "account_service", "account_1", "VERIFY_RECORD_ABSENT", "ABSENT", "evidence_01")
    ])
    incomplete = fixture("case_b", "INCOMPLETE", [
        make_step(1, "FINDING", "account_service", "account_2", "REPORT_REMAINING_RECORD", "PRESENT", "activity_07"),
        make_step(2, "REMEDIATION", "account_service", "account_2", "DELETE_RECORD", "ABSENT", ""),
        make_step(3, "VERIFICATION", "account_service", "account_2", "VERIFY_RECORD_ABSENT", "ABSENT", ""),
    ])
    not_applicable = fixture("case_c", "NOT_APPLICABLE", [])
    valid_errors = validate_rows(
        [{"case_id": "case_a"}, {"case_id": "case_b"}, {"case_id": "case_c"}],
        [complete, incomplete, not_applicable], refs,
    )
    if valid_errors:
        return ["fixture validation failed: " + "; ".join(valid_errors)]

    bad_order = fixture("case_x", "INCOMPLETE", [
        make_step(1, "FINDING", "account_service", "account_2", "REPORT_REMAINING_RECORD", "PRESENT", "activity_07"),
        make_step(2, "REMEDIATION", "account_service", "account_2", "DELETE_RECORD", "ABSENT", ""),
        make_step(3, "VERIFICATION", "account_service", "account_2", "VERIFY_RECORD_ABSENT", "ABSENT", "evidence_01"),
    ])
    if not any("future verification evidence_id must be empty" in e for e in validate_steps("case_x", "INCOMPLETE", bad_order["steps_json"], refs)):
        return ["fixture mutation was not rejected: non-empty future evidence"]
    bad_na = fixture("case_y", "NOT_APPLICABLE", [
        make_step(1, "VERIFICATION", "account_service", "account_3", "VERIFY_RECORD_ABSENT", "ABSENT", "evidence_01")
    ])
    if not any("NOT_APPLICABLE requires []" in e for e in validate_steps("case_y", "NOT_APPLICABLE", bad_na["steps_json"], refs)):
        return ["fixture mutation was not rejected: non-empty NOT_APPLICABLE steps"]
    return []




def canonical_steps(value: str) -> list[dict[str, object]] | None:
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return None
    return parsed if isinstance(parsed, list) else None


def compare_sample(predictions: list[dict[str, str]], expected: list[dict[str, str]]) -> dict[str, object]:
    actual_by_id = {row.get("case_id", ""): row for row in predictions}
    expected_by_id = {row.get("case_id", ""): row for row in expected}
    shared = set(actual_by_id) & set(expected_by_id)
    statuses_correct = 0
    exact_rows = 0
    exact_sequences = 0
    step_true_positive = 0
    predicted_step_count = 0
    expected_step_count = 0
    field_correct = 0
    field_total = 0

    def step_counter(steps: list[dict[str, object]] | None) -> dict[str, int]:
        counts: dict[str, int] = {}
        for step in steps or []:
            key = json.dumps(step, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            counts[key] = counts.get(key, 0) + 1
        return counts

    for case_id, expected_row in expected_by_id.items():
        actual_row = actual_by_id.get(case_id)
        if actual_row and actual_row.get("deletion_status") == expected_row.get("deletion_status"):
            statuses_correct += 1
        expected_steps = canonical_steps(expected_row.get("steps_json", ""))
        actual_steps = canonical_steps(actual_row.get("steps_json", "")) if actual_row else None
        if expected_steps is None:
            expected_steps = []
        if actual_steps == expected_steps:
            exact_sequences += 1
        if actual_row and actual_row.get("deletion_status") == expected_row.get("deletion_status") and actual_steps == expected_steps:
            exact_rows += 1

        expected_counts = step_counter(expected_steps)
        actual_counts = step_counter(actual_steps)
        expected_step_count += sum(expected_counts.values())
        predicted_step_count += sum(actual_counts.values())
        step_true_positive += sum(min(count, actual_counts.get(key, 0)) for key, count in expected_counts.items())

        actual_list = actual_steps or []
        for index, expected_step in enumerate(expected_steps):
            actual_step = actual_list[index] if index < len(actual_list) and isinstance(actual_list[index], dict) else {}
            for field in STEP_FIELDS:
                field_total += 1
                field_correct += actual_step.get(field) == expected_step.get(field)
        field_total += max(0, len(actual_list) - len(expected_steps)) * len(STEP_FIELDS)

    total = len(expected)
    return {
        "expected_rows": total,
        "prediction_rows": len(predictions),
        "coverage": len(shared) / total if total else 1.0,
        "status_correct": statuses_correct,
        "status_accuracy": statuses_correct / total if total else 1.0,
        "full_row_exact": exact_rows / total if total else 1.0,
        "full_row_exact_count": exact_rows,
        "step_set_precision": step_true_positive / predicted_step_count if predicted_step_count else 1.0,
        "step_set_recall": step_true_positive / expected_step_count if expected_step_count else 1.0,
        "step_true_positive": step_true_positive,
        "predicted_step_count": predicted_step_count,
        "expected_step_count": expected_step_count,
        "all_seven_fields_accuracy": field_correct / field_total if field_total else 1.0,
        "field_correct": field_correct,
        "field_total": field_total,
        "sequence_exact": exact_sequences / total if total else 1.0,
        "sequence_exact_count": exact_sequences,
    }


def import_engine(repo_root: Path):
    import importlib.util
    import sys
    code_dir = repo_root / "code"
    if str(code_dir) not in sys.path:
        sys.path.insert(0, str(code_dir))
    spec = importlib.util.spec_from_file_location("ghost_data_engine_eval", code_dir / "main.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load code/main.py")
    engine = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = engine
    spec.loader.exec_module(engine)
    return engine


def evaluate_engine_sample(repo_root: Path) -> tuple[dict[str, object], list[str], list[str]]:
    engine = import_engine(repo_root)
    index = engine.DatasetIndex(repo_root / "dataset")
    requests = read_csv(repo_root / "dataset/sample_deletion_requests.csv")
    expected = read_csv(repo_root / "dataset/sample_output.csv")
    predictions: list[dict[str, str]] = []
    failures: list[str] = []
    for case in requests:
        try:
            status, steps = engine.audit_case(case, index)
            predictions.append({
                "case_id": case["case_id"],
                "deletion_status": status,
                "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":")),
            })
        except Exception as exc:
            failures.append(f"{case['case_id']}: {type(exc).__name__}: {exc}")
    return compare_sample(predictions, expected), failures, [row["case_id"] for row in requests]


def synthetic_index(engine, observations: list[dict[str, object]], email: str = "former@example.test"):
    from collections import defaultdict
    user = "user_fixture"
    token = engine.normalize(email)
    index = engine.DatasetIndex.__new__(engine.DatasetIndex)
    index.dataset = None
    index.users = {user: {user, token}}
    index.alias = defaultdict(set)
    index.alias[token].add(user)
    index.rules = [
        {"data_category": "USER_PROFILE", "required_action": "DELETE"},
        {"data_category": "SECURITY_AUDIT_LOG", "required_action": "RETAIN"},
        {"data_category": "ACCOUNT_TOMBSTONE", "required_action": "REDACT"},
        {"data_category": "ANALYTICS_PROFILE", "required_action": "ANONYMIZE"},
    ]
    index.observations = observations
    index.scopes = []
    index.diagnostics = []
    index.activities = []
    index.by_resource = defaultdict(list)
    index.subject_resources = defaultdict(set)
    index.resource_links = defaultdict(list)
    index.resource_keys = defaultdict(set)
    for obs in observations:
        raw = obs.get("raw") or {}
        tokens = engine.identifiers(raw, obs.get("text", ""))
        tokens.add(user)
        obs["_identity_tokens"] = tokens
        key = (str(obs["system_id"]), str(obs["resource_id"]))
        index.by_resource[key].append(obs)
        index.resource_keys[key[1]].add(key)
        for item in tokens:
            index.subject_resources[item].add(key)
    return index


def synthetic_observation(engine, resource: str, system: str, category: str,
                          evidence: str, *, observed: str = "2026-09-10T10:00:00Z",
                          state: str = "PRESENT", raw: dict[str, object] | None = None):
    data = {"user_id": "user_fixture"}
    if raw:
        data.update(raw)
    return {
        "system_id": system, "resource_id": resource, "category": category,
        "evidence_id": evidence, "capture_at": observed, "observed_at": observed,
        "state_hint": state, "raw": data, "text": "",
        "source_kind": "json_record", "is_claim": False,
    }


def run_engine_fixtures(repo_root: Path) -> list[tuple[str, bool, str]]:
    engine = import_engine(repo_root)
    base_case = {
        "case_id": "fixture_case", "email": "former@example.test",
        "requested_at": "2026-09-01T00:00:00Z",
        "audit_at": "2026-09-30T00:00:00Z",
        "request_text": "Please permanently delete my account and personal data.",
    }
    results: list[tuple[str, bool, str]] = []

    historical = synthetic_observation(
        engine, "account_hist", "account_service", "USER_PROFILE", "evidence_fixture_hist",
        raw={"email": "former@example.test", "email_hash": None},
    )
    status, steps = engine.audit_case(base_case, synthetic_index(engine, [historical]))
    hist_ok = (status == "INCOMPLETE" and len(steps) == 3
               and steps[0]["evidence_id"] == "evidence_fixture_hist"
               and steps[0]["operation"] == "REPORT_REMAINING_RECORD"
               and steps[1]["operation"] == "DELETE_RECORD"
               and steps[2]["evidence_id"] == "")
    results.append(("historical email alias resolves to the stable user", hist_ok,
                    f"{status}; {len(steps)} steps; evidence={steps[0]['evidence_id'] if steps else 'none'}"))

    cutoff_case = dict(base_case, case_id="fixture_future", audit_at="2026-09-10T11:00:00Z")
    current = synthetic_observation(
        engine, "account_temporal", "account_service", "USER_PROFILE", "evidence_fixture_current",
        observed="2026-09-10T10:00:00Z", state="PRESENT",
        raw={"email": "former@example.test"},
    )
    future = synthetic_observation(
        engine, "account_temporal", "account_service", "USER_PROFILE", "evidence_fixture_future",
        observed="2026-09-10T12:00:00Z", state="ABSENT",
        raw={"email": "former@example.test"},
    )
    status, steps = engine.audit_case(cutoff_case, synthetic_index(engine, [current, future]))
    future_ok = (status == "INCOMPLETE" and bool(steps)
                 and steps[0]["evidence_id"] == "evidence_fixture_current"
                 and all(step["evidence_id"] != "evidence_fixture_future" for step in steps))
    results.append(("future proof cannot override state at audit_at", future_ok,
                    f"{status}; cited={[step['evidence_id'] for step in steps]}"))

    tombstone = synthetic_observation(
        engine, "tombstone_fixture", "identity_service", "ACCOUNT_TOMBSTONE",
        "evidence_fixture_tombstone", state="REDACTED",
        raw={"email": None, "phone": None, "email_hash": None,
             "name": None, "subject_reference": "user_fixture"},
    )
    retention = synthetic_observation(
        engine, "audit_fixture", "security_service", "SECURITY_AUDIT_LOG",
        "evidence_fixture_retention", state="PRESENT",
        raw={"retention_until": "2030-01-01T00:00:00Z", "subject_reference": "user_fixture"},
    )
    status, steps = engine.audit_case(base_case, synthetic_index(engine, [tombstone, retention]))
    observed = {(s["system_id"], s["resource_id"], s["operation"], s["evidence_id"]) for s in steps}
    retained_ok = (status == "COMPLETE" and len(steps) == 2
                   and ("identity_service", "tombstone_fixture", "VERIFY_RECORD_REDACTED", "evidence_fixture_tombstone") in observed
                   and ("security_service", "audit_fixture", "VERIFY_RECORD_PRESENT", "evidence_fixture_retention") in observed)
    results.append(("redacted tombstone and policy-retained audit record verify", retained_ok,
                    f"{status}; checks={sorted(x[2] for x in observed)}"))

    flow = synthetic_observation(
        engine, "data_flow_fixture", "integration_service", "DATA_FLOW",
        "evidence_fixture_flow", state="ACTIVE", raw={"enabled": True},
    )
    backup = synthetic_observation(
        engine, "backup_fixture", "backup_service", "BACKUP_ARCHIVE",
        "evidence_fixture_backup", state="ACTIVE", raw={"restore_allowed": True},
    )
    status, steps = engine.audit_case(base_case, synthetic_index(engine, [flow, backup]))
    operations = [(step["phase"], step["system_id"], step["operation"], step["evidence_id"]) for step in steps]
    flow_ok = (status == "INCOMPLETE" and
               ("FINDING", "integration_service", "REPORT_ACTIVE_DATA_FLOW", "evidence_fixture_flow") in operations and
               ("REMEDIATION", "integration_service", "DISABLE_DATA_FLOW", "") in operations and
               ("VERIFICATION", "backup_service", "VERIFY_RESTORE_BLOCKED", "") in operations)
    results.append(("active sync and restore paths require ordered actions", flow_ok,
                    f"{status}; operations={[(p, op) for p, _, op, _ in operations]}"))
    return results

def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?", type=Path, help="prediction CSV to validate")
    parser.add_argument("--sample", nargs="?", const="__ENGINE__", metavar="PREDICTIONS",
                        help="compare predictions with dataset/sample_output.csv")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2],
                        help="repository root (defaults to the parent of code/)")
    parser.add_argument("--engine-fixtures", action="store_true", help="run synthetic decision fixtures against code/main.py")
    parser.add_argument("--self-check", action="store_true", help="check embedded structural fixtures only")
    args = parser.parse_args(argv)
    if args.engine_fixtures:
        results = run_engine_fixtures(args.repo_root)
        for name, passed, detail in results:
            verdict = "PASS" if passed else "FAIL"
            print(f"{verdict}: {name}: {detail}")
        return 0 if all(passed for _, passed, _ in results) else 1
    if args.sample is not None:
        if args.sample == "__ENGINE__":
            metrics, failures, _case_ids = evaluate_engine_sample(args.repo_root)
        else:
            prediction_path = Path(args.sample)
            if not prediction_path.is_absolute():
                prediction_path = args.repo_root / prediction_path
            if not prediction_path.exists():
                print(f"Missing predictions file: {prediction_path}", file=sys.stderr)
                return 2
            with prediction_path.open("r", newline="", encoding="utf-8-sig") as source:
                reader = csv.DictReader(source)
                if reader.fieldnames != OUTPUT_FIELDS:
                    print("Prediction header must be exactly " + ",".join(OUTPUT_FIELDS), file=sys.stderr)
                    return 1
                predictions = list(reader)
            expected = read_csv(args.repo_root / "dataset/sample_output.csv")
            metrics = compare_sample(predictions, expected)
            failures = []
        print(f"Sample coverage: {metrics['coverage']:.1%} ({metrics['coverage'] * metrics['expected_rows']:.0f}/{metrics['expected_rows']})")
        print(f"Status accuracy: {metrics['status_accuracy']:.1%} ({metrics['status_correct']}/{metrics['expected_rows']})")
        print(f"Full-row exact: {metrics['full_row_exact']:.1%} ({metrics['full_row_exact_count']}/{metrics['expected_rows']})")
        print(f"Step-set precision: {metrics['step_set_precision']:.1%} ({metrics['step_true_positive']}/{metrics['predicted_step_count']})")
        print(f"Step-set recall: {metrics['step_set_recall']:.1%} ({metrics['step_true_positive']}/{metrics['expected_step_count']})")
        print(f"All-seven-fields accuracy: {metrics['all_seven_fields_accuracy']:.1%} ({metrics['field_correct']}/{metrics['field_total']})")
        print(f"Sequence exact: {metrics['sequence_exact']:.1%} ({metrics['sequence_exact_count']}/{metrics['expected_rows']})")
        if failures:
            print(f"Engine exceptions: {len(failures)} (counted as incorrect; denominator remains {metrics['expected_rows']})")
            for failure in failures:
                print("ERROR: " + failure)
            return 1
        return 0
    if args.self_check:
        errors = self_check()
        print("Self-check: PASS" if not errors else "Self-check: FAIL")
    else:
        request_path = args.repo_root / "dataset/deletion_requests.csv"
        output_path = args.output if args.output else args.repo_root / "output.csv"
        if not output_path.is_absolute():
            output_path = args.repo_root / output_path
        if not request_path.exists() or not output_path.exists():
            print(f"Missing required file: {request_path if not request_path.exists() else output_path}", file=sys.stderr)
            return 2
        with request_path.open("r", newline="", encoding="utf-8-sig") as source:
            input_reader = csv.DictReader(source)
            if input_reader.fieldnames != ["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"]:
                print("Input request header does not match the challenge contract", file=sys.stderr)
                return 2
            requests = list(input_reader)
        with output_path.open("r", newline="", encoding="utf-8-sig") as source:
            reader = csv.DictReader(source)
            if reader.fieldnames != OUTPUT_FIELDS:
                print("Output header must be exactly " + ",".join(OUTPUT_FIELDS), file=sys.stderr)
                return 1
            outputs = list(reader)
        errors = validate_rows(requests, outputs, reference_ids(args.repo_root))
        print(f"Rows: {len(outputs)} / {len(requests)}")
    if errors:
        for error in errors:
            print("ERROR: " + error)
        print(f"Validation failed with {len(errors)} issue(s)")
        return 1
    if not args.self_check:
        print("Validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
