"""Normalize participant evidence into resource-scoped, timestamped observations.

SQL is loaded only into a disposable in-memory SQLite database with a restrictive
authorizer; extensions, attached databases, triggers and arbitrary functions are
denied. JSON, six log dialects and business media share the same observation
contract. Mutation acknowledgements are not observations of resulting state.
"""
from __future__ import annotations

import csv
import json
import re
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import media

MAX_BYTES = 25 * 1024 * 1024
WARNINGS: list[str] = []
MEDIA_TEXT: dict[str, str] = {}
TIME_RE = re.compile(r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?Z")
RESOURCE_RE = re.compile(r"(?<![\w-])(?:account|search|support|attachment|analytics|export|data_flow|backup|audit_record|tombstone|marketing|telemetry|delivery_log|email_log|email_delivery|cache|secondary_identifier|legal_hold)_(?=[A-Za-z0-9-]*\d)[A-Za-z0-9-]+(?![\w-])", re.I)
USER_RE = re.compile(r"(?<![\w-])user_[A-Za-z0-9-]+(?![\w-])", re.I)
EMAIL_RE = re.compile(r"[A-Z0-9._%+,-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
KV_RE = re.compile(r'([\w.-]+)\s*=\s*("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[^\s|]+)')

CATEGORY_SYSTEM = {
    "USER_PROFILE": "account_service", "SECONDARY_IDENTIFIER": "account_service",
    "SEARCH_INDEX_ENTRY": "search_service", "CACHE_ENTRY": "cache_service",
    "SUPPORT_MESSAGE": "support_platform", "SUPPORT_ATTACHMENT": "support_platform",
    "ANALYTICS_PROFILE": "analytics_platform", "PRODUCT_TELEMETRY": "analytics_platform",
    "USER_EXPORT": "export_service", "MARKETING_PROFILE": "marketing_platform",
    "EMAIL_DELIVERY_LOG": "email_delivery_service", "SECURITY_AUDIT_LOG": "security_service",
    "LEGAL_HOLD_RECORD": "legal_retention_service", "BACKUP_ARCHIVE": "backup_service",
    "ACCOUNT_TOMBSTONE": "identity_service", "DATA_FLOW": "integration_service",
}
PREFIX_CATEGORY = {
    "account": "USER_PROFILE", "secondary_identifier": "SECONDARY_IDENTIFIER",
    "search": "SEARCH_INDEX_ENTRY", "cache": "CACHE_ENTRY",
    "support": "SUPPORT_MESSAGE", "attachment": "SUPPORT_ATTACHMENT",
    "analytics": "ANALYTICS_PROFILE", "telemetry": "PRODUCT_TELEMETRY",
    "export": "USER_EXPORT", "marketing": "MARKETING_PROFILE",
    "email_delivery": "EMAIL_DELIVERY_LOG", "delivery_log": "EMAIL_DELIVERY_LOG",
    "email_log": "EMAIL_DELIVERY_LOG", "audit_record": "SECURITY_AUDIT_LOG",
    "legal_hold": "LEGAL_HOLD_RECORD", "backup": "BACKUP_ARCHIVE",
    "tombstone": "ACCOUNT_TOMBSTONE", "data_flow": "DATA_FLOW",
}
FUNCTION_SYSTEM = {
    "profile_service": "account_service", "customer_profile_service": "account_service",
    "search_index_service": "search_service", "support_service": "support_platform",
    "analytics_service": "analytics_platform", "connector_service": "integration_service",
    "restore_service": "backup_service", "audit_service": "security_service",
    "support_replica": "support_platform", "marketing_service": "marketing_platform",
}


def scalar(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False) if isinstance(value, (list, dict)) else str(value or "")


def unpack(raw: dict[str, Any]) -> dict[str, Any]:
    result = dict(raw)
    for key in ("record_json", "payload_json", "data_json"):
        if isinstance(result.get(key), str):
            try:
                inner = json.loads(result[key])
            except (ValueError, TypeError):
                continue
            if isinstance(inner, dict):
                result.pop(key)
                result.update(inner)
    return result


def infer_category(raw: dict[str, Any], collection: str = "", resource: str = "") -> str:
    for field in ("data_category", "category", "record_type", "resource_type"):
        value = str(raw.get(field) or "").upper().replace("-", "_")
        if value == "ACTIVE_DATA_FLOW":
            value = "DATA_FLOW"
        if value in CATEGORY_SYSTEM:
            return value
    table = collection.lower()
    if "contact_lookup" in table or "contact_query" in table:
        return "SECONDARY_IDENTIFIER"
    for fragment, cat in (
        ("tombstone", "ACCOUNT_TOMBSTONE"), ("deleted_customer_reference", "ACCOUNT_TOMBSTONE"),
        ("attachment", "SUPPORT_ATTACHMENT"), ("support", "SUPPORT_MESSAGE"),
        ("telemetry", "PRODUCT_TELEMETRY"), ("analytics", "ANALYTICS_PROFILE"),
        ("search", "SEARCH_INDEX_ENTRY"), ("cache", "CACHE_ENTRY"),
        ("export", "USER_EXPORT"), ("connector", "DATA_FLOW"),
        ("subscription", "DATA_FLOW"), ("backup", "BACKUP_ARCHIVE"),
        ("restore", "BACKUP_ARCHIVE"), ("security_audit", "SECURITY_AUDIT_LOG"),
        ("audit_record", "SECURITY_AUDIT_LOG"), ("legal_hold", "LEGAL_HOLD_RECORD"),
        ("marketing", "MARKETING_PROFILE"), ("email_delivery", "EMAIL_DELIVERY_LOG"),
        ("secondary_identifier", "SECONDARY_IDENTIFIER"), ("customer_profile", "USER_PROFILE"),
    ):
        if fragment in table:
            return cat
    for prefix in sorted(PREFIX_CATEGORY, key=len, reverse=True):
        if resource.lower().startswith(prefix + "_"):
            return PREFIX_CATEGORY[prefix]
    return ""


def system_name(value: Any, category: str) -> str:
    text = str(value or "").strip().lower().replace("-", "_")
    text = FUNCTION_SYSTEM.get(text, text)
    if text in CATEGORY_SYSTEM.values():
        return text
    if text.endswith(("_service", "_platform")) and text not in {"records_assurance_service", "profile_service"}:
        return text
    if re.fullmatch(r"[a-z][a-z0-9_]+", text) and text not in {"records_assurance_service", "log_router"}:
        return text
    return CATEGORY_SYSTEM.get(category, "")


def resource_id(raw: dict[str, Any]) -> str:
    # Explicit fields are authoritative identifiers; no lexical prefix shortcut.
    for key in ("resource_id", "record_id", "object_id", "entry_id"):
        if raw.get(key):
            return str(raw[key]).strip()
    return ""


def direct_state(raw: dict[str, Any], category: str, hint: str = "") -> str:
    raw_state = str(raw.get("state") or raw.get("result") or "").upper()
    if raw_state in {"ABSENT", "NOT_FOUND", "PRESENT", "FOUND", "IDENTIFIABLE",
                     "REDACTED", "ANONYMIZED", "ACTIVE", "DISABLED", "BLOCKED"}:
        hint = {"NOT_FOUND": "ABSENT", "FOUND": "PRESENT", "IDENTIFIABLE": "PRESENT"}.get(raw_state, raw_state)
    def boolean(value):
        text = str(value).lower()
        return True if text in {"1", "true", "yes", "enabled", "allowed"} else False if text in {"0", "false", "no", "disabled", "blocked"} else None
    if category == "DATA_FLOW":
        enabled = boolean(raw.get("enabled", raw.get("active")))
        return ("ACTIVE" if enabled else "DISABLED") if enabled is not None else (hint or "ACTIVE")
    if category == "BACKUP_ARCHIVE":
        blocked = boolean(raw.get("deletion_block"))
        if blocked is not None:
            return "BLOCKED" if blocked else "ACTIVE"
        allowed = boolean(raw.get("restore_allowed", raw.get("restore_access")))
        return ("ACTIVE" if allowed else "BLOCKED") if allowed is not None else (hint or "ACTIVE")
    for key in ("rows", "total_rows", "total_hits"):
        if key in raw:
            try:
                return "ABSENT" if int(raw[key]) == 0 else "PRESENT"
            except (ValueError, TypeError):
                pass
    status = str(raw.get("http_status", raw.get("status_code", "")))
    if status == "404":
        return "ABSENT"
    if isinstance(raw.get("hits"), dict) and "total" in raw["hits"]:
        total = raw["hits"]["total"]
        if isinstance(total, dict):
            total = total.get("value")
        return "ABSENT" if total == 0 else "PRESENT"
    result = str(raw.get("lookup_result", raw.get("result", ""))).lower()
    if result in {"not_found", "absent", "no_match", "miss"}:
        return "ABSENT"
    if result in {"hit", "found", "present", "match"}:
        return "PRESENT"
    if hint:
        return {"NOT_FOUND": "ABSENT", "FOUND": "PRESENT", "IDENTIFIABLE": "PRESENT"}.get(hint, hint)
    return "PRESENT"


def observation(raw, *, meta, system="", category="", collection="", observed="", hint="", kind="", priority=90, proof=True, context=None):
    raw = unpack(raw)
    rid = resource_id(raw)
    if not rid:
        return None
    category = category or infer_category(raw, collection, rid)
    system = system_name(raw.get("origin_system") or raw.get("system_id") or raw.get("system") or system, category)
    if not category or not system:
        return None
    raw = dict(raw)
    raw.setdefault("_context", dict(context or {}, collection=collection))
    text = json.dumps(raw, ensure_ascii=False, sort_keys=True)
    uid = next((str(raw[key]) for key in ("user_id", "customer_reference", "subject_reference", "subject_ref") if raw.get(key)), "")
    return dict(system_id=system, resource_id=rid, user_id=uid, category=category,
                observed_at=observed or meta["captured_at"], capture_at=meta["captured_at"],
                source_available_at=meta.get("available_at", meta["captured_at"]),
                evidence_id=meta["file_id"], source_path=meta["file_path"],
                source_priority=priority, source_kind=kind, raw=raw, text=text,
                state_hint=direct_state(raw, category, hint), relations=[], scope_complete=False,
                proof=proof)


def sql_observations(path: Path, meta: dict) -> list[dict]:
    text = path.read_text(encoding="utf-8")
    captured = re.search(r"--\s*Captured at:\s*(\S+)", text)
    snapshot_at = captured.group(1) if captured else meta["captured_at"]
    topology_match = re.search(r"--\s*Database topology:\s*(\S+)", text)
    topology = topology_match.group(1) if topology_match else path.stem
    db = sqlite3.connect(":memory:")
    db.execute("PRAGMA temp_store=MEMORY")
    if hasattr(db, "enable_load_extension"):
        db.enable_load_extension(False)
    allowed = {sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_CREATE_INDEX,
               sqlite3.SQLITE_INSERT, sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ,
               sqlite3.SQLITE_TRANSACTION, sqlite3.SQLITE_REINDEX}
    def authorize(action, a, b, database, trigger):
        if action in allowed:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_UPDATE and a == "sqlite_master":
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_PRAGMA and a == "foreign_keys":
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_FUNCTION and str(b or a).lower() == "json_valid":
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY
    db.set_authorizer(authorize)
    budget = [0]
    def progress():
        budget[0] += 1
        return int(budget[0] > 20000)
    db.set_progress_handler(progress, 1000)
    try:
        db.executescript(text)
        tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        scopes = {}
        if "snapshot_scope" in tables:
            scopes = dict(db.execute("SELECT origin_system,captured_at FROM snapshot_scope"))
        out = []
        for table in tables:
            if table == "snapshot_scope":
                continue
            safe_table = '"' + table.replace('"', '""') + '"'
            cursor = db.execute("SELECT * FROM " + safe_table)
            columns = [d[0] for d in cursor.description]
            records = [unpack(dict(zip(columns, row))) for row in cursor]
            grouped = defaultdict(list)
            table_cat = infer_category({}, table)
            if table_cat:
                grouped[(CATEGORY_SYSTEM[table_cat], table_cat, table)] = []
            for record in records:
                collection = str(record.get("collection_name") or table)
                cat = infer_category(record, collection, resource_id(record))
                system = system_name(record.get("origin_system"), cat)
                if not cat or not system:
                    continue
                grouped[(system, cat, collection)].append(resource_id(record))
                obs = observation(record, meta=meta, system=system, category=cat,
                                  collection=collection, observed=scopes.get(system, snapshot_at),
                                  kind="sql_snapshot", priority=100,
                                  context={"database_topology": topology, "table": table})
                if obs:
                    obs["scope_complete"] = True
                    out.append(obs)
            for (system, cat, collection), present in grouped.items():
                # The capture is a complete table, not a filename-based case list.
                raw = dict(table=table, collection=collection, topology=topology,
                           resource_ids=present, category=cat,
                           _context={"database_topology": topology, "collection": table})
                out.append(dict(system_id=system, resource_id="", category=cat,
                                observed_at=scopes.get(system, snapshot_at), capture_at=meta["captured_at"],
                                source_available_at=meta["captured_at"], evidence_id=meta["file_id"],
                                source_path=meta["file_path"], source_kind="sql_scope", source_priority=95,
                                scope_complete=True, raw=raw, text="", state_hint="", proof=True))
        return out
    finally:
        db.close()


def json_observations(path: Path, meta: dict) -> list[dict]:
    document = json.loads(path.read_text(encoding="utf-8"))
    out = []
    outer_export = document.get("exported_at", "") if isinstance(document, dict) else ""
    meta = dict(meta, available_at=max(meta["captured_at"], str(outer_export)))
    def visit(value, context):
        if isinstance(value, list):
            for child in value:
                visit(child, context)
            return
        if not isinstance(value, dict):
            return
        ctx = dict(context)
        for key in ("captured_at", "data_store", "origin_system", "system_id", "collection", "collection_name", "replica"):
            if value.get(key) is not None:
                ctx[key] = value[key]
        raw = unpack(value)
        rid = resource_id(raw)
        if rid:
            # Direct API reads carry observed_at; snapshots carry captured_at.
            at = str(raw.get("observed_at") or ctx.get("captured_at") or meta["captured_at"])
            collection = str(raw.get("collection_name") or ctx.get("collection_name") or ctx.get("collection") or "")
            system = raw.get("origin_system") or ctx.get("data_store") or ctx.get("origin_system") or ctx.get("system_id")
            obs = observation(raw, meta=meta, system=system, collection=collection,
                              observed=at, kind="json_record", priority=90, context=ctx)
            if obs:
                out.append(obs)
        for key, child in value.items():
            if not isinstance(child, (dict, list)):
                continue
            next_ctx = dict(ctx)
            if key in CATEGORY_SYSTEM.values():
                next_ctx["data_store"] = key
            if key not in {"service_exports", "snapshots", "records", "items", "profile", "hits", "documents"}:
                next_ctx["collection"] = key
            visit(child, next_ctx)
    visit(document, {})
    return out


def parse_key_values(text: str) -> dict[str, Any]:
    result = {}
    for match in KV_RE.finditer(text):
        key, value = match.groups()
        if value.startswith('"'):
            try:
                value = json.loads(value)
            except ValueError:
                value = value[1:-1].replace('\\"', '"')
        elif value.startswith("'"):
            value = value[1:-1]
        result[key.lower()] = value
    return result


def log_line(line: str) -> dict | None:
    time = TIME_RE.search(line)
    if not time:
        return None
    tail = line[time.end():].strip()
    raw = {}
    if tail.startswith("{"):
        try:
            value = json.loads(tail)
            if isinstance(value, dict):
                raw.update(value)
        except ValueError:
            pass
    if "|" in tail:
        pieces = [piece.strip() for piece in tail.split("|")]
        pieces = [piece for piece in pieces if piece]
        if len(pieces) >= 4:
            raw.update(level=pieces[0], service=pieces[1], trace_id=pieces[2], event=pieces[3])
    bracket = re.match(r"\[(\w+)\]\s*\[([^]]+)\]\s*\[([^]]+)\]\s*([\w.-]+):", tail)
    if bracket:
        raw.update(level=bracket[1], service=bracket[2], trace_id=bracket[3], event=bracket[4])
    syslog = re.match(r"<\d+>1\s+\S+\s+(\S+)\s+(\S+)\s", tail)
    if syslog:
        raw.update(service=syslog[1], trace_id=syslog[2])
    raw.update(parse_key_values(tail))
    message = raw.get("message")
    if isinstance(message, str):
        raw.update(parse_key_values(message))
        try:
            body = json.loads(message)
            if isinstance(body, dict):
                raw.update(body)
        except ValueError:
            pass
    for key in ("payload", "fields", "attributes", "context"):
        if isinstance(raw.get(key), dict):
            raw.update(raw[key])
    raw["_observed_at"] = time.group(0).replace(" ", "T")
    raw["_line"] = line
    raw["service"] = raw.get("service") or raw.get("function") or raw.get("logger")
    raw["trace_id"] = raw.get("trace_id") or raw.get("requestid") or raw.get("requestId") or raw.get("correlation_id")
    raw["event"] = raw.get("event") or raw.get("event_type") or raw.get("operation")
    return raw


def log_observations(path: Path, meta: dict) -> list[dict]:
    groups = defaultdict(list)
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        raw = log_line(line)
        if raw:
            groups[(str(raw.get("service")), str(raw.get("trace_id") or f"line-{number}"))].append(raw)
    out = []
    for (service, trace), events in groups.items():
        # A trace may read several resources: keep its query context, but never
        # overwrite one returned record with another returned record's fields.
        shared = {}
        by_resource = defaultdict(list)
        for event in events:
            rid = resource_id(event)
            if rid:
                by_resource[rid].append(event)
            else:
                for key, value in event.items():
                    if key in {"lookup_key", "match_key", "scan_key", "subject_key", "subject_ref", "customer_reference", "correlation_key", "query", "user_id"}:
                        shared[key] = value
        for rid, records in by_resource.items():
            raw = {"_query_context": dict(shared)}
            for record in records:
                # Intermediate cache misses are not final database misses.
                if record.get("event") == "cache_lookup":
                    continue
                raw.update({key: value for key, value in record.items() if not key.startswith("_")})
            raw["resource_id"] = rid
            event_names = " ".join(str(record.get("event") or "") for record in records)
            raw["_event_names"] = event_names
            if "record_lookup" in event_names:
                # This is the lookup's subject selector, not a retained field
                # in an anonymized/redacted record returned by that lookup.
                for field in ("subject_reference", "lookup_key", "subject_key"):
                    if field in raw:
                        raw["_query_context"][field] = raw.pop(field)
            cat = infer_category(raw, event_names, rid)
            proof = bool(any(key in raw for key in ("rows", "total_rows", "total_hits", "http_status", "status_code", "enabled", "restore_allowed", "eligible", "deletion_block", "matched_value", "direct_identifiers")) or re.search(r"(?:read|query|lookup|scan|inspect|fetch).*(?:completed|result)|pii_scan|record_lookup", event_names))
            if re.search(r"attachment", event_names):
                cat = "SUPPORT_ATTACHMENT"
            obs = observation(raw, meta=meta, system=service, category=cat,
                              collection=event_names, observed=max(r["_observed_at"] for r in records),
                              kind="log_trace", priority=85, proof=proof)
            if obs:
                out.append(obs)
    return out


def normalized_ocr(text: str) -> str:
    text = re.sub(r"\b(account|search|support|analytics|export|backup|tombstone|marketing)\s+(\d+)\b", r"\1_\2", text, flags=re.I)
    # Generic, documented OCR confusions in common mailbox domains.
    text = re.sub(r"@gmall\.com\b", "@gmail.com", text, flags=re.I)
    text = re.sub(r"@outiook\.com\b", "@outlook.com", text, flags=re.I)
    text = re.sub(r"([\w.]+),([\w.]+@)", r"\1.\2", text)
    return text


def media_observations(path: Path, meta: dict) -> list[dict]:
    extracted = ({"text": path.read_text(encoding="utf-8"), "method": "text_document", "warnings": []}
                 if path.suffix.lower() == ".txt" else media.extract_media(path))
    for warning in extracted.get("warnings", []):
        WARNINGS.append(f"{meta['file_id']}: {warning}")
    text = normalized_ocr(extracted.get("text", ""))
    MEDIA_TEXT[meta["file_id"]] = text
    lines = text.splitlines()
    # Explicit handover rows have stronger structure than business UI OCR.
    out = []
    for line in lines:
        fields = [part.strip() for part in line.lstrip("- ").split("|")]
        if len(fields) >= 6 and TIME_RE.fullmatch(fields[0]) and fields[3] in CATEGORY_SYSTEM:
            raw = dict(resource_id=fields[2], lookup_key=fields[5], source_excerpt=line)
            for email in EMAIL_RE.findall(fields[5]):
                raw["email"] = email
            uid = USER_RE.search(fields[5])
            if uid:
                raw["customer_reference"] = uid.group(0)
            hint = fields[4].upper()
            if hint == "ANONYMIZED":
                raw = dict(resource_id=fields[2], email=None, customer_reference=None, source_excerpt=line)
            obs = observation(raw, meta=meta, system=fields[1], category=fields[3],
                              observed=fields[0], hint=hint, kind="text_record", priority=90)
            if obs:
                out.append(obs)
    if out:
        return out
    mentions = [(i, match.group(0)) for i, line in enumerate(lines) for match in RESOURCE_RE.finditer(line)]
    if not mentions:
        return []
    # Classify the artifact, not common toolbar labels such as Search/Export.
    # File type hints do not establish subject membership; row content does.
    title = path.stem.lower()
    preferred = ""
    for words, prefix in (("search", "search_"), ("connector", "data_flow_"),
                          ("analytics", "analytics_"), ("export", "export_"),
                          ("backup", "backup_"), ("support_ticket", "support_"),
                          ("security", "audit_record_"), ("marketing", "marketing_"),
                          ("account_admin", "account_")):
        if words in title:
            preferred = prefix
            break
    if preferred:
        mentions = [(i, rid) for i, rid in mentions if rid.lower().startswith(preferred)]
    selected_audit = re.search(r"(audit_record_\d+)\s*[-–]\s*Raw event", text, re.I)
    if selected_audit:
        mentions = [(i, rid) for i, rid in mentions if rid.lower() == selected_audit[1].lower()]
    chunks = defaultdict(list)
    for position, (line_no, rid) in enumerate(mentions):
        next_line = mentions[position + 1][0] if position + 1 < len(mentions) else len(lines)
        end = max(line_no + 1, next_line)
        chunks[rid].append("\n".join(lines[line_no:end]))
    unique = set(chunks)
    for rid, excerpts in chunks.items():
        excerpt = "\n".join(excerpts)
        if len(unique) == 1:
            excerpt = text
        raw = dict(resource_id=rid, source_excerpt=excerpt)
        emails = list(dict.fromkeys(EMAIL_RE.findall(excerpt)))
        if emails:
            raw["emails"] = emails
        uid = USER_RE.search(excerpt)
        if uid:
            raw["customer_reference"] = uid.group(0)
        cat = infer_category(raw, "", rid)
        if cat == "SUPPORT_MESSAGE" and re.search(r"attachment properties|uploader customer|identity document", text, re.I):
            cat = "SUPPORT_ATTACHMENT"
        hint = "PRESENT"
        if cat == "DATA_FLOW":
            hint = "DISABLED" if re.search(r"\b(disabled|stopped|inactive)\b", excerpt, re.I) else "ACTIVE"
        if cat == "BACKUP_ARCHIVE":
            hint = "BLOCKED" if re.search(r"restore.{0,20}(blocked|disabled|denied)", excerpt, re.I) else "ACTIVE"
        obs = observation(raw, meta=meta, category=cat, hint=hint,
                          kind=extracted.get("method", "media"), priority=75)
        if obs:
            out.append(obs)
    return out


def load_observations(dataset: Path) -> list[dict]:
    """Load all participant-visible evidence, preserving availability cutoffs."""
    dataset = Path(dataset)
    WARNINGS.clear()
    MEDIA_TEXT.clear()
    with (dataset / "evidence_files.csv").open(encoding="utf-8-sig", newline="") as stream:
        manifest = list(csv.DictReader(stream))
    out = []
    root = dataset.resolve()
    for meta in manifest:
        path = (dataset / meta["file_path"]).resolve()
        if root not in path.parents or not path.is_file() or path.stat().st_size > MAX_BYTES:
            raise ValueError(f"Unsafe or missing evidence path: {meta['file_id']}")
        try:
            if path.suffix == ".sql":
                out.extend(sql_observations(path, meta))
            elif path.suffix == ".json":
                out.extend(json_observations(path, meta))
            elif path.suffix == ".log":
                out.extend(log_observations(path, meta))
            else:
                out.extend(media_observations(path, meta))
        except (OSError, ValueError, sqlite3.Error) as error:
            raise ValueError(f"Evidence extraction failed for {meta['file_id']}: {error}") from error
    # Catalog identity links can connect a business filename to its actual
    # object ID without assuming that storage IDs encode a user or case number.
    # The catalog establishes ownership; the independently captured listing
    # establishes presence. Both must be available before a case's audit.
    activity_path = dataset / "system_activity.csv"
    if activity_path.is_file():
        with activity_path.open(encoding="utf-8-sig", newline="") as stream:
            activities = list(csv.DictReader(stream))
        for activity in activities:
            if activity.get("event_type") != "LINK_RESOURCE_IDENTITY":
                continue
            details = activity.get("details", "")
            match = re.search(r"\(([^()]+\.(?:pdf|png|jpe?g|zip|csv|json|txt))\)", details, re.I)
            if not match:
                continue
            filename = match.group(1)
            if "attachment" in details.lower() and re.search(r"only|sole|no other subject", details, re.I):
                cat = "SUPPORT_ATTACHMENT"
            elif "export" in details.lower():
                cat = "USER_EXPORT"
            else:
                continue
            for meta in manifest:
                text = MEDIA_TEXT.get(meta["file_id"], "")
                if filename.casefold() not in text.casefold():
                    continue
                excerpt = "\n".join(line for line in text.splitlines()
                                    if filename.casefold() in line.casefold())
                available = max(meta["captured_at"], activity["event_time"])
                joined_meta = dict(meta, available_at=available)
                raw = dict(resource_id=activity["resource_id"], file_name=filename,
                           source_excerpt=excerpt,
                           _catalog_activity_id=activity["activity_id"])
                obs = observation(raw, meta=joined_meta,
                                  system=activity["target_system"], category=cat,
                                  hint="PRESENT", kind="catalog_media_join", priority=90)
                if obs:
                    out.append(obs)
    return out
