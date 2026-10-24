#!/usr/bin/env python3
"""Temporal deletion audit with evidence-backed, deterministic policy decisions.

The inference path reads participant-facing inputs only. Public golden answers
are used exclusively by the separate evaluation program.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from evidence import load_observations

ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = {
    "FINDING": ["REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII",
                "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"],
    "REMEDIATION": ["DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD",
                    "REDACT_RECORD", "ANONYMIZE_RECORD"],
    "VERIFICATION": ["VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT",
                     "VERIFY_RECORD_REDACTED", "VERIFY_RECORD_ANONYMIZED",
                     "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"],
}
PHASE_ORDER = {phase: i for i, phase in enumerate(OPERATIONS)}
RESOURCE_PATTERN = re.compile(
    r"(?<![\w-])(?:account|search|support|attachment|analytics|export|data_flow|"
    r"backup|audit_record|tombstone|cache|email_delivery|legal_hold|marketing)"
    r"_[A-Za-z0-9-]+(?![\w-])", re.I)
EMAIL_PATTERN = re.compile(r"[\w.!#$%&'*+/=?^`{|}~-]+@[\w.-]+\.[A-Za-z]{2,}", re.I)
USER_PATTERN = re.compile(r"(?<![\w-])user_[A-Za-z0-9-]+(?![\w-])", re.I)
HASH_PATTERN = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", re.I)
EMPTY_VALUES = {"", "none", "null", "n/a", "-", "[redacted]", "redacted",
                "removed", "not available", "no direct identifier"}
PII_NAMES = {"name", "full_name", "display_name", "requester_name", "customer_name",
             "email", "phone", "email_hash", "requester_email", "requester_phone",
             "owner_email", "owner_phone", "customer_email", "customer_phone",
             "subject_email", "subject_phone", "contact_email", "contact_phone",
             "emails", "phones", "email_addresses", "matched_value",
             "matched_identifier", "identifier_value"}
CATEGORY_BY_PREFIX = {
    "account": "USER_PROFILE", "search": "SEARCH_INDEX_ENTRY",
    "support": "SUPPORT_MESSAGE", "attachment": "SUPPORT_ATTACHMENT",
    "analytics": "ANALYTICS_PROFILE", "export": "USER_EXPORT",
    "data_flow": "DATA_FLOW", "backup": "BACKUP_ARCHIVE",
    "audit_record": "SECURITY_AUDIT_LOG", "tombstone": "ACCOUNT_TOMBSTONE",
    "cache": "CACHE_ENTRY", "email_delivery": "EMAIL_DELIVERY_LOG",
    "legal_hold": "LEGAL_HOLD_RECORD", "marketing": "MARKETING_PROFILE",
}


def timestamp(value: Any) -> datetime:
    """An invalid/missing timestamp is never evidence of a future mutation."""
    try:
        result = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
        return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result
    except (TypeError, ValueError):
        return datetime.min.replace(tzinfo=timezone.utc)


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def normalize(value: Any) -> str:
    return unicodedata.normalize("NFKC", str(value or "")).strip().casefold()


def phone_key(value: Any) -> str:
    return "".join(re.findall(r"\d", str(value or "")))


def walk_values(value: Any, prefix: str = ""):
    if isinstance(value, dict):
        for key, child in value.items():
            name = str(key).lower()
            yield from walk_values(child, name)
    elif isinstance(value, list):
        for child in value:
            yield from walk_values(child, prefix)
    elif value is not None:
        yield prefix, str(value)


def identifiers(value: Any, text: str = "") -> set[str]:
    """Extract exact identity tokens; resource IDs and common names are not identities."""
    answer: set[str] = set()
    strings = [str(text)]
    for key, item in walk_values(value):
        strings.append(item)
        if "phone" in key or key in {"mobile", "telephone", "msisdn"}:
            digits = phone_key(item)
            if len(digits) >= 7:
                answer.add("phone:" + digits)
    for string in strings:
        answer.update(normalize(x) for x in EMAIL_PATTERN.findall(string))
        answer.update(normalize(x) for x in USER_PATTERN.findall(string))
        answer.update(normalize(x) for x in HASH_PATTERN.findall(string))
        for phone in re.findall(r"(?<!\w)\+\d[\d ()-]{6,}\d(?!\w)", string):
            if len(phone_key(phone)) >= 7:
                answer.add("phone:" + phone_key(phone))
    return answer


def deletion(text: str) -> bool:
    """Authorize the requested act, rather than trusting workflow metadata.

    Accent folding supports Latin-language variants. Non-Latin verbs are
    ordinary semantic vocabulary, not request IDs or dataset-label shortcuts.
    Explicit negation and marketing-only requests take precedence.
    """
    original = normalize(text).replace("\u2019", "'")
    folded = "".join(ch for ch in unicodedata.normalize("NFKD", original)
                     if not unicodedata.combining(ch))
    negatives = [
        r"\b(?:do not|don't|never)\s+(?:delete|erase|remove|change|close)",
        r"\bnot\s+(?:a\s+)?request\s+to\s+(?:erase|delete|remove)",
        r"\b(?:without|rather than)\s+(?:delet|eras|remov)",
        r"\bnot\s+(?:a\s+)?(?:account\s+)?(?:deletion|erasure)",
        r"\bnot\s+(?:asking|requesting).{0,25}\b(?:deletion|erasure)",
        r"\b(?:marketing lists|promotional emails|marketing messages)\b.{0,15}\bonly\b",
        r"\bonly\b.{0,30}\b(?:unsubscribe|opt.?out|marketing)",
        r"\bne\b.{0,30}\bpas\b.{0,20}\b(?:supprim|effac)",
    ]
    if any(re.search(pattern, folded) for pattern in negatives):
        return False
    positive = (
        r"delet|eras(?:e|ed|ure)|remov|clos(?:e|ed|ing)|elimin|suppr|"
        r"exclus|borrar|apagar|effac|losch|loesch|entfern|"
        r"\u524a\u9664|\u524a\u9664|\u5220\u9664|\u522a\u9664|"
        r"\uc0ad\uc81c|\u0443\u0434\u0430\u043b|\u062d\u0630\u0641"
    )
    authorized = bool(re.search(positive, folded) or re.search(positive, original))
    authorized |= bool(re.search(r"(?:profile|account).{0,30}(?:gone|fully removed)", folded))
    if not authorized:
        return False
    # "Remove me from marketing lists" is a limited opt-out, not erasure.
    if re.search(r"marketing|promotional|unsubscribe|opt.?out", folded):
        account_erasure = re.search(
            r"(?:delet|eras|clos|remov).{0,45}(?:account|profile|personal)|"
            r"(?:account|profile|personal).{0,45}(?:delet|eras|clos|remov)", folded)
        if not account_erasure:
            return False
    return True


def category(observation: dict[str, Any]) -> str:
    value = str(observation.get("category") or "").upper()
    value = {"ACTIVE_DATA_FLOW": "DATA_FLOW"}.get(value, value)
    if value:
        return value
    resource = observation.get("resource_id", "")
    for prefix in sorted(CATEGORY_BY_PREFIX, key=len, reverse=True):
        if resource.startswith(prefix + "_"):
            return CATEGORY_BY_PREFIX[prefix]
    return value


def truth(value: Any) -> bool | None:
    text = normalize(value)
    if text in {"true", "1", "yes", "enabled", "active", "allowed"}:
        return True
    if text in {"false", "0", "no", "disabled", "blocked", "inactive", "denied"}:
        return False
    return None


def flatten(raw: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in walk_values(raw)}


def has_pii(raw: dict[str, Any], *, anonymize: bool = False) -> bool:
    def stored_fields(value, prefix=""):
        if isinstance(value, dict):
            for field, child in value.items():
                if not str(field).startswith("_"):
                    yield from stored_fields(child, str(field).lower())
        elif isinstance(value, list):
            for child in value:
                yield from stored_fields(child, prefix)
        elif value is not None:
            yield prefix, str(value)
    for key, value in stored_fields(raw):
        if key in PII_NAMES and normalize(value) not in EMPTY_VALUES:
            return True
        if anonymize and key in {"customer_reference", "subject_reference", "user_id"}:
            if normalize(value) not in EMPTY_VALUES:
                return True
        if key in {"message_excerpt", "body", "message", "content", "text"}:
            if EMAIL_PATTERN.search(value) or HASH_PATTERN.search(value):
                return True
    return False


def resource_state(observation: dict[str, Any], cat: str) -> str:
    """Interpret a direct read/snapshot; successful mutation claims are not proof."""
    raw = observation.get("raw") or {}
    flat = flatten(raw)
    hint = str(observation.get("state_hint") or "").upper()
    aliases = {"NOT_FOUND": "ABSENT", "MISSING": "ABSENT", "FOUND": "PRESENT",
               "IDENTIFIABLE": "PRESENT", "DELETED": "ABSENT", "INACTIVE": "DISABLED"}
    hint = aliases.get(hint, hint)
    if cat == "DATA_FLOW":
        enabled = truth(flat.get("enabled"))
        if enabled is not None:
            return "ACTIVE" if enabled else "DISABLED"
        return hint if hint in {"ACTIVE", "DISABLED", "ABSENT"} else "UNKNOWN"
    if cat == "BACKUP_ARCHIVE":
        allowed = truth(flat.get("restore_allowed", flat.get("restore_access")))
        if allowed is not None:
            return "ACTIVE" if allowed else "BLOCKED"
        return hint if hint in {"ACTIVE", "BLOCKED", "ABSENT"} else "UNKNOWN"
    count = flat.get("rows", flat.get("total_rows", flat.get("total_hits")))
    if count is not None:
        try:
            hint = "ABSENT" if int(count) == 0 else "PRESENT"
        except (ValueError, TypeError):
            pass
    if str(flat.get("status_code", flat.get("http_status", ""))) == "404":
        hint = "ABSENT"
    if hint == "ABSENT":
        return hint
    if str(flat.get("result", "")).upper() == "IDENTIFIABLE":
        return "PRESENT"
    if str(flat.get("direct_identifiers", "")) not in {"", "0"}:
        if cat in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY", "SUPPORT_MESSAGE",
                   "EMAIL_DELIVERY_LOG", "ACCOUNT_TOMBSTONE"}:
            return "PRESENT"
    if cat in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        if has_pii(raw, anonymize=True):
            return "PRESENT"
        if hint in {"ANONYMIZED", "PRESENT", "REDACTED"} or raw:
            return "ANONYMIZED"
    if cat in {"SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG", "ACCOUNT_TOMBSTONE"}:
        if has_pii(raw):
            return "PRESENT"
        if hint in {"REDACTED", "PRESENT", "ANONYMIZED"} or raw:
            return "REDACTED"
    return hint if hint in {"PRESENT", "ABSENT", "REDACTED", "ANONYMIZED"} else "PRESENT"


def evidence_rank(observation: dict[str, Any]):
    return (timestamp(observation.get("observed_at")),
            timestamp(observation.get("capture_at", observation.get("captured_at"))),
            int(observation.get("source_priority") or 0),
            observation.get("evidence_id", ""))


def is_state_proof(observation: dict[str, Any]) -> bool:
    if observation.get("is_claim") or observation.get("proof") is False:
        return False
    kind = str(observation.get("source_kind", "")).lower()
    if kind in {"activity", "activity_claim", "operation", "mutation_claim"}:
        return bool(observation.get("direct_check"))
    return True


class DatasetIndex:
    """Parse evidence once, then answer cases from a temporal resource graph."""

    def __init__(self, dataset: str | Path):
        self.dataset = Path(dataset)
        self.users: dict[str, set[str]] = {}
        self.alias: dict[str, set[str]] = defaultdict(set)
        self.rules = rows(self.dataset / "deletion_rules.csv")
        identity_rows = rows(self.dataset / "user_identities.csv")
        audit_rows = rows(self.dataset / "user_audit_log.csv")
        self.name_owners: dict[str, set[str]] = defaultdict(set)
        for row in identity_rows:
            if normalize(row.get("name")) not in EMPTY_VALUES:
                self.name_owners[normalize(row["name"])].add(normalize(row["user_id"]))
        for row in audit_rows:
            if row.get("field_name") in {"name", "full_name"}:
                for field in ("old_value", "new_value"):
                    if normalize(row.get(field)) not in EMPTY_VALUES:
                        self.name_owners[normalize(row[field])].add(normalize(row["user_id"]))
        self.unique_names = {name: next(iter(owners)) for name, owners in self.name_owners.items()
                             if len(owners) == 1 and len(name.split()) >= 2}
        self.name_pattern = (re.compile(r"(?<!\w)(?:" + "|".join(
            re.escape(name) for name in sorted(self.unique_names, key=len, reverse=True)) +
            r")(?!\w)") if self.unique_names else None)
        for row in identity_rows:
            user = normalize(row["user_id"])
            keys = identifiers(row)
            if row.get("phone"):
                keys.add("phone:" + phone_key(row["phone"]))
            keys.add(user)
            self.users[user] = keys
            for key in keys:
                self.alias[key].add(user)
        for name, owner in self.unique_names.items():
            self.users.setdefault(owner, {owner}).add("name:" + name)
        for row in audit_rows:
            if row.get("field_name") not in {"email", "phone", "email_hash", "user_id"}:
                continue
            user = normalize(row["user_id"])
            keys = identifiers({"text": row["old_value"] + " " + row["new_value"]})
            if row["field_name"] == "phone":
                keys.update("phone:" + phone_key(row[key]) for key in ("old_value", "new_value")
                            if row.get(key) and len(phone_key(row[key])) >= 7)
            self.users.setdefault(user, {user}).update(keys)
            for key in keys:
                self.alias[key].add(user)
        self.observations = load_observations(self.dataset)
        self.scopes = [obs for obs in self.observations
                       if obs.get("scope_complete") and not obs.get("resource_id")]
        self.activities = rows(self.dataset / "system_activity.csv")
        self.by_resource: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        self.subject_resources: dict[str, set[tuple[str, str]]] = defaultdict(set)
        self.resource_links: dict[str, list[tuple[str, Any, Any]]] = defaultdict(list)
        self.resource_keys: dict[str, set[tuple[str, str]]] = defaultdict(set)
        self.diagnostics: list[dict[str, Any]] = []
        for observation in self.observations:
            self._index(observation)
        self._index_activity_links()

    def _index(self, observation: dict[str, Any]):
        if not observation.get("system_id") or not observation.get("resource_id"):
            return
        key = observation["system_id"], observation["resource_id"]
        self.by_resource[key].append(observation)
        self.resource_keys[key[1]].add(key)
        values = identifiers(observation.get("raw") or {}, observation.get("text", ""))
        if self.name_pattern:
            scoped_text = normalize(observation.get("text", "")) + " " + normalize(
                json.dumps(observation.get("raw") or {}, ensure_ascii=False))
            values.update("name:" + match.group(0) for match in self.name_pattern.finditer(scoped_text))
        if observation.get("user_id"):
            values.add(normalize(observation["user_id"]))
        observation["_identity_tokens"] = values
        for token in values:
            self.subject_resources[token].add(key)
        resource_ids = {key[1]}
        lineage_fields = {"source_resource_id", "source_record_id", "source_account",
                          "source_account_id", "target_resource_id", "parent_resource_id",
                          "source_resource", "target_resource"}
        for field, value in walk_values(observation.get("raw") or {}):
            if field in lineage_fields:
                resource_ids.update(RESOURCE_PATTERN.findall(value))
        for relation in observation.get("relations") or []:
            if isinstance(relation, str):
                resource_ids.update(RESOURCE_PATTERN.findall(relation))
            elif isinstance(relation, dict):
                for _, value in walk_values(relation):
                    resource_ids.update(RESOURCE_PATTERN.findall(value))
        for resource in resource_ids:
            for target in resource_ids - {resource}:
                self.resource_links[resource].append(
                    (target, observation.get("observed_at"),
                     observation.get("capture_at", observation.get("captured_at"))))

    def _index_activity_links(self):
        # Activities establish lineage and identity links, never successful state.
        for activity in self.activities:
            resource = activity.get("resource_id", "")
            if not resource:
                continue
            references = {rid for rid in RESOURCE_PATTERN.findall(activity.get("details", ""))
                          if rid in self.resource_keys} | {resource}
            for source in references:
                for target in references - {source}:
                    self.resource_links[source].append(
                        (target, activity.get("event_time"), activity.get("event_time")))
            if activity.get("event_type") == "LINK_RESOURCE_IDENTITY":
                tokens = identifiers(activity)
                for token in tokens:
                    for key in self.resource_keys.get(resource, ()):
                        self.subject_resources[token].add(key)

    def identity(self, email: str) -> set[str]:
        token = normalize(email)
        candidates = self.alias.get(token, set())
        keys = {token}
        for user in candidates:
            keys.update(self.users[user])
        return keys

    def eligible(self, observation: dict[str, Any], cutoff: datetime) -> bool:
        capture = observation.get("source_available_at") or observation.get("capture_at", observation.get("captured_at"))
        return (timestamp(capture) <= cutoff and
                timestamp(observation.get("observed_at")) <= cutoff)

    def relevant(self, ids: set[str], cutoff: datetime,
                 case: dict[str, str] | None = None) -> dict[tuple[str, str], dict[str, Any]]:
        # Seed from historic identifier-bearing facts, and keep later clean facts
        # for the same resource even after their direct identifiers are removed.
        linked: set[tuple[str, str]] = set()
        for token in ids:
            for key in self.subject_resources.get(token, ()):
                if any(self.eligible(obs, cutoff) and
                       token in obs.get("_identity_tokens", ()) and
                       self.name_link_allowed(token, obs, ids)
                       for obs in self.by_resource[key]):
                    linked.add(key)
        # Link catalog identities only when that catalog event existed by cutoff.
        for activity in self.activities:
            if timestamp(activity.get("event_time")) > cutoff:
                continue
            if activity.get("event_type") == "LINK_RESOURCE_IDENTITY" and ids & identifiers(activity):
                linked.update(self.resource_keys.get(activity["resource_id"], ()))
        # A unique workflow event close to its report can identify the claimed
        # target when a deleted record has no remaining identifiers. It is NOT
        # proof of deletion; a separate eligible read/snapshot must prove state.
        if case:
            reported = timestamp(case.get("reported_at"))
            operations = {"DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD",
                          "DISABLE_DATA_FLOW", "BLOCK_RESTORE"}
            candidates = defaultdict(set)
            for activity in self.activities:
                at = timestamp(activity.get("event_time"))
                if (activity.get("event_type") in operations and at <= cutoff
                        and abs((reported - at).total_seconds()) <= 600):
                    candidates[(activity["event_type"], activity["target_system"])].add(activity["resource_id"])
            for (_operation, system), targets in candidates.items():
                if (len(targets) == 1
                        and not any(existing_system == system for existing_system, _ in linked)
                        and (system == "account_service" or not linked)):
                    resource = next(iter(targets))
                    linked.add((system, resource))
                    if hasattr(self, "diagnostics"):
                        self.diagnostics.append({"case_id": case.get("case_id"),
                            "method": "unique_temporal_claim_candidate",
                            "system_id": system, "resource_id": resource,
                            "window_seconds": 600})
        queue = [key[1] for key in linked]
        seen = set(queue)
        while queue:
            resource = queue.pop()
            # Same ID in a replica remains the same subject but a separate copy.
            linked.update(self.resource_keys.get(resource, ()))
            for target, observed, captured in self.resource_links.get(resource, ()):
                if target not in self.resource_keys:
                    continue
                if timestamp(observed) > cutoff or timestamp(captured) > cutoff:
                    continue
                if target not in seen:
                    seen.add(target)
                    queue.append(target)
                    linked.update(self.resource_keys.get(target, ()))
        latest = {}
        for key in linked:
            eligible = [obs for obs in self.by_resource[key]
                        if self.eligible(obs, cutoff) and is_state_proof(obs)]
            inferred_category = category({"resource_id": key[1]})
            # A complete table snapshot can prove a known target absent. A
            # partial excerpt or an unrelated system cannot establish absence.
            for scope in self.scopes:
                raw = scope.get("raw") or {}
                scope_category = category(scope) or str(raw.get("category") or raw.get("data_category") or "")
                present = raw.get("resource_ids", scope.get("resource_ids", []))
                if (scope.get("system_id") == key[0]
                        and scope_category == inferred_category
                        and key[1] not in present and self.eligible(scope, cutoff)
                        and any(rule["data_category"] == inferred_category
                                and rule["required_action"] == "DELETE" for rule in self.rules)):
                    absent = dict(scope)
                    absent.update(resource_id=key[1], category=inferred_category,
                                  state_hint="ABSENT", raw={"_context": raw.get("_context", {}),
                                  "_scope_table": raw.get("table", raw.get("table_name", "")),
                                  "_scope_topology": raw.get("topology", raw.get("database_topology", ""))})
                    eligible.append(absent)
            if eligible:
                # Keep a replica's last supported state separate from a clean
                # primary. A later primary read must not erase a replica ghost.
                locations = defaultdict(list)
                for observation in eligible:
                    locations[self.location(observation)].append(observation)
                states = [max(values, key=evidence_rank) for values in locations.values()]
                violations = [obs for obs in states
                              if not self.compliant(obs, cutoff)]
                latest[key] = max(violations or states, key=evidence_rank)
        if case:
            requested = timestamp(case.get("requested_at"))
            direct_owned = {key: [obs for obs in self.by_resource[key]
                                 if self.eligible(obs, cutoff) and is_state_proof(obs)
                                 and ids & obs.get("_identity_tokens", set())]
                            for key in latest}
            fresh_context = any(timestamp(obs.get("observed_at")) >= requested
                                for facts in direct_owned.values() for obs in facts)
            if fresh_context:
                for key, facts in direct_owned.items():
                    if not facts:
                        continue
                    prior = max(facts, key=evidence_rank)
                    # An old already-absent account from a previous lifecycle is
                    # not made relevant again by an unrelated global snapshot.
                    # Crucially, old PRESENT evidence is never expired this way.
                    if (timestamp(prior.get("observed_at")) < requested
                            and category(prior) == "USER_PROFILE"
                            and self.required_action(prior, cutoff) == "DELETE"
                            and resource_state(prior, category(prior)) == "ABSENT"
                            and any(other != key and other[0] == key[0]
                                    and any(category(fact) == "USER_PROFILE"
                                            and timestamp(fact.get("observed_at")) >= requested
                                            for fact in other_facts)
                                    for other, other_facts in direct_owned.items())):
                        latest.pop(key, None)
        return latest

    @staticmethod
    def name_link_allowed(token: str, observation: dict[str, Any], ids: set[str]) -> bool:
        if not token.startswith("name:"):
            return True
        strong = {value for value in observation.get("_identity_tokens", ())
                  if not value.startswith("name:")}
        # A matching display name never overrules a different explicit subject.
        return not strong or bool(strong & ids)

    @staticmethod
    def location(observation: dict[str, Any]) -> str:
        raw = observation.get("raw") or {}
        context = raw.get("_context") or {}
        table = normalize(raw.get("_scope_table") or context.get("table") or context.get("collection") or "")
        if "primary" in table:
            return "primary"
        if "failover" in table:
            return "failover"
        descriptor = normalize(" ".join(str(value) for value in (
            context.get("replica"), context.get("database_topology"),
            raw.get("_scope_table"), raw.get("_scope_topology"),
            raw.get("replica"), observation.get("source_path"))))
        if "failover" in descriptor:
            return "failover"
        if "reporting_replica" in descriptor:
            return "reporting"
        if "read_replica" in descriptor:
            return "read_replica"
        if "regional_replic" in descriptor:
            return "regional"
        return "primary"

    def compliant(self, observation: dict[str, Any], cutoff: datetime) -> bool:
        action = self.required_action(observation, cutoff)
        expected = {"DELETE": "ABSENT", "REDACT": "REDACTED",
                    "ANONYMIZE": "ANONYMIZED", "RETAIN": "PRESENT",
                    "DISABLE": "DISABLED", "BLOCK": "BLOCKED"}[action]
        state = resource_state(observation, category(observation))
        return state == expected or (state == "ABSENT" and action in {"DISABLE", "BLOCK"})

    def required_action(self, observation: dict[str, Any], cutoff: datetime) -> str:
        cat = category(observation)
        raw = flatten(observation.get("raw") or {})
        if cat == "DATA_FLOW":
            return "DISABLE"
        if cat == "BACKUP_ARCHIVE":
            return "BLOCK"
        matches = [rule for rule in self.rules if rule["data_category"] == cat]
        if not matches:
            raise ValueError(f"No supplied policy for category {cat!r}")
        action = matches[0]["required_action"]
        if cat == "SECURITY_AUDIT_LOG" and raw.get("retention_until"):
            if timestamp(raw["retention_until"]) < cutoff:
                return "DELETE"
        if cat == "LEGAL_HOLD_RECORD":
            active = truth(raw.get("legal_hold_active", raw.get("hold_active")))
            until = raw.get("hold_until", raw.get("legal_hold_until"))
            if active is False or (until and timestamp(until) < cutoff):
                return "DELETE"
        return action


def step(phase: str, system: str, resource: str, operation: str,
         state: str, evidence: str) -> dict[str, Any]:
    return {"step_no": 0, "phase": phase, "system_id": system,
            "resource_id": resource, "operation": operation, "state": state,
            "evidence_id": evidence}


def audit_case(case: dict[str, str], dataset: DatasetIndex | str | Path | None = None):
    if not deletion(case.get("request_text", "")):
        return "NOT_APPLICABLE", []
    index = dataset if isinstance(dataset, DatasetIndex) else DatasetIndex(dataset or ROOT / "dataset")
    cutoff = timestamp(case["audit_at"])
    relevant = index.relevant(index.identity(case["email"]), cutoff, case)
    findings, remediation, verification = [], [], []
    for (system, resource), observation in sorted(relevant.items()):
        cat = category(observation)
        action = index.required_action(observation, cutoff)
        state = resource_state(observation, cat)
        operation, final_state = {
            "DELETE": ("VERIFY_RECORD_ABSENT", "ABSENT"),
            "REDACT": ("VERIFY_RECORD_REDACTED", "REDACTED"),
            "ANONYMIZE": ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
            "RETAIN": ("VERIFY_RECORD_PRESENT", "PRESENT"),
            "DISABLE": ("VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
            "BLOCK": ("VERIFY_RESTORE_BLOCKED", "BLOCKED"),
        }[action]
        verification.append(step("VERIFICATION", system, resource, operation,
                                 final_state, observation["evidence_id"]))
        if state == final_state or (state == "ABSENT" and action in {"DISABLE", "BLOCK"}):
            continue
        if action == "RETAIN":
            raise ValueError(f"Required retained record lacks proof of presence: {system}/{resource}")
        finding, remedy = {
            "DELETE": ("REPORT_REMAINING_RECORD", "DELETE_RECORD"),
            "REDACT": ("REPORT_EXPOSED_PII", "REDACT_RECORD"),
            "ANONYMIZE": ("REPORT_EXPOSED_PII", "ANONYMIZE_RECORD"),
            "DISABLE": ("REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW"),
            "BLOCK": ("REPORT_RESTORE_RISK", "BLOCK_RESTORE"),
        }[action]
        findings.append(step("FINDING", system, resource, finding,
                             "ACTIVE" if action in {"DISABLE", "BLOCK"} else "PRESENT",
                             observation["evidence_id"]))
        remediation.append(step("REMEDIATION", system, resource, remedy, final_state, ""))
    if not verification:
        raise ValueError(f"No eligible state proof was linked to {case['case_id']}")
    status = "INCOMPLETE" if findings else "COMPLETE"
    if findings:
        for item in verification:
            item["evidence_id"] = ""
    result = findings + remediation + verification
    result.sort(key=lambda item: (PHASE_ORDER[item["phase"]],
                OPERATIONS[item["phase"]].index(item["operation"]),
                item["system_id"], item["resource_id"]))
    for number, item in enumerate(result, 1):
        item["step_no"] = number
    return status, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=ROOT / "dataset")
    parser.add_argument("--requests", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "output.csv")
    arguments = parser.parse_args()
    index = DatasetIndex(arguments.dataset)
    request_path = arguments.requests or arguments.dataset / "deletion_requests.csv"
    predictions = []
    for case in rows(request_path):
        status, steps = audit_case(case, index)
        predictions.append({"case_id": case["case_id"], "deletion_status": status,
                            "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":"))})
    with arguments.output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["case_id", "deletion_status", "steps_json"],
                                lineterminator="\n")
        writer.writeheader()
        writer.writerows(sorted(predictions, key=lambda item: item["case_id"]))
    print(f"Wrote {len(predictions)} rows to {arguments.output}")
    print("Status counts:", dict(Counter(row["deletion_status"] for row in predictions)))
    print("Evidence observations:", dict(Counter(obs["source_kind"] for obs in index.observations)))
    print("Temporal discovery hints:", len(index.diagnostics))


if __name__ == "__main__":
    main()
