#!/usr/bin/env python3
"""Validate a local Silver Fox v2 report and its evidence references."""

from __future__ import annotations

import argparse
from contextlib import closing
import json
from pathlib import Path
import re
import sqlite3
import sys
from typing import Any

from evidence import VIEW_DEFINITIONS, readonly_connection


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "references" / "silverfox-report-v2.schema.json"
MODULE_SOURCES = {
    "browser_analysis": {"browser_histories": "browser_history", "browser_downloads": "browser_download"},
    "last_activity_analysis": {"last_activity_view_records": "last_activity"},
    "persistence_analysis": {"persistence_items": "persistence", "autorun_items": "persistence"},
    "process_analysis": {"process_infos": "process"},
    "network_analysis": {"network_connections": "network_connection", "dns_queries": "dns_query", "dns_logs": "dns_threat"},
    "virus_analysis": {"virus_hits": "virus_file", "virus_events": "virus_file", "sample_analyses": "virus_file"},
    "memory_analysis": {"memory_hits": "memory_hit"},
}
MODULE_COUNT_VIEWS = {
    "browser_analysis": ("browser_histories", "browser_downloads"),
    "last_activity_analysis": ("last_activity_view_records",),
    "persistence_analysis": ("persistence_items", "autorun_items"),
    "process_analysis": ("process_infos",),
    "network_analysis": ("network_connections", "dns_queries", "dns_logs"),
    "virus_analysis": ("virus_hits", "virus_events", "sample_analyses"),
    "memory_analysis": ("memory_hits",),
}
REF_PATTERN = re.compile(r"^([a-z][a-z0-9_]*):([1-9][0-9]*)$")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _validate_schema(value: Any, rule: dict, schema: dict, path: str) -> None:
    if "$ref" in rule:
        reference = rule["$ref"]
        _require(reference.startswith("#/$defs/"), f"unsupported schema reference at {path}")
        _validate_schema(value, schema["$defs"][reference.rsplit("/", 1)[-1]], schema, path)
        return
    if "const" in rule:
        _require(value == rule["const"], f"{path} must equal {rule['const']!r}")
    if "enum" in rule:
        _require(value in rule["enum"], f"{path} has unsupported value")
    expected = rule.get("type")
    if expected == "object":
        _require(isinstance(value, dict), f"{path} must be an object")
        required = set(rule.get("required", []))
        missing = required - value.keys()
        _require(not missing, f"{path} missing {sorted(missing)}")
        properties = rule.get("properties", {})
        if rule.get("additionalProperties") is False:
            extra = value.keys() - properties.keys()
            _require(not extra, f"{path} has extra fields {sorted(extra)}")
        for key, child in value.items():
            if key in properties:
                _validate_schema(child, properties[key], schema, f"{path}.{key}")
    elif expected == "array":
        _require(isinstance(value, list), f"{path} must be an array")
        _require(len(value) >= rule.get("minItems", 0), f"{path} has too few items")
        _require(len(value) <= rule.get("maxItems", sys.maxsize), f"{path} has too many items")
        if "items" in rule:
            for index, child in enumerate(value):
                _validate_schema(child, rule["items"], schema, f"{path}[{index}]")
    elif expected == "string":
        _require(isinstance(value, str), f"{path} must be a string")
        _require(len(value) >= rule.get("minLength", 0), f"{path} is too short")
    elif expected == "integer":
        _require(type(value) is int, f"{path} must be an integer")
        _require(value >= rule.get("minimum", -sys.maxsize), f"{path} is below minimum")
    elif expected == "boolean":
        _require(type(value) is bool, f"{path} must be a boolean")


def validate_report(report: dict, db_path: Path) -> dict:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    _validate_schema(report, schema, schema, "report")
    seen_objects: set[str] = set()
    checked_refs: set[str] = set()
    allowed_refs = set(VIEW_DEFINITIONS) | {"native_artifacts"}
    with closing(readonly_connection(db_path)) as connection:
        for module_name, primary_sources in MODULE_SOURCES.items():
            module = report[module_name]
            metrics = module["metrics"]
            details = module["details"]
            total, suspicious, high, displayed = (
                metrics[key] for key in ("total_analyzed", "suspicious_count", "high_risk_count", "displayed_count")
            )
            actual_total = sum(connection.execute(f"SELECT COUNT(*) FROM {view}").fetchone()[0]
                               for view in MODULE_COUNT_VIEWS[module_name])
            _require(total == actual_total, f"{module_name}.total_analyzed must equal {actual_total}")
            _require(0 <= high <= suspicious <= total, f"{module_name} has inconsistent counts")
            _require(displayed == len(details) == min(suspicious, 32), f"{module_name} displayed_count is inconsistent")
            _require(metrics["truncated"] is (suspicious > 32), f"{module_name} truncated is inconsistent")
            if suspicious == 0:
                _require(not module["findings"] and not module["evidence"] and not details,
                         f"{module_name} has findings but suspicious_count is zero")
            displayed_high = sum(detail["risk_level"] in {"critical", "high"} for detail in details)
            _require(displayed_high == min(high, displayed), f"{module_name} high_risk_count does not match visible details")
            for detail in details:
                object_id = detail["object_id"]
                refs = detail["evidence_refs"]
                _require(refs[0] == object_id, f"{module_name} {object_id} must use first reference as primary")
                _require(object_id not in seen_objects, f"duplicate object_id {object_id}")
                seen_objects.add(object_id)
                primary_match = REF_PATTERN.fullmatch(object_id)
                _require(primary_match is not None, f"invalid object_id {object_id}")
                source = primary_match.group(1)
                _require(source in primary_sources, f"{object_id} is not a primary source for {module_name}")
                _require(detail["object_type"] == primary_sources[source], f"{object_id} has wrong object_type")
                for reference in refs:
                    match = REF_PATTERN.fullmatch(reference)
                    _require(match is not None, f"invalid evidence reference {reference}")
                    source, identifier = match.group(1), int(match.group(2))
                    _require(source in allowed_refs, f"unsupported evidence source {source}")
                    exists = connection.execute(f"SELECT 1 FROM {source} WHERE id=?", (identifier,)).fetchone()
                    _require(exists is not None, f"evidence reference not found: {reference}")
                    checked_refs.add(reference)
    return {"schema_version": report["schema_version"], "objects": len(seen_objects), "evidence_refs": len(checked_refs)}


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        result = validate_report(report, args.db)
        print(json.dumps({"valid": True, **result}, ensure_ascii=False))
        return 0
    except (OSError, ValueError, sqlite3.Error, KeyError) as exc:
        print(f"invalid report: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
