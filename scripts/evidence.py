#!/usr/bin/env python3
"""Import and query AVTool JSONL evidence without running collected files."""

from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from zipfile import BadZipFile, ZipFile


MAX_JSONL_BYTES = 4 * 1024**3
MAX_LINE_BYTES = 16 * 1024**2
MAX_QUERY_ROWS = 200
NATIVE_TYPES = {
    "prefetch_records": "prefetch",
    "amcache_records": "amcache",
    "usn_journal_records": "usn_journal",
    "srum_network_records": "srum_network",
    "scheduled_task_records": "scheduled_task",
    "wer_crash_records": "wer_crash",
    "recent_file_records": "recent_file",
    "software_install_records": "software_install",
    "dns_cache_records": "dns_cache",
}


def _json_path(field: str) -> str:
    return "json_extract(record_json, '$.data." + field + "')"


def _json_path_any(*fields: str) -> str:
    return "COALESCE(" + ", ".join(_json_path(field) for field in fields) + ")"


def _view_columns(mapping: dict[str, str]) -> str:
    return ",\n       ".join(f"{expression} AS {name}" for name, expression in mapping.items())


VIEW_DEFINITIONS: dict[str, tuple[str, dict[str, str]]] = {
    "browser_histories": ("event_type = 'browser_history'", {
        "browser": _json_path_any("Web_Browser", "browser"),
        "url": _json_path_any("URL", "url"),
        "title": _json_path_any("Title", "title"),
        "visit_time": _json_path_any("Visit_Time", "visit_time"),
        "visit_count": _json_path_any("Visit_Count", "visit_count"),
    }),
    "browser_downloads": ("event_type = 'browser_downloads'", {
        "browser": _json_path("Web_Browser"), "url": _json_path("Download_URL_1"),
        "source_url": _json_path("Web_Page_URL"), "path": _json_path("Full_Path_Filename"),
        "filename": _json_path("Filename"), "file_size": _json_path("Download_Size"),
        "state": _json_path("Download_State"), "download_time": _json_path("Start_Time"),
        "end_time": _json_path("End_Time"), "file_exists": _json_path("File_Exists"),
    }),
    "last_activity_view_records": ("event_type = 'last_activity'", {
        "action_time": _json_path("Action_Time"), "description": _json_path("Description"),
        "filename": _json_path("Filename"), "full_path": _json_path("Full_Path"),
        "more_information": _json_path("More_Information"),
        "file_extension": _json_path("File_Extension"), "data_source": _json_path("Data_Source"),
    }),
    "persistence_items": ("event_type = 'persistence_item'", {
        "location": _json_path("location"), "entry": _json_path("entry"),
        "enabled": _json_path("enabled"), "image_path": _json_path("image_path"),
        "launch_string": _json_path("launch_string"), "sha1": _json_path("sha1"),
        "type": _json_path("type"),
    }),
    "process_infos": ("event_type = 'process'", {
        "p_id": _json_path("pid"), "ppid": _json_path("ppid"),
        "name": _json_path("name"), "path": _json_path("path"),
        "cmdline": _json_path("cmdline"), "username": _json_path("username"),
        "company": _json_path("company"), "signing_status": _json_path("signing_status"),
        "modules": _json_path("modules"),
    }),
    "network_connections": ("event_type = 'network_connection'", {
        "p_id": _json_path("pid"), "process_name": _json_path("process"),
        "local_address": _json_path("local_address"),
        "remote_address": _json_path("remote_address"),
        "remote_port": _json_path("remote_port"), "protocol": _json_path("protocol"),
        "state": _json_path("state"),
    }),
    "virus_hits": ("event_type = 'virus_hit'", {
        "file_path": _json_path("file_path"), "rule_name": _json_path("rule_name"),
        "sha1": _json_path("sha1"), "threat_level": _json_path("threat_level"),
        "file_size": _json_path("file_size"),
    }),
    "memory_hits": ("event_type = 'memory_hit'", {
        "p_id": _json_path("pid"), "process_name": _json_path("process"),
        "rule_name": _json_path("rule_name"), "address": _json_path("address"),
        "size": _json_path("dump_size"), "dump_path": _json_path("dump_path"),
    }),
    "system_infos": ("event_type = 'snapshot_begin'", {
        "hostname": _json_path("hostname"), "username": _json_path("username"),
        "os_version": _json_path("os_version"),
        "collection_start": _json_path("collection_start"),
    }),
    "autorun_items": ("event_type = 'autorun_item'", {
        "entry_location": _json_path("entry_location"), "entry": _json_path("entry"),
        "image_path": _json_path("image_path"),
        "signing_status": _json_path("signing_status"),
    }),
    "dns_queries": ("event_type = 'dns_query'", {
        "domain": _json_path("domain"), "resolved_ips": _json_path("resolved_ips"),
        "process_name": _json_path("process_name"), "p_id": _json_path("pid"),
    }),
    "dns_logs": ("event_type = 'dns_log'", {
        "domain": _json_path("domain"), "is_threat": _json_path("is_threat"),
    }),
    "virus_events": ("event_type = 'virus_event'", {
        "file_path": _json_path("file_path"), "rule_name": _json_path("rule_name"),
        "sha1": _json_path("sha1"), "action_taken": _json_path("action_taken"),
    }),
    "sample_analyses": ("event_type = 'sample_analysis'", {
        "file_path": _json_path("file_path"), "sha1": _json_path("sha1"),
        "malware_name": _json_path("malware_name"),
        "ai_analysis": _json_path("ai_analysis"),
    }),
}


def _create_schema(connection: sqlite3.Connection) -> None:
    connection.execute("SELECT json_extract('{}', '$')")
    connection.executescript("""
        CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE events (
            id INTEGER PRIMARY KEY,
            ts TEXT,
            level TEXT,
            module TEXT,
            event_type TEXT,
            artifact_type TEXT,
            batch_id TEXT,
            decode_status TEXT NOT NULL,
            record_json TEXT,
            data_json TEXT,
            raw BLOB NOT NULL
        );
        CREATE INDEX events_type_batch ON events(event_type, batch_id);
        CREATE INDEX events_artifact_type ON events(artifact_type);
        CREATE INDEX events_decode_status ON events(decode_status);
    """)
    for name, (predicate, mapping) in VIEW_DEFINITIONS.items():
        connection.execute(
            f"CREATE VIEW {name} AS SELECT id, ts, batch_id, "
            f"{_view_columns(mapping)}, data_json FROM events WHERE {predicate}"
        )
    connection.execute(
        "CREATE VIEW native_artifacts AS SELECT id, ts, batch_id, artifact_type, "
        "data_json FROM events WHERE event_type = 'native_collection_item'"
    )
    for name, artifact_type in NATIVE_TYPES.items():
        connection.execute(
            f"CREATE VIEW {name} AS SELECT id, ts, batch_id, data_json "
            "FROM native_artifacts WHERE artifact_type = ?".replace("?", f"'{artifact_type}'")
        )


def _decode(raw: bytes) -> tuple[dict | None, str]:
    try:
        value = json.loads(raw.decode("utf-8"))
        return (value, "utf8") if isinstance(value, dict) else (None, "invalid_json")
    except UnicodeDecodeError:
        pass
    except (json.JSONDecodeError, ValueError):
        return None, "invalid_json"

    try:
        value = json.loads(raw.decode("gb18030"))
        if isinstance(value, dict):
            return value, "gb18030"
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        pass

    # AVTool can embed GB18030 bytes in an otherwise UTF-8 JSONL line.
    mixed = raw.decode("utf-8", "surrogateescape")
    had_replacement = False

    def recover(match: re.Match[str]) -> str:
        nonlocal had_replacement
        original = bytes(ord(char) - 0xDC00 for char in match.group())
        try:
            return original.decode("gb18030")
        except UnicodeDecodeError:
            had_replacement = True
            return original.decode("gb18030", "replace")

    mixed = re.sub(r"[\udc80-\udcff]+", recover, mixed)
    for candidate, label in ((mixed, "mixed_gb18030"), (raw.decode("utf-8", "replace"), "replacement")):
        try:
            value = json.loads(candidate)
            if isinstance(value, dict):
                return value, "replacement" if had_replacement or label == "replacement" else label
        except (json.JSONDecodeError, ValueError):
            pass
    return None, "invalid_json"


def _source(input_path: Path):
    if input_path.suffix.lower() != ".zip":
        if input_path.suffix.lower() != ".jsonl":
            raise ValueError("input must be a ZIP or investigation.jsonl file")
        if input_path.stat().st_size > MAX_JSONL_BYTES:
            raise ValueError("JSONL input exceeds the 4 GiB safety limit")
        return input_path.open("rb"), "investigation.jsonl", []
    archive = ZipFile(input_path)
    candidates = [item for item in archive.infolist() if item.filename.replace("\\", "/").split("/")[-1].lower() == "investigation.jsonl"]
    if len(candidates) != 1:
        archive.close()
        raise ValueError("ZIP must contain exactly one investigation.jsonl")
    item = candidates[0]
    if item.flag_bits & 1 or item.file_size > MAX_JSONL_BYTES:
        archive.close()
        raise ValueError("encrypted or oversized investigation.jsonl is unsupported")
    entries = [{"name": member.filename, "size": member.file_size} for member in archive.infolist()]
    return (archive, archive.open(item), item.filename, entries)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def default_database_path(input_path: Path, source_sha256: str) -> Path:
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", input_path.stem).strip("._-")[:80] or "avtool"
    return input_path.parent / ".silverfox-db" / f"{name}-{source_sha256[:12]}.sqlite"


def import_evidence(input_path: Path, db_path: Path | None = None) -> dict:
    input_path = input_path.resolve(strict=True)
    if not input_path.is_file():
        raise ValueError("input must be a file")
    if input_path.suffix.lower() not in {".zip", ".jsonl"}:
        raise ValueError("input must be a ZIP or investigation.jsonl file")
    source_sha256 = _sha256_file(input_path)
    db_path = db_path or default_database_path(input_path, source_sha256)
    db_path = db_path.resolve()
    if db_path.exists():
        raise FileExistsError(f"database already exists: {db_path}")
    db_path.parent.mkdir(parents=True, exist_ok=True)
    handle = _source(input_path)
    archive = None
    if len(handle) == 4:
        archive, stream, member_name, entries = handle
    else:
        stream, member_name, entries = handle
    fd, temporary_name = tempfile.mkstemp(prefix=".silverfox-", suffix=".sqlite", dir=db_path.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        with closing(sqlite3.connect(temporary)) as connection, connection:
            _create_schema(connection)
            batch = []
            total = 0
            valid_events = 0
            line_number = 0
            while raw := stream.readline(MAX_LINE_BYTES + 1):
                line_number += 1
                total = line_number
                if len(raw) > MAX_LINE_BYTES:
                    raise ValueError(f"JSONL line {line_number} exceeds the 16 MiB safety limit")
                record, status = _decode(raw)
                data = record.get("data") if isinstance(record, dict) else None
                if isinstance(record, dict) and isinstance(record.get("event_type"), str) and isinstance(data, dict):
                    valid_events += 1
                if not isinstance(data, dict):
                    data = {}
                batch.append((
                    line_number,
                    record.get("ts") if record else None,
                    record.get("level") if record else None,
                    record.get("module") if record else None,
                    record.get("event_type") if record else None,
                    data.get("artifact_type"), data.get("batch_id"), status,
                    json.dumps(record, ensure_ascii=False, separators=(",", ":")) if record else None,
                    json.dumps(data, ensure_ascii=False, separators=(",", ":")) if record else None,
                    raw,
                ))
                if len(batch) >= 1000:
                    connection.executemany("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?)", batch)
                    batch.clear()
            if batch:
                connection.executemany("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?)", batch)
            if total == 0:
                raise ValueError("investigation.jsonl is empty")
            if valid_events == 0:
                raise ValueError("input contains no AVTool event records")
            metadata = {
                "format": "silver-fox-local/v1",
                "source_path": str(input_path),
                "source_sha256": source_sha256,
                "jsonl_member": member_name,
                "archive_entries": json.dumps(entries, ensure_ascii=False),
                "imported_at_utc": datetime.now(timezone.utc).isoformat(),
                "line_count": str(total),
            }
            connection.executemany("INSERT INTO metadata VALUES (?,?)", metadata.items())
        if db_path.exists():
            raise FileExistsError(f"database appeared during import: {db_path}")
        os.replace(temporary, db_path)
    finally:
        stream.close()
        if archive is not None:
            archive.close()
        temporary.unlink(missing_ok=True)
    return inventory(db_path)


def readonly_connection(db_path: Path) -> sqlite3.Connection:
    db_path = db_path.resolve(strict=True)
    connection = sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def inventory(db_path: Path) -> dict:
    with closing(readonly_connection(db_path)) as connection:
        metadata = {row["key"]: row["value"] for row in connection.execute("SELECT key,value FROM metadata")}
        types = {row["event_type"] or "<unparsed>": row["n"] for row in connection.execute(
            "SELECT event_type, COUNT(*) AS n FROM events GROUP BY event_type ORDER BY n DESC"
        )}
        native = {row["artifact_type"] or "<missing>": row["n"] for row in connection.execute(
            "SELECT artifact_type, COUNT(*) AS n FROM native_artifacts GROUP BY artifact_type ORDER BY n DESC"
        )}
        decoding = {row["decode_status"]: row["n"] for row in connection.execute(
            "SELECT decode_status, COUNT(*) AS n FROM events GROUP BY decode_status ORDER BY n DESC"
        )}
        incomplete_downloads = connection.execute(
            "SELECT COUNT(*) FROM browser_downloads "
            "WHERE NULLIF(TRIM(CAST(url AS TEXT)), '') IS NULL "
            "OR NULLIF(TRIM(CAST(path AS TEXT)), '') IS NULL "
            "OR NULLIF(TRIM(CAST(state AS TEXT)), '') IS NULL"
        ).fetchone()[0]
        incomplete_histories = connection.execute(
            "SELECT COUNT(*) FROM browser_histories "
            "WHERE NULLIF(TRIM(CAST(url AS TEXT)), '') IS NULL "
            "OR NULLIF(TRIM(CAST(visit_time AS TEXT)), '') IS NULL "
            "OR NULLIF(TRIM(CAST(browser AS TEXT)), '') IS NULL"
        ).fetchone()[0]
        fields_without_values = []
        for view_name, (_, mapping) in VIEW_DEFINITIONS.items():
            row_count = connection.execute(f"SELECT COUNT(*) FROM {view_name}").fetchone()[0]
            if not row_count:
                continue
            checks = ", ".join(
                f"COUNT(NULLIF(TRIM(CAST({column} AS TEXT)), '')) AS {column}"
                for column in mapping
            )
            coverage = connection.execute(f"SELECT {checks} FROM {view_name}").fetchone()
            missing = [column for column in mapping if coverage[column] == 0]
            if missing:
                fields_without_values.append({
                    "view": view_name, "rows": row_count, "fields": missing,
                })
    metadata["archive_entries"] = json.loads(metadata["archive_entries"])
    return {
        "database_path": str(db_path.resolve()),
        "metadata": metadata, "event_types": types, "native_artifact_types": native,
        "decode_status": decoding,
        "quality": {
            "browser_download_rows_missing_core_fields": incomplete_downloads,
            "browser_history_rows_missing_core_fields": incomplete_histories,
            "view_fields_without_values": fields_without_values,
        },
    }


def _json_safe(value):
    if isinstance(value, bytes):
        return {"raw_bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}
    return value


def query(db_path: Path, sql: str, max_rows: int = MAX_QUERY_ROWS) -> dict:
    if not 1 <= max_rows <= MAX_QUERY_ROWS:
        raise ValueError("max_rows must be between 1 and 200")
    sql = sql.strip().rstrip(";").strip()
    if not re.match(r"(?is)^(select|with)\b", sql):
        raise ValueError("query must start with SELECT or WITH")
    with closing(readonly_connection(db_path)) as connection:
        cursor = connection.execute(sql)
        if cursor.description is None:
            raise ValueError("query must return rows")
        fetched = cursor.fetchmany(max_rows + 1)
        columns = [item[0] for item in cursor.description]
        rows = [{key: _json_safe(value) for key, value in zip(columns, row)} for row in fetched[:max_rows]]
    return {
        "database_path": str(db_path.resolve()), "columns": columns,
        "rows": rows, "row_count": len(rows), "truncated": len(fetched) > max_rows,
    }


def record(db_path: Path, line_id: int, raw_output: Path | None = None) -> dict:
    with closing(readonly_connection(db_path)) as connection:
        row = connection.execute("SELECT * FROM events WHERE id=?", (line_id,)).fetchone()
        if row is None:
            raise ValueError(f"no JSONL line {line_id}")
        result = {
            "database_path": str(db_path.resolve()),
            "id": line_id, "decode_status": row["decode_status"],
            "raw_sha256": hashlib.sha256(row["raw"]).hexdigest(),
            "record": json.loads(row["record_json"]) if row["record_json"] else None,
        }
        if raw_output is not None:
            if raw_output.exists():
                raise FileExistsError(f"raw output already exists: {raw_output}")
            raw_output.write_bytes(row["raw"])
            result["raw_output"] = str(raw_output.resolve())
    return result


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    importer = commands.add_parser("import", help="import AVTool ZIP or JSONL into a new SQLite database")
    importer.add_argument("input", type=Path)
    importer.add_argument("--db", type=Path, help="optional destination; default is a per-package hashed name")
    for name in ("inventory", "query", "record"):
        command = commands.add_parser(name)
        command.add_argument("--db", required=True, type=Path)
        if name == "query":
            command.add_argument("--sql", required=True)
            command.add_argument("--max-rows", type=int, default=200)
        if name == "record":
            command.add_argument("--id", required=True, type=int)
            command.add_argument("--raw-output", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "import":
            output = import_evidence(args.input, args.db)
        elif args.command == "inventory":
            output = inventory(args.db)
        elif args.command == "query":
            output = query(args.db, args.sql, args.max_rows)
        else:
            output = record(args.db, args.id, args.raw_output)
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, sqlite3.Error, EOFError, BadZipFile) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
