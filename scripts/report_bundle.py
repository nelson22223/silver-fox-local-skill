#!/usr/bin/env python3
"""Start and check a per-collection Markdown and v2 JSON report bundle."""

from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sqlite3
import sys

from evidence import VIEW_DEFINITIONS, readonly_connection
from validate_report import validate_report


SOURCE_LINE = re.compile(r"采集包 SHA-256：(?:\*\*)?\s*`([0-9a-f]{64})`")
EVIDENCE_REF = re.compile(r"\b([a-z][a-z0-9_]*):([1-9][0-9]*)\b")
SOURCES = set(VIEW_DEFINITIONS) | {"events", "native_artifacts"} | {
    "prefetch_records", "amcache_records", "usn_journal_records", "srum_network_records",
    "scheduled_task_records", "wer_crash_records", "recent_file_records",
    "software_install_records", "dns_cache_records",
}


def _metadata(connection: sqlite3.Connection) -> dict[str, str]:
    metadata = {row["key"]: row["value"] for row in connection.execute("SELECT key, value FROM metadata")}
    if not re.fullmatch(r"[0-9a-f]{64}", metadata.get("source_sha256", "")):
        raise ValueError("database has no valid source SHA-256")
    return metadata


def default_report_dir(metadata: dict[str, str]) -> Path:
    source = Path(metadata["source_path"])
    safe_stem = re.sub(r"[^A-Za-z0-9._-]+", "-", source.stem).strip("._-")[:80] or "avtool"
    return source.parent / ".silverfox-reports" / f"{safe_stem}-{metadata['source_sha256'][:12]}"


def initialize(db_path: Path, output_dir: Path | None = None) -> Path:
    with closing(readonly_connection(db_path)) as connection:
        metadata = _metadata(connection)
    directory = (output_dir or default_report_dir(metadata)).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    markdown = directory / "report.md"
    if markdown.exists():
        raise FileExistsError(f"report already exists: {markdown}")
    now = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    content = (
        "# 银狐本地取证报告\n\n"
        "**状态：** 分析中  \n"
        f"**最近更新：** {now}  \n"
        f"**采集包：** `{Path(metadata['source_path']).name}`  \n"
        f"**采集包 SHA-256：** `{metadata['source_sha256']}`  \n"
        f"**证据库：** `{db_path.resolve()}`\n\n"
        "## 当前判断\n\n"
        "尚未完成分析。这里用简短文字说明目前能确认什么、仍在核查什么；不要把情报命中直接写成感染结论。\n\n"
        "## 关键证据链\n\n"
        "尚未建立证据链。每条链按时间写明来源、落地、执行、持久化或防护改动、通信，"
        "并指出缺失环节。事实后标注数据库引用，格式为 `来源:行号`。\n\n"
        "## 待核查与处置建议\n\n"
        "根据已核查证据逐步填写；区分调查动作与已确认的处置需要。\n\n"
        "## 覆盖范围与局限\n\n"
        "尚未盘点各类证据。记录未采集、解析异常和无法确认的环节。\n\n"
        "## 更新记录\n\n"
        f"- {now}：建立报告，尚未得出案件结论。\n"
    )
    with markdown.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(content)
    return markdown


def check(db_path: Path, markdown: Path, json_path: Path | None = None) -> dict:
    with closing(readonly_connection(db_path)) as connection:
        metadata = _metadata(connection)
        content = markdown.read_text(encoding="utf-8")
        matches = SOURCE_LINE.findall(content)
        if len(matches) != 1 or matches[0] != metadata["source_sha256"]:
            raise ValueError("Markdown source SHA-256 is missing or does not match this database")
        checked_refs: set[str] = set()
        for source, identifier in EVIDENCE_REF.findall(content):
            if source not in SOURCES:
                continue
            reference = f"{source}:{identifier}"
            if reference in checked_refs:
                continue
            exists = connection.execute(f"SELECT 1 FROM {source} WHERE id=?", (int(identifier),)).fetchone()
            if exists is None:
                raise ValueError(f"Markdown evidence reference not found: {reference}")
            checked_refs.add(reference)
    result = {"markdown": str(markdown.resolve()), "source_sha256": metadata["source_sha256"],
              "markdown_evidence_refs": len(checked_refs)}
    if json_path is not None:
        if json_path.resolve() == markdown.resolve():
            raise ValueError("Markdown and JSON must use separate paths")
        report = json.loads(json_path.read_text(encoding="utf-8"))
        result["json"] = validate_report(report, db_path)
        coverage = report["post_run_review"]["coverage"]
        declared_hashes = re.findall(r"(?:source|采集包)\s*SHA-256\s*[:：]?\s*([0-9a-f]{64})", coverage, re.I)
        if declared_hashes and metadata["source_sha256"] not in declared_hashes:
            raise ValueError("JSON post_run_review.coverage names a different source SHA-256")
        result["json_source_sha256_present"] = metadata["source_sha256"] in declared_hashes
        result["json_path"] = str(json_path.resolve())
    return result


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    start = subparsers.add_parser("init", help="create an incremental Markdown report for one evidence database")
    start.add_argument("--db", required=True, type=Path)
    start.add_argument("--output-dir", type=Path)
    verify = subparsers.add_parser("check", help="check Markdown source and evidence; optionally validate v2 JSON")
    verify.add_argument("--db", required=True, type=Path)
    verify.add_argument("--markdown", required=True, type=Path)
    verify.add_argument("--json", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "init":
            result = {"markdown": str(initialize(args.db, args.output_dir))}
        else:
            result = check(args.db, args.markdown, args.json)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError, KeyError, sqlite3.Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
