"""Behavior checks for the portable importer, query boundary, and v2 contract."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from zipfile import ZipFile


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from evidence import import_evidence, inventory, query, record  # noqa: E402
from doctor import check as check_runtime  # noqa: E402
from report_bundle import check as check_bundle, initialize as initialize_report  # noqa: E402
from validate_report import validate_report  # noqa: E402


def empty_module(total: int = 0) -> dict:
    return {
        "summary": "fixture", "findings": [], "evidence": [], "assessment": "fixture",
        "metrics": {"total_analyzed": total, "suspicious_count": 0,
                    "high_risk_count": 0, "displayed_count": 0, "truncated": False},
        "details": [],
    }


def fixture_report() -> dict:
    result = {
        "schema_version": "silverfox-report/v2", "threat_level": "low",
        "summary": "test fixture", "team_summary": "test fixture",
        "current_stage": "完成", "progress": 100, "stage_details": "test fixture",
        "key_findings": ["test fixture"], "recommendations": [],
        "post_run_review": {"coverage": "fixture", "confidence": "low",
                            "included_signals": [], "noise_reasons": [], "gaps": [], "next_steps": []},
    }
    for module in ("browser_analysis", "last_activity_analysis", "persistence_analysis",
                   "process_analysis", "network_analysis", "virus_analysis", "memory_analysis"):
        result[module] = empty_module()
    result["virus_analysis"] = {
        "summary": "fixture", "findings": ["fixture"], "evidence": ["fixture"],
        "assessment": "fixture", "metrics": {"total_analyzed": 1, "suspicious_count": 1,
                                          "high_risk_count": 0, "displayed_count": 1, "truncated": False},
        "details": [{"object_id": "virus_hits:2", "risk_level": "low", "object_type": "virus_file",
                     "title": "fixture", "timestamp": "", "attributes": [], "reasons": ["fixture"],
                     "recommendation": "", "evidence_refs": ["virus_hits:2"]}],
    }
    return result


class LocalEvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.input = root / "collection.zip"
        self.db = root / "collection.sqlite"
        lines = [
            json.dumps({"ts": "2026-01-01", "event_type": "snapshot_begin",
                        "data": {"batch_id": "a", "hostname": "test"}}).encode() + b"\n",
            json.dumps({"ts": "2026-01-01", "event_type": "virus_hit",
                        "data": {"file_path": "C:\\test.exe", "rule_name": "heuristic_test",
                                 "sha1": "abc", "threat_level": "HIGH", "unknown": {"x": 1}}}).encode() + b"\n",
            json.dumps({"ts": "2026-01-01", "event_type": "native_collection_item",
                        "data": {"artifact_type": "software_install", "Description": "软件安装"}},
                       ensure_ascii=False).encode("gb18030") + b"\n",
            b"{invalid json\n",
        ]
        with ZipFile(self.input, "w") as archive:
            archive.writestr("investigation.jsonl", b"".join(lines))
            archive.writestr("samples/payload.exe", b"MZ" + b"\x00" * 16)
        self.result = import_evidence(self.input, self.db)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_import_preserves_lines_and_unknown_fields(self) -> None:
        self.assertEqual("4", self.result["metadata"]["line_count"])
        self.assertEqual(1, self.result["decode_status"]["invalid_json"])
        self.assertEqual("abc", query(self.db, "SELECT sha1 FROM virus_hits")["rows"][0]["sha1"])
        self.assertEqual(1, record(self.db, 2)["record"]["data"]["unknown"]["x"])
        raw_copy = self.db.parent / "line-2.raw"
        record(self.db, 2, raw_copy)
        with ZipFile(self.input) as archive:
            self.assertEqual(archive.read("investigation.jsonl").splitlines(keepends=True)[1], raw_copy.read_bytes())
        self.assertEqual("软件安装", record(self.db, 3)["record"]["data"]["Description"])
        self.assertIn(record(self.db, 3)["decode_status"], {"gb18030", "mixed_gb18030"})
        self.assertIsNone(record(self.db, 4)["record"])
        self.assertFalse((self.db.parent / "samples" / "payload.exe").exists())
        self.assertEqual(1, inventory(self.db)["native_artifact_types"]["software_install"])
        self.assertEqual(0, inventory(self.db)["quality"]["browser_download_rows_missing_core_fields"])

    def test_preflight_checks_runtime_and_input_shape(self) -> None:
        valid = check_runtime(self.input)
        self.assertTrue(valid["ok"], valid["errors"])
        self.assertEqual(str(self.input.resolve()), valid["input"])
        bad_zip = self.db.parent / "not-avtool.zip"
        with ZipFile(bad_zip, "w") as archive:
            archive.writestr("unrelated.txt", "x")
        invalid = check_runtime(bad_zip)
        self.assertFalse(invalid["ok"])
        self.assertIn("ZIP must contain exactly one investigation.jsonl", invalid["errors"])

    def test_query_is_bounded_and_read_only(self) -> None:
        result = query(self.db, "SELECT id FROM events ORDER BY id", 2)
        self.assertEqual([1, 2], [row["id"] for row in result["rows"]])
        self.assertTrue(result["truncated"])
        with self.assertRaises((ValueError, sqlite3.Error)):
            query(self.db, "DELETE FROM events", 2)
        self.assertEqual(4, query(self.db, "SELECT COUNT(*) AS n FROM events")["rows"][0]["n"])

    def test_plain_jsonl_and_no_overwrite(self) -> None:
        plain = self.db.parent / "plain.jsonl"
        with ZipFile(self.input) as archive:
            plain.write_bytes(archive.read("investigation.jsonl"))
        other_db = self.db.parent / "plain.sqlite"
        self.assertEqual("4", import_evidence(plain, other_db)["metadata"]["line_count"])
        with self.assertRaises(FileExistsError):
            import_evidence(plain, other_db)
        invalid = self.db.parent / "invalid.jsonl"
        invalid.write_bytes(b"not json\n")
        with self.assertRaisesRegex(ValueError, "no AVTool event records"):
            import_evidence(invalid, self.db.parent / "invalid.sqlite")

    def test_default_names_isolate_packages_in_one_directory(self) -> None:
        second = self.db.parent / "other-collection.zip"
        with ZipFile(second, "w") as archive:
            archive.writestr("investigation.jsonl", json.dumps({
                "ts": "2026-01-02", "event_type": "process",
                "data": {"batch_id": "b", "pid": 7, "name": "test.exe"},
            }).encode() + b"\n")
        first_result = import_evidence(self.input)
        second_result = import_evidence(second)
        first_db = Path(first_result["database_path"])
        second_db = Path(second_result["database_path"])
        self.assertNotEqual(first_db, second_db)
        self.assertEqual(first_db.parent, second_db.parent)
        self.assertEqual(1, query(first_db, "SELECT COUNT(*) AS n FROM virus_hits")["rows"][0]["n"])
        self.assertEqual(0, query(second_db, "SELECT COUNT(*) AS n FROM virus_hits")["rows"][0]["n"])
        self.assertEqual(1, query(second_db, "SELECT COUNT(*) AS n FROM process_infos")["rows"][0]["n"])
        with self.assertRaises(FileExistsError):
            import_evidence(self.input)

    def test_report_checks_schema_and_real_reference(self) -> None:
        report = fixture_report()
        self.assertEqual(1, validate_report(report, self.db)["evidence_refs"])
        report["virus_analysis"]["details"][0]["evidence_refs"] = ["virus_hits:999"]
        report["virus_analysis"]["details"][0]["object_id"] = "virus_hits:999"
        with self.assertRaisesRegex(ValueError, "not found"):
            validate_report(report, self.db)

    def test_incremental_markdown_and_final_json_share_source(self) -> None:
        report_dir = self.db.parent / "report-bundle"
        markdown = initialize_report(self.db, report_dir)
        self.assertEqual(0, check_bundle(self.db, markdown)["markdown_evidence_refs"])
        with self.assertRaises(FileExistsError):
            initialize_report(self.db, report_dir)

        with markdown.open("a", encoding="utf-8") as stream:
            stream.write("\n已复核检测记录 `virus_hits:2`。\n")
        self.assertEqual(1, check_bundle(self.db, markdown)["markdown_evidence_refs"])
        with markdown.open("a", encoding="utf-8") as stream:
            stream.write("\n不存在的记录 `events:999`。\n")
        with self.assertRaisesRegex(ValueError, "not found"):
            check_bundle(self.db, markdown)
        markdown.write_text(markdown.read_text(encoding="utf-8").replace("events:999", "events:2"),
                            encoding="utf-8")

        report = fixture_report()
        report["post_run_review"]["coverage"] = f"source SHA-256 {self.result['metadata']['source_sha256']}"
        json_path = report_dir / "report.json"
        json_path.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
        result = check_bundle(self.db, markdown, json_path)
        self.assertEqual(1, result["json"]["objects"])

        original_markdown = markdown.read_text(encoding="utf-8")
        markdown.write_text(original_markdown.replace(self.result["metadata"]["source_sha256"], "0" * 64),
                            encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Markdown source SHA-256"):
            check_bundle(self.db, markdown, json_path)
        markdown.write_text(original_markdown, encoding="utf-8")

        report["post_run_review"]["coverage"] = f"source SHA-256 {'0' * 64}"
        json_path.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "source SHA-256"):
            check_bundle(self.db, markdown, json_path)


if __name__ == "__main__":
    unittest.main()
