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
from build_distribution import build as build_distribution  # noqa: E402
from feedback import (configure as configure_feedback, disable as disable_feedback,
                      load_config as load_feedback_config, prepare as prepare_feedback,
                      main as feedback_main, preview as preview_feedback, send as send_feedback,
                      submit_if_enabled, read_token, PinnedHTTPSConnection,
                      PinnedHTTPSHandler)  # noqa: E402
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
        self.assertIn({"view": "virus_hits", "rows": 1, "fields": ["file_size"]},
                      inventory(self.db)["quality"]["view_fields_without_values"])

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

    def test_browser_history_avtool_fields_and_legacy_aliases(self) -> None:
        source = self.db.parent / "history.jsonl"
        rows = [
            {"Web_Browser": "Chrome", "URL": "https://example.test/one",
             "Title": "first", "Visit_Time": "2026-01-01 01:00:00", "Visit_Count": 2},
            {"browser": "Firefox", "url": "https://example.test/two",
             "title": "second", "visit_time": "2026-01-01 02:00:00", "visit_count": 3},
            {"Web_Browser": "Chrome", "Visit_Time": "2026-01-01 03:00:00"},
            {"Web_Browser": "Chrome", "URL": "  ",
             "Visit_Time": "2026-01-01 04:00:00"},
        ]
        source.write_text("".join(json.dumps({
            "ts": "2026-01-01", "event_type": "browser_history", "data": data,
        }) + "\n" for data in rows), encoding="utf-8")
        history_db = self.db.parent / "history.sqlite"
        result = import_evidence(source, history_db)
        mapped = query(history_db, "SELECT browser, url, title, visit_time, visit_count "
                       "FROM browser_histories ORDER BY id")["rows"]
        self.assertEqual({"browser": "Chrome", "url": "https://example.test/one",
                          "title": "first", "visit_time": "2026-01-01 01:00:00",
                          "visit_count": 2}, mapped[0])
        self.assertEqual({"browser": "Firefox", "url": "https://example.test/two",
                          "title": "second", "visit_time": "2026-01-01 02:00:00",
                          "visit_count": 3}, mapped[1])
        self.assertIsNone(mapped[2]["url"])
        self.assertEqual(2, result["quality"]["browser_history_rows_missing_core_fields"])
        self.assertNotIn("browser_histories", [item["view"] for item in
                          result["quality"]["view_fields_without_values"]])
        self.assertEqual(rows[0]["URL"], record(history_db, 1)["record"]["data"]["URL"])

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

    def test_feedback_is_explicit_and_uses_validated_reports(self) -> None:
        from unittest.mock import MagicMock, patch

        report_dir = self.db.parent / "feedback-bundle"
        markdown = initialize_report(self.db, report_dir)
        report = fixture_report()
        report["post_run_review"]["coverage"] = f"采集包 SHA-256 {self.result['metadata']['source_sha256']}"
        json_path = report_dir / "report.json"
        json_path.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
        payload = prepare_feedback(self.db, markdown, json_path, customer="customer-a",
                                   analyst_id="analyst-a")
        self.assertEqual("test", payload["hostname"])
        self.assertEqual("customer-a", payload["customer"])
        self.assertEqual("analyst-a", payload["analyst_id"])
        self.assertEqual(report, payload["report_json"])
        self.assertIn("银狐本地取证报告", payload["report_markdown"])
        self.assertNotIn("report_markdown", preview_feedback(payload))
        self.assertTrue(preview_feedback(payload)["contains_full_reports"])

        with self.assertRaisesRegex(ValueError, "HTTPS"):
            send_feedback(payload, "http://feedback.example.test/reports", "token")
        response = MagicMock()
        response.status = 202
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        with patch("feedback.build_opener", return_value=opener):
            self.assertEqual(202, send_feedback(payload, "https://feedback.example.test/reports", "token"))
        request = opener.open.call_args.args[0]
        self.assertEqual("Bearer token", request.get_header("Authorization"))
        self.assertEqual("silverfox-feedback/v1", payload["schema_version"])
        self.assertEqual("silver-fox-local", payload["skill"])
        self.assertEqual("success", payload["status"])
        self.assertEqual(payload["report_hash"], request.get_header("Idempotency-key"))
        self.assertEqual(payload, json.loads(request.data))

        report["post_run_review"]["coverage"] = "fixture without a source hash"
        json_path.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "source SHA-256"):
            prepare_feedback(self.db, markdown, json_path)

    def test_feedback_automatic_submission_requires_prior_consent_config(self) -> None:
        from contextlib import redirect_stderr, redirect_stdout
        import io
        from unittest.mock import patch

        report_dir = self.db.parent / "feedback-opt-in"
        markdown = initialize_report(self.db, report_dir)
        report = fixture_report()
        report["post_run_review"]["coverage"] = f"采集包 SHA-256 {self.result['metadata']['source_sha256']}"
        json_path = report_dir / "report.json"
        json_path.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
        config_path = self.db.parent / "settings" / "feedback.json"
        command = ["feedback.py", "configure", "--config", str(config_path),
                   "--endpoint", "https://feedback.example.test/reports"]
        with patch.object(sys, "argv", command), redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
            self.assertEqual(1, feedback_main())
        self.assertFalse(config_path.exists())
        with patch("feedback.BUNDLED_CONFIG", self.db.parent / "absent-deployment.json"), \
                patch("feedback.send") as transmit:
            result = submit_if_enabled(config_path, self.db, markdown, json_path)
            self.assertFalse(result["submitted"])
            transmit.assert_not_called()

        with self.assertRaisesRegex(ValueError, "HTTPS"):
            configure_feedback(config_path, "http://feedback.example.test/reports",
                               "SILVERFOX_FEEDBACK_TOKEN")
        self.assertFalse(config_path.exists())
        configured = configure_feedback(config_path, "https://feedback.example.test/reports",
                                        "SILVERFOX_FEEDBACK_TOKEN", "analyst-a")
        self.assertTrue(configured["enabled"])
        self.assertEqual("full_reports_with_hostname", load_feedback_config(config_path)["scope"])
        with patch.dict("os.environ", {"SILVERFOX_FEEDBACK_TOKEN": "token"}):
            with patch("feedback.send", return_value=202) as transmit:
                result = submit_if_enabled(config_path, self.db, markdown, json_path)
                self.assertTrue(result["submitted"])
                self.assertEqual("analyst-a", transmit.call_args.args[0]["analyst_id"])
                self.assertEqual("https://feedback.example.test/reports", transmit.call_args.args[1])
                self.assertEqual("token", transmit.call_args.args[2])
        disable_feedback(config_path)
        with patch("feedback.send") as transmit:
            result = submit_if_enabled(config_path, self.db, markdown, json_path)
            self.assertFalse(result["submitted"])
            transmit.assert_not_called()

    def test_feedback_certificate_pin_checked_before_http_request(self) -> None:
        import hashlib
        import ssl
        from unittest.mock import MagicMock, patch

        certificate = b"test certificate fixture"
        fingerprint = hashlib.sha256(certificate).hexdigest()
        connection = PinnedHTTPSConnection("feedback.example.test", fingerprint)
        connection.sock = MagicMock()
        connection.sock.getpeercert.return_value = certificate
        with patch("feedback.http.client.HTTPSConnection.connect"):
            connection.connect()

        wrong = PinnedHTTPSConnection("feedback.example.test", "0" * 64)
        wrong.sock = MagicMock()
        wrong.sock.getpeercert.return_value = certificate
        with patch("feedback.http.client.HTTPSConnection.connect"), patch.object(wrong, "close") as close:
            with self.assertRaisesRegex(ssl.SSLError, "fingerprint does not match"):
                wrong.connect()
            close.assert_called_once()

        payload = {"report_hash": "a" * 64, "report_markdown": "fixture"}
        response = MagicMock()
        response.status = 202
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        with patch("feedback.build_opener", return_value=opener) as build:
            self.assertEqual(202, send_feedback(payload, "https://feedback.example.test/feedback",
                                                "token", fingerprint.upper()))
        self.assertTrue(any(isinstance(item, PinnedHTTPSHandler) for item in build.call_args.args))
        with self.assertRaisesRegex(ValueError, "64 hexadecimal digits"):
            send_feedback(payload, "https://feedback.example.test/feedback", "token", "bad-pin")

    def test_feedback_reads_private_token_file(self) -> None:
        from unittest.mock import patch

        token_file = self.db.parent / "feedback-token"
        token_file.write_text("fixture-token\n", encoding="utf-8")
        token_file.chmod(0o600)
        self.assertEqual("fixture-token", read_token("UNSET_FEEDBACK_TOKEN", token_file))
        config_path = self.db.parent / "feedback-file-config.json"
        configure_feedback(config_path, "https://feedback.example.test/feedback",
                           "UNSET_FEEDBACK_TOKEN", token_file=token_file)
        self.assertEqual(str(token_file), load_feedback_config(config_path)["token_file"])
        if sys.platform != "win32":
            token_file.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "mode 600"):
                read_token("UNSET_FEEDBACK_TOKEN", token_file)
            token_file.chmod(0o600)
        token_file.write_text("invalid token\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "malformed"):
            read_token("UNSET_FEEDBACK_TOKEN", token_file)
        token_file.write_text("fixture-token\n", encoding="utf-8")
        with patch.dict("os.environ", {"UNSET_FEEDBACK_TOKEN": "other-token"}):
            self.assertEqual("fixture-token", read_token("UNSET_FEEDBACK_TOKEN", token_file))

    def test_feedback_bundled_distribution_uploads_without_user_configuration(self) -> None:
        from unittest.mock import patch

        report_dir = self.db.parent / "bundled-report"
        markdown = initialize_report(self.db, report_dir)
        report = fixture_report()
        report["post_run_review"]["coverage"] = f"采集包 SHA-256 {self.result['metadata']['source_sha256']}"
        json_path = report_dir / "report.json"
        json_path.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
        deployment = self.db.parent / "deployment"
        deployment.mkdir()
        bundled_config = deployment / "feedback.json"
        bundled_config.write_text(json.dumps({
            "version": 1, "scope": "full_reports_with_hostname", "enabled": True,
            "consented_at": "2026-10-08T00:00:00+00:00",
            "endpoint": "https://feedback.example.test/feedback",
            "token_env": "SILVERFOX_FEEDBACK_TOKEN", "token_file": "token",
            "analyst_id": None, "cert_sha256": "a" * 64,
        }), encoding="utf-8")
        token_file = deployment / "token"
        token_file.write_text("fixture-token\n", encoding="utf-8")
        token_file.chmod(0o644)
        user_config = self.db.parent / "user-settings" / "feedback.json"
        with patch("feedback.BUNDLED_CONFIG", bundled_config):
            with patch("feedback.send", return_value=200) as send:
                result = submit_if_enabled(user_config, self.db, markdown, json_path)
            self.assertTrue(result["submitted"])
            self.assertEqual("fixture-token", send.call_args.args[2])
            self.assertEqual("a" * 64, send.call_args.args[3])
            if sys.platform != "win32":
                self.assertEqual(0o600, token_file.stat().st_mode & 0o777)
            disable_feedback(user_config)
            with patch("feedback.send") as send:
                self.assertFalse(submit_if_enabled(user_config, self.db, markdown,
                                                   json_path)["submitted"])
                send.assert_not_called()

    def test_private_distribution_contains_skill_and_bundled_feedback(self) -> None:
        token_file = self.db.parent / "source-token"
        token_file.write_text("fixture-token\n", encoding="utf-8")
        token_file.chmod(0o600)
        output = self.db.parent / "private-skill.zip"
        with self.assertRaisesRegex(ValueError, "prior informed consent"):
            build_distribution(output, token_file, "https://feedback.example.test/feedback",
                               "a" * 64, consent_acknowledged=False)
        result = build_distribution(output, token_file,
                                    "https://feedback.example.test/feedback", "a" * 64,
                                    consent_acknowledged=True)
        self.assertTrue(result["contains_shared_token"])
        if sys.platform != "win32":
            self.assertEqual(0o600, output.stat().st_mode & 0o777)
        with ZipFile(output) as archive:
            self.assertIsNone(archive.testzip())
            config = json.loads(archive.read("silver-fox-local/deployment/feedback.json"))
            self.assertTrue(config["enabled"])
            self.assertEqual("token", config["token_file"])
            self.assertEqual(b"fixture-token\n",
                             archive.read("silver-fox-local/deployment/token"))
            self.assertIn("silver-fox-local/SKILL.md", archive.namelist())
            self.assertIn("silver-fox-local/scripts/feedback.py", archive.namelist())


if __name__ == "__main__":
    unittest.main()
