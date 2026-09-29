#!/usr/bin/env python3
"""Check the local runtime required by the Silver Fox skill."""

import json
from pathlib import Path
import platform
import shutil
import sqlite3
import sys
import tempfile
from zipfile import ZipFile, BadZipFile


REQUIRED_FILES = (
    "SKILL.md",
    "scripts/doctor.py",
    "scripts/evidence.py",
    "scripts/report_bundle.py",
    "scripts/validate_report.py",
    "references/local-data.md",
    "references/report-writing.md",
    "references/setup.md",
    "references/silverfox-analysis.md",
    "references/silverfox-report-v2.schema.json",
)


def check(input_path=None):
    root = Path(__file__).resolve().parents[1]
    errors = []
    if sys.version_info < (3, 10):
        errors.append("Python 3.10 or newer is required")
    for relative in REQUIRED_FILES:
        if not (root / relative).is_file():
            errors.append("missing skill file: " + relative)
    try:
        with sqlite3.connect(":memory:") as connection:
            connection.execute("SELECT json_extract('{\"ok\":1}', '$.ok')").fetchone()
    except sqlite3.Error as exc:
        errors.append("SQLite JSON functions are unavailable: " + str(exc))
    try:
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "utf8-check.txt").write_text("银狐", encoding="utf-8")
    except OSError as exc:
        errors.append("temporary files cannot be written: " + str(exc))

    inspected_input = None
    if input_path is not None:
        source = Path(input_path).expanduser()
        inspected_input = str(source.resolve())
        if not source.is_file():
            errors.append("input file does not exist: " + str(source))
        elif source.suffix.lower() == ".zip":
            try:
                with ZipFile(source) as archive:
                    matches = [item for item in archive.infolist()
                               if item.filename.replace("\\", "/").split("/")[-1].lower() == "investigation.jsonl"]
                    if len(matches) != 1:
                        errors.append("ZIP must contain exactly one investigation.jsonl")
            except (OSError, BadZipFile) as exc:
                errors.append("ZIP cannot be read: " + str(exc))
        elif source.suffix.lower() != ".jsonl":
            errors.append("input must be a ZIP or investigation.jsonl file")

    system = platform.system()
    if system == "Windows":
        command = "py -3" if shutil.which("py") else '"' + sys.executable + '"'
    elif system == "Darwin":
        command = "python3" if shutil.which("python3") else sys.executable
    else:
        command = Path(sys.executable).name
    return {
        "ok": not errors,
        "host_os": system,
        "python_version": platform.python_version(),
        "python_executable": sys.executable,
        "python_command_hint": command,
        "sqlite_version": sqlite3.sqlite_version,
        "skill_directory": str(root),
        "input": inspected_input,
        "errors": errors,
    }


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    input_path = None
    if len(sys.argv) == 3 and sys.argv[1] == "--input":
        input_path = sys.argv[2]
    elif len(sys.argv) != 1:
        print("usage: doctor.py [--input AVTOOL_ZIP_OR_JSONL]", file=sys.stderr)
        return 2
    result = check(input_path)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
