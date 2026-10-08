#!/usr/bin/env python3
"""Build a private, ready-to-use Silver Fox skill ZIP for consented distribution."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

from feedback import (CONFIG_VERSION, CONSENT_SCOPE, normalize_cert_sha256,
                      read_token, validate_endpoint)


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = "silver-fox-local"


def _members() -> list[Path]:
    paths = [ROOT / name for name in ("AGENTS.md", "LICENSE", "README.md", "SKILL.md")]
    for directory, pattern in (("agents", "*.yaml"), ("references", "*"),
                               ("scripts", "*.py"), ("tests", "*.py")):
        paths.extend(sorted((ROOT / directory).glob(pattern)))
    for path in paths:
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"distribution input is missing or not a regular file: {path}")
    return paths


def _add(archive: ZipFile, name: str, content: bytes, mode: int) -> None:
    entry = ZipInfo(name)
    entry.create_system = 3
    entry.external_attr = (stat.S_IFREG | mode) << 16
    entry.compress_type = ZIP_DEFLATED
    archive.writestr(entry, content)


def build(output: Path, token_source: Path, endpoint: str, cert_sha256: str,
          *, consent_acknowledged: bool) -> dict:
    if not consent_acknowledged:
        raise ValueError("distribution requires prior informed consent for full report transfer")
    validate_endpoint(endpoint)
    fingerprint = normalize_cert_sha256(cert_sha256)
    if fingerprint is None:
        raise ValueError("private distribution requires a verified certificate fingerprint")
    output = output.expanduser().absolute()
    if output.is_relative_to(ROOT):
        raise ValueError("private distribution ZIP must be outside the public repository")
    if output.exists():
        raise FileExistsError(f"distribution ZIP already exists: {output}")
    token = read_token("SILVERFOX_FEEDBACK_TOKEN", token_source)
    files = _members()
    config = {
        "version": CONFIG_VERSION,
        "scope": CONSENT_SCOPE,
        "enabled": True,
        "consented_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "endpoint": endpoint,
        "token_env": "SILVERFOX_FEEDBACK_TOKEN",
        "token_file": "token",
        "analyst_id": None,
        "cert_sha256": fingerprint,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".silverfox-distribution-", suffix=".zip",
                                             dir=output.parent)
    os.close(descriptor)
    try:
        with ZipFile(temporary, "w") as archive:
            for path in files:
                relative = path.relative_to(ROOT).as_posix()
                _add(archive, f"{PACKAGE_ROOT}/{relative}", path.read_bytes(), 0o644)
            _add(archive, f"{PACKAGE_ROOT}/deployment/feedback.json",
                 (json.dumps(config, ensure_ascii=False, indent=2) + "\n").encode("utf-8"), 0o600)
            _add(archive, f"{PACKAGE_ROOT}/deployment/token",
                 (token + "\n").encode("utf-8"), 0o600)
        with ZipFile(temporary) as archive:
            if archive.testzip() is not None:
                raise ValueError("distribution ZIP integrity check failed")
        os.chmod(temporary, 0o600)
        os.replace(temporary, output)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {
        "archive": str(output),
        "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "files": len(files) + 2,
        "contains_shared_token": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--token-source", type=Path, required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--cert-sha256", required=True)
    parser.add_argument("--acknowledge-distribution-consent", action="store_true")
    args = parser.parse_args()
    try:
        result = build(args.output, args.token_source, args.endpoint, args.cert_sha256,
                       consent_acknowledged=args.acknowledge_distribution_consent)
    except (OSError, ValueError) as exc:
        print(f"distribution error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
