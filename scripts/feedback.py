#!/usr/bin/env python3
"""Submit completed Silver Fox reports using the deployed feedback configuration."""

from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import sqlite3
import ssl
import stat
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from evidence import readonly_connection
from report_bundle import check


MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_REQUEST_BYTES = 10 * 1024 * 1024
CONFIG_VERSION = 1
CONSENT_SCOPE = "full_reports_with_hostname"
BUNDLED_CONFIG = Path(__file__).resolve().parents[1] / "deployment" / "feedback.json"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def normalize_cert_sha256(fingerprint: str | None) -> str | None:
    if fingerprint is None:
        return None
    normalized = fingerprint.replace(":", "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", normalized):
        raise ValueError("certificate SHA-256 fingerprint must contain 64 hexadecimal digits")
    return normalized


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, fingerprint: str, **kwargs):
        self.fingerprint = normalize_cert_sha256(fingerprint)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        super().__init__(host, context=context, **kwargs)

    def connect(self) -> None:
        super().connect()
        certificate = self.sock.getpeercert(binary_form=True)
        actual = hashlib.sha256(certificate).hexdigest() if certificate else ""
        if not hmac.compare_digest(actual, self.fingerprint):
            self.close()
            raise ssl.SSLError("feedback server certificate fingerprint does not match")


class PinnedHTTPSHandler(HTTPSHandler):
    def __init__(self, fingerprint: str):
        super().__init__()
        self.fingerprint = normalize_cert_sha256(fingerprint)

    def https_open(self, request):
        return self.do_open(
            lambda host, **kwargs: PinnedHTTPSConnection(host, self.fingerprint, **kwargs),
            request,
        )


def _hostname(db_path: Path) -> str | None:
    with closing(readonly_connection(db_path)) as connection:
        row = connection.execute(
            "SELECT hostname FROM system_infos WHERE hostname IS NOT NULL "
            "AND TRIM(hostname) != '' ORDER BY id LIMIT 1"
        ).fetchone()
    return row[0] if row else None


def prepare(db_path: Path, markdown: Path, json_path: Path, *,
            customer: str | None = None, analyst_id: str | None = None,
            hostname: str | None = None,
            now: datetime | None = None) -> dict:
    checked = check(db_path, markdown, json_path)
    if not checked["json_source_sha256_present"]:
        raise ValueError("JSON coverage must state the matching source SHA-256 before submission")
    markdown_bytes = markdown.read_bytes()
    json_bytes = json_path.read_bytes()
    if len(markdown_bytes) + len(json_bytes) > MAX_REPORT_BYTES:
        raise ValueError("combined report exceeds the 8 MiB feedback limit")
    report_json = json.loads(json_bytes)
    submitted_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return {
        "schema_version": "silverfox-feedback/v1",
        "skill": "silver-fox-local",
        "status": "success",
        "report_hash": hashlib.sha256(markdown_bytes + b"\0" + json_bytes).hexdigest(),
        "submitted_at": submitted_at.isoformat(timespec="seconds"),
        "source_sha256": checked["source_sha256"],
        "customer": customer or None,
        "hostname": hostname or _hostname(db_path),
        "analyst_id": analyst_id or None,
        "report_markdown": markdown_bytes.decode("utf-8"),
        "report_json": report_json,
    }


def preview(payload: dict) -> dict:
    return {
        "schema_version": payload["schema_version"],
        "skill": payload["skill"],
        "status": payload["status"],
        "submitted_at": payload["submitted_at"],
        "source_sha256": payload["source_sha256"],
        "report_hash": payload["report_hash"],
        "customer": payload["customer"],
        "hostname": payload["hostname"],
        "analyst_id": payload["analyst_id"],
        "markdown_bytes": len(payload["report_markdown"].encode("utf-8")),
        "json_bytes": len(json.dumps(payload["report_json"], ensure_ascii=False).encode("utf-8")),
        "contains_full_reports": True,
    }


def validate_endpoint(endpoint: str) -> None:
    url = urlsplit(endpoint)
    if (url.scheme != "https" or not url.hostname or url.username or url.password
            or url.query or url.fragment):
        raise ValueError("endpoint must be an HTTPS URL without credentials, query, or fragment")


def default_config_path() -> Path:
    override = os.environ.get("SILVERFOX_FEEDBACK_CONFIG")
    if override:
        return Path(override).expanduser()
    base = (Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
            if os.name == "nt" else Path.home() / ".config")
    return base / "silver-fox-local" / "feedback.json"


def load_config(path: Path) -> dict | None:
    if not path.exists():
        return None
    config = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(config, dict) or type(config.get("version")) is not int
            or config["version"] != CONFIG_VERSION
            or config.get("scope") != CONSENT_SCOPE
            or not isinstance(config.get("enabled"), bool)
            or not isinstance(config.get("consented_at"), str)
            or not config["consented_at"]):
        raise ValueError("feedback configuration has an unsupported consent record")
    try:
        consented_at = datetime.fromisoformat(config["consented_at"])
    except ValueError as exc:
        raise ValueError("feedback configuration has an invalid consent time") from exc
    if consented_at.tzinfo is None:
        raise ValueError("feedback configuration has an invalid consent time")
    if not isinstance(config.get("endpoint"), str):
        raise ValueError("feedback configuration has no HTTPS endpoint")
    validate_endpoint(config["endpoint"])
    if not isinstance(config.get("token_env"), str) or not config["token_env"]:
        raise ValueError("feedback configuration has no token environment variable")
    token_file = config.get("token_file")
    if token_file is not None and (not isinstance(token_file, str) or not token_file):
        raise ValueError("feedback configuration has an invalid token file")
    config["cert_sha256"] = normalize_cert_sha256(config.get("cert_sha256"))
    return config


def effective_config(path: Path) -> tuple[dict | None, Path | None]:
    config = load_config(path)
    if config is not None:
        return config, path
    config = load_config(BUNDLED_CONFIG)
    return config, BUNDLED_CONFIG if config is not None else None


def config_token_file(config: dict, config_path: Path) -> Path | None:
    value = config.get("token_file")
    if not value:
        return None
    file_path = Path(value).expanduser()
    return file_path if file_path.is_absolute() else config_path.parent / file_path


def read_token(token_env: str, token_file: Path | None = None) -> str:
    if token_file is None:
        token = os.environ.get(token_env, "")
    else:
        token_file = token_file.expanduser()
        if token_file.is_symlink():
            raise ValueError("feedback token file must not be a symbolic link")
        descriptor = os.open(token_file, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("feedback token file must be a regular file")
            if os.name != "nt" and info.st_mode & 0o077:
                raise ValueError("feedback token file must have mode 600 or stricter")
            token = stream.read().rstrip("\r\n")
    if not token or any(character.isspace() for character in token):
        raise ValueError("feedback token is missing or malformed")
    return token


def _write_config(path: Path, config: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent,
                                         prefix=".feedback-", delete=False) as stream:
            temporary = Path(stream.name)
            os.chmod(temporary, 0o600)
            json.dump(config, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def configure(path: Path, endpoint: str, token_env: str,
              analyst_id: str | None = None,
              cert_sha256: str | None = None,
              token_file: Path | None = None) -> dict:
    validate_endpoint(endpoint)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token_env):
        raise ValueError("token environment variable name is invalid")
    config = {
        "version": CONFIG_VERSION,
        "scope": CONSENT_SCOPE,
        "enabled": True,
        "consented_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "endpoint": endpoint,
        "token_env": token_env,
        "token_file": str(token_file.expanduser().absolute()) if token_file else None,
        "analyst_id": analyst_id or None,
        "cert_sha256": normalize_cert_sha256(cert_sha256),
    }
    _write_config(path, config)
    return config


def disable(path: Path) -> dict:
    config, _ = effective_config(path)
    if config is None:
        raise ValueError("feedback is not configured")
    config["enabled"] = False
    _write_config(path, config)
    return config


def send(payload: dict, endpoint: str, token: str,
         cert_sha256: str | None = None) -> int:
    validate_endpoint(endpoint)
    if not token:
        raise ValueError("feedback token is missing")
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_REQUEST_BYTES:
        raise ValueError("feedback request exceeds the 10 MiB limit")
    request = Request(endpoint, data=body, method="POST", headers={
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": "Bearer " + token,
        "Idempotency-Key": payload["report_hash"],
    })
    fingerprint = normalize_cert_sha256(cert_sha256)
    handlers = [NoRedirect()]
    if fingerprint:
        handlers.append(PinnedHTTPSHandler(fingerprint))
    with build_opener(*handlers).open(request, timeout=15) as response:
        status = response.status
    if status < 200 or status >= 300:
        raise ValueError(f"feedback endpoint returned HTTP {status}")
    return status


def submit_report(config_path: Path, db_path: Path, markdown: Path,
                  json_path: Path, *, customer: str | None = None,
                  hostname: str | None = None, analyst_id: str | None = None,
                  require_config: bool = True) -> dict:
    config, source_path = effective_config(config_path)
    if config is None:
        if require_config:
            raise ValueError("default report submission requires the deployed feedback configuration; "
                             "use the ready-to-use distribution ZIP or configure the receiver")
        return {"submitted": False, "reason": "not_configured"}
    if not config["enabled"]:
        return {"submitted": False, "reason": "disabled_by_user"}
    payload = prepare(db_path, markdown, json_path, customer=customer, hostname=hostname,
                      analyst_id=analyst_id or config.get("analyst_id"))
    token_file = config_token_file(config, source_path)
    if source_path == BUNDLED_CONFIG and token_file and os.name != "nt":
        if token_file.is_symlink():
            raise ValueError("feedback token file must not be a symbolic link")
        token_file.chmod(0o600)
    status = send(payload, config["endpoint"], read_token(config["token_env"], token_file),
                  config.get("cert_sha256"))
    return {"submitted": True, "http_status": status,
            "report_hash": payload["report_hash"]}


def submit_if_enabled(config_path: Path, db_path: Path, markdown: Path,
                      json_path: Path, *, customer: str | None = None,
                      hostname: str | None = None, analyst_id: str | None = None) -> dict:
    """Compatibility entry point for deployments using the older optional command."""
    return submit_report(config_path, db_path, markdown, json_path, customer=customer,
                         hostname=hostname, analyst_id=analyst_id, require_config=False)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("submit", "preview", "send", "configure", "status",
                                            "disable", "submit-if-enabled"))
    parser.add_argument("--db", type=Path)
    parser.add_argument("--markdown", type=Path)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--config", type=Path, default=default_config_path())
    parser.add_argument("--customer")
    parser.add_argument("--hostname", help="override hostname detected from the evidence database")
    parser.add_argument("--analyst-id", help="explicit identifier supplied by the analyst or organization")
    parser.add_argument("--endpoint", help="HTTPS POST endpoint for send")
    parser.add_argument("--cert-sha256", help="independently verified server certificate SHA-256 fingerprint")
    parser.add_argument("--token-env", default="SILVERFOX_FEEDBACK_TOKEN")
    parser.add_argument("--token-file", type=Path,
                        help="private local file containing one token (mode 600 on Unix)")
    parser.add_argument("--consent-to-send", action="store_true",
                        help="confirm that this report may be sent to the named endpoint")
    parser.add_argument("--acknowledge-full-report-transfer", action="store_true",
                        help="record prior informed consent for automatic future submissions")
    args = parser.parse_args()
    try:
        if args.command == "configure":
            if not args.acknowledge_full_report_transfer or not args.endpoint:
                raise ValueError("configure requires --endpoint and --acknowledge-full-report-transfer")
            result = configure(args.config, args.endpoint, args.token_env, args.analyst_id,
                               args.cert_sha256, args.token_file)
        elif args.command == "status":
            result, source_path = effective_config(args.config)
            result = dict(result, configuration_source=str(source_path)) if result else {
                "enabled": False, "reason": "not_configured"}
        elif args.command == "disable":
            result = disable(args.config)
        else:
            if not args.db or not args.markdown or not args.json:
                raise ValueError(f"{args.command} requires --db, --markdown, and --json")
            if args.command in ("submit", "submit-if-enabled"):
                result = submit_report(args.config, args.db, args.markdown, args.json,
                                       customer=args.customer, hostname=args.hostname,
                                       analyst_id=args.analyst_id,
                                       require_config=args.command == "submit")
            else:
                if args.command == "send" and (not args.consent_to_send or not args.endpoint):
                    raise ValueError("send requires --endpoint and --consent-to-send")
                payload = prepare(args.db, args.markdown, args.json,
                                  customer=args.customer, analyst_id=args.analyst_id,
                                  hostname=args.hostname)
                if args.command == "preview":
                    result = preview(payload)
                else:
                    status = send(payload, args.endpoint, read_token(args.token_env, args.token_file),
                                  args.cert_sha256)
                    result = {"submitted": True, "http_status": status,
                              "report_hash": payload["report_hash"]}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except HTTPError as exc:
        print(f"feedback request failed: HTTP {exc.code}", file=sys.stderr)
    except URLError as exc:
        print(f"feedback request failed: {type(exc.reason).__name__}", file=sys.stderr)
    except (OSError, ValueError, KeyError, sqlite3.Error, UnicodeError) as exc:
        print(f"feedback error: {exc}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
