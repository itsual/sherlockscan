"""Explicit CI decisions and auditable, narrowly scoped suppressions."""

from __future__ import annotations

from datetime import date
from pathlib import Path, PurePosixPath
import re
import yaml
from .findings import SEVERITIES


def load_suppressions(path: Path | None):
    if path is None:
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if (
        not isinstance(data, dict)
        or data.get("schema_version") != 1
        or not isinstance(data.get("suppressions"), list)
    ):
        raise ValueError("Suppressions require schema_version: 1 and a suppressions list")
    for entry in data["suppressions"]:
        if not isinstance(entry, dict) or set(entry) - {
            "rule_id",
            "path",
            "fingerprint",
            "reason",
            "expires",
        }:
            raise ValueError("Invalid suppression fields")
        if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
            raise ValueError("Each suppression requires a reason")
        if not isinstance(entry.get("rule_id"), str) or not re.fullmatch(
            r"SHLK-[A-Z0-9-]+", entry["rule_id"]
        ):
            raise ValueError("A suppression requires an exact rule_id")
        path_value = entry.get("path")
        fingerprint = entry.get("fingerprint")
        if not path_value and not fingerprint:
            raise ValueError("Scope each suppression to an exact relative path or fingerprint")
        if path_value and (
            not isinstance(path_value, str)
            or PurePosixPath(path_value).is_absolute()
            or any(c in path_value for c in "*?[]\\:")
            or ".." in PurePosixPath(path_value).parts
        ):
            raise ValueError("Suppression paths must be exact relative POSIX paths without wildcards")
        if fingerprint and (
            not isinstance(fingerprint, str) or not re.fullmatch("[a-f0-9]{64}", fingerprint)
        ):
            raise ValueError("Invalid finding fingerprint")
        if entry.get("expires"):
            date.fromisoformat(str(entry["expires"]))
    return data["suppressions"]


def apply_suppressions(findings, entries, today=None):
    today = today or date.today()
    matched = set()
    for finding in findings:
        for index, entry in enumerate(entries):
            if entry.get("expires") and date.fromisoformat(str(entry["expires"])) < today:
                continue
            if (
                entry["rule_id"] == finding["rule_id"]
                and (not entry.get("path") or entry["path"] == finding["file_path"])
                and (not entry.get("fingerprint") or entry["fingerprint"] == finding["fingerprint"])
            ):
                finding["suppressed"] = True
                finding["suppression"] = {k: str(v) for k, v in entry.items()}
                matched.add(index)
                break
    return [f"Suppression {i + 1} is expired or unmatched." for i in range(len(entries)) if i not in matched]


def decision(findings, coverage, fail_on=None):
    if coverage:
        return "INCOMPLETE", 20
    active = [f for f in findings if not f["suppressed"]]
    if fail_on and any(SEVERITIES.index(f["severity"]) <= SEVERITIES.index(fail_on) for f in active):
        return "POLICY_FAILED", 10
    return "COMPLETE", 0
