"""Public static scanning API. No target imports, build hooks or subprocesses."""

from __future__ import annotations

import ast
import hashlib
import re
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from . import __version__
from .context_scanner import scan_source
from .deobfuscator import decode_literal
from .findings import DISCLAIMER, SEVERITIES, make_finding, summary, redact_url_credentials
from .ingestor import Limits, ingest
from .policy import apply_suppressions, decision, load_suppressions
from .scanner.heuristics import calculate_entropy, load_risk_patterns
from .scanner.deps import load_approved_packages

SOURCE_LIMIT = 2 * 1024 * 1024


def _patterns(config_dir):
    path = config_dir / "risk_patterns.yaml"
    if not path.is_file():
        raise ValueError("Missing risk_patterns.yaml; heuristic scanning cannot be silently disabled")
    patterns = load_risk_patterns(str(path))
    ids = set()
    for group, field in (("regex_patterns", "pattern"), ("keywords", "keyword")):
        for entry in patterns[group]:
            if not isinstance(entry, dict) or not isinstance(entry.get(field), str) or not entry[field]:
                raise ValueError(f"Each {group} entry requires {field}")
            if entry.get("severity", "MEDIUM") not in SEVERITIES:
                raise ValueError("Unknown rule severity")
            identity = (
                entry.get("id")
                or hashlib.sha256((group + entry.get("name", "") + entry[field]).encode())
                .hexdigest()[:12]
                .upper()
            )
            if identity in ids or not re.fullmatch(r"[A-Z0-9-]+", identity):
                raise ValueError("Duplicate or invalid heuristic rule ID")
            ids.add(identity)
            entry["id"] = identity
            if field == "pattern":
                entry["compiled"] = re.compile(entry[field])
    return patterns


def _heuristics(source, path, patterns, *, decoded=False, line_override=None, chain=None):
    findings = []
    for number, line in enumerate(source.splitlines(), 1):
        if len(findings) > 10000:
            raise ValueError("Heuristic finding budget exceeded")
        for entry in patterns["regex_patterns"]:
            if entry["compiled"].search(line):
                secret = (
                    "secret" in entry.get("type", "").lower()
                    or "key" in entry.get("name", "").lower()
                    or "password" in entry.get("name", "").lower()
                )
                f = make_finding(
                    "SECRET" if secret else "KEYWORD",
                    path,
                    line_override or number,
                    "[potential credential omitted]"
                    if secret
                    else "[decoded payload omitted]"
                    if decoded
                    else line,
                    suffix=entry["id"],
                    severity=entry.get("severity", "MEDIUM"),
                    evidence={"decoded": decoded, "encoding_chain": chain or []},
                )
                findings.append(f)
        for entry in patterns["keywords"]:
            if entry["keyword"].lower() in line.lower():
                findings.append(
                    make_finding(
                        "KEYWORD",
                        path,
                        line_override or number,
                        "[decoded payload omitted]" if decoded else line,
                        suffix=entry["id"],
                        severity=entry.get("severity", "LOW"),
                        evidence={"decoded": decoded, "encoding_chain": chain or []},
                    )
                )
    return findings


def _torch_default(requirements):
    # Only infer the new default if every allowed version is constrained >=2.6.
    for raw in requirements:
        req = Requirement(raw)
        if canonicalize_name(req.name) == "torch" and not req.marker and not req.url:
            for spec in req.specifier:
                if spec.operator in {">=", ">", "==", "~="}:
                    from packaging.version import Version

                    try:
                        if Version(spec.version.rstrip(".*")) >= Version("2.6"):
                            return True
                    except ValueError:
                        pass
    return False


def scan_package(
    target: str,
    *,
    config_dir=None,
    include_tests=False,
    suppressions=None,
    fail_on=None,
    limits=Limits(),
    deobfuscation=True,
):
    """Return an auditable JSON-compatible report; configuration/input failures raise.

    status COMPLETE means all supported checks finished, never that a package is safe.
    Native code, dynamic metadata, parse failures and exceeded decode limits are explicit
    coverage gaps with exit_code 20. Dependencies are declared, not recursively scanned.
    """
    if fail_on is not None and fail_on not in SEVERITIES:
        raise ValueError("Invalid fail_on severity")
    config_dir = Path(config_dir) if config_dir else Path(__file__).parent / "config"
    patterns = _patterns(config_dir)
    policy = load_approved_packages(str(config_dir / "approved_packages.yaml"))
    entries = load_suppressions(Path(suppressions) if suppressions else None)
    pkg = ingest(target, limits)
    coverage = list(pkg.coverage)
    findings = []
    exclusions = []
    redactions = set()
    scanned = 0
    started = time.monotonic()
    torch_default = _torch_default(pkg.requirements)
    declared = list(pkg.requirements)
    declared += [r for group in pkg.dependency_groups.values() for r in group]
    for raw in declared:
        req = Requirement(raw)
        name = canonicalize_name(req.name)
        if name in policy["blocklist"] or (policy["enforce_allowlist"] and name not in policy["allowlist"]):
            findings.append(
                make_finding(
                    "DEPENDENCY",
                    pkg.metadata_source or "metadata",
                    None,
                    raw,
                    severity="CRITICAL" if name in policy["blocklist"] else "MEDIUM",
                    detail="Declared requirement; optional extras and markers have not been resolved for a target environment.",
                    evidence={"dependency_name": name},
                )
            )
    for path, data in sorted(pkg.files.items()):
        if len(findings) > 10000 or time.monotonic() - started > limits.seconds:
            coverage.append(
                "Scan time or finding-count budget exhausted; remaining files were not inspected."
            )
            break
        name = PurePosixPath(path).name
        if path.lower().endswith((".so", ".dll", ".pyd", ".dylib", ".exe", ".pyc")):
            coverage.append(f"Native/compiled code was not analyzed: {path}")
        if not include_tests and any(
            p in {"tests", "test", "testing", "integration", "docs", "examples"}
            for p in PurePosixPath(path).parts
        ):
            exclusions.append(path)
            continue
        if not path.endswith((".py", ".pth")) and name != "pyproject.toml":
            continue
        if len(data) > SOURCE_LIMIT:
            coverage.append(f"Source exceeds {SOURCE_LIMIT} byte parsing limit: {path}")
            continue
        try:
            # PEP 263 encodings, without importing or executing source.
            import io
            import tokenize

            encoding, _ = (
                tokenize.detect_encoding(io.BytesIO(data).readline) if path.endswith(".py") else ("utf-8", [])
            )
            source = data.decode(encoding)
            scanned += 1
            if path.endswith(".pth"):
                for line, text in enumerate(source.splitlines(), 1):
                    if text.startswith(("import ", "import\t")):
                        findings.append(make_finding("PTH", path, line, text, context="PYTHON_STARTUP"))
                continue
            if name == "pyproject.toml":
                import toml

                project = toml.loads(source)
                backend = project.get("build-system", {}).get("build-backend", "")
                custom = project.get("tool", {}).get("setuptools", {}).get("cmdclass")
                if (
                    custom
                    or project.get("build-system", {}).get("backend-path")
                    or (
                        backend
                        and backend
                        not in {
                            "setuptools.build_meta",
                            "setuptools.build_meta:__legacy__",
                            "flit_core.buildapi",
                            "hatchling.build",
                            "poetry.core.masonry.api",
                        }
                    )
                ):
                    findings.append(
                        make_finding(
                            "BUILD", path, None, "[custom build settings]", context="SETUP_OR_BUILD_SCRIPT"
                        )
                    )
                continue
            findings.extend(_heuristics(source, path, patterns))
            for entry in patterns["regex_patterns"]:
                for match in entry["compiled"].finditer(source):
                    if len(match.group()) >= 8:
                        redactions.add(match.group())
            ast_findings, tree = scan_source(source, path, torch_default=torch_default)
            findings.extend(ast_findings)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Constant) or not isinstance(node.value, (str, bytes)):
                    continue
                value = node.value
                text = value if isinstance(value, str) else value.decode("utf-8", "replace")
                entropy = calculate_entropy(text[:65536]) if len(text) >= 32 else 0
                if entropy > (patterns["settings"].get("entropy_threshold") or 100):
                    findings.append(
                        make_finding(
                            "ENTROPY",
                            path,
                            node.lineno,
                            "[literal omitted]",
                            evidence={"entropy": round(entropy, 3)},
                        )
                    )
                if deobfuscation and len(value) >= 8:
                    decoded, limited = decode_literal(value)
                    if limited:
                        coverage.append(f"Literal decoding budget exceeded: {path}:{node.lineno}")
                    for chain, payload in decoded:
                        decoded_text = payload.decode("utf-8", "replace")
                        for entry in patterns["regex_patterns"]:
                            for match in entry["compiled"].finditer(decoded_text):
                                if len(match.group()) >= 8:
                                    redactions.add(match.group())
                        findings.extend(
                            _heuristics(
                                decoded_text,
                                path,
                                patterns,
                                decoded=True,
                                line_override=node.lineno,
                                chain=chain,
                            )
                        )
        except (SyntaxError, UnicodeError, LookupError, ValueError, RecursionError) as exc:
            # Do not include exception source text, which may contain a credential.
            coverage.append(f"Source inspection failed ({type(exc).__name__}): {path}")
    if not scanned:
        coverage.append("No supported source files were inspected.")
    if not deobfuscation:
        coverage.append("Literal decoding was explicitly disabled.")
    # Evidence correlations are review hints only; never automatic attack verdicts.
    correlations = []
    for path in sorted({f["file_path"] for f in findings}):
        evidence = [f for f in findings if f["file_path"] == path]
        if any(f["rule_id"] == "SHLK-ENV" for f in evidence) and any(
            f["rule_id"] == "SHLK-NETWORK" for f in evidence
        ):
            correlations.append(
                {
                    "file_path": path,
                    "message": "Environment access and networking co-occur; data flow is unproven.",
                    "finding_fingerprints": [
                        f["fingerprint"] for f in evidence if f["rule_id"] in {"SHLK-ENV", "SHLK-NETWORK"}
                    ],
                }
            )
    # Keep repeated evidence on different lines, but merge identical detector output.
    findings = list({(f["fingerprint"], f["line_number"]): f for f in findings}.values())
    for finding in findings:
        for field in ("code_snippet", "message"):
            for secret in sorted(redactions, key=len, reverse=True):
                finding[field] = finding[field].replace(secret, "[REDACTED]")
    warnings = apply_suppressions(findings, entries)
    coverage = sorted(set(coverage))
    status, code = decision(findings, coverage, fail_on)
    active = [f for f in findings if not f["suppressed"]]
    return {
        "schema_version": "0.3",
        "scanner_version": __version__,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "package_name": pkg.name,
        "package_version": pkg.version,
        "artifact": pkg.artifact,
        "metadata_source": pkg.metadata_source,
        "requirements": [redact_url_credentials(r) for r in pkg.requirements],
        "optional_dependencies": {
            k: [redact_url_credentials(r) for r in v] for k, v in pkg.dependency_groups.items()
        },
        "status": status,
        "exit_code": code,
        "disclaimer": DISCLAIMER,
        "explanation": DISCLAIMER,
        "findings": findings,
        "full_summary": summary(findings),
        "summary": summary(findings),
        "actionable_summary": summary(active),
        "overall_risk_level": next(
            (s for s in SEVERITIES if any(f["severity"] == s for f in findings)), "INFO"
        ),
        "coverage": {
            "complete": not coverage,
            "limitations": coverage,
            "excluded_files": exclusions,
            "files_scanned": scanned,
            "dependency_scope": "Declared direct dependencies only; not a dependency graph audit.",
        },
        "warnings": warnings,
        "correlations": correlations,
    }
