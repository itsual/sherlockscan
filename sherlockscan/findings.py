"""Stable, explainable findings shared by all report formats."""

from __future__ import annotations

import hashlib
import re

DISCLAIMER = (
    "A finding indicates potential risk; it does not prove maliciousness. A clean scan does not prove safety."
)
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Trigger-specific guidance, rather than a single generic warning.
GUIDANCE = {
    "EXEC": (
        "Dynamic code execution",
        "HIGH",
        "MEDIUM",
        "Evaluates or compiles code at runtime.",
        "Interpreters, template engines and generated numerical kernels use dynamic code.",
        "Trace the code argument to its source; check validation and whether untrusted input reaches execution.",
    ),
    "SHELL": (
        "Process execution",
        "MEDIUM",
        "MEDIUM",
        "Starts an external process or shell command.",
        "Build tools, command wrappers and scientific workloads legitimately launch processes.",
        "Inspect executable paths and arguments; check shell=True and input validation.",
    ),
    "PICKLE": (
        "Model deserialization",
        "HIGH",
        "MEDIUM",
        "Loads an object format that can execute Python during deserialization.",
        "Trusted local model caches and legacy scientific workflows use pickle-based formats.",
        "Verify the model source and integrity; prefer restricted loaders or non-executable formats.",
    ),
    "TORCH": (
        "PyTorch loader policy",
        "MEDIUM",
        "LOW",
        "A PyTorch loader uses unsafe or statically unresolved options.",
        "Legacy checkpoints may require custom classes or explicitly trusted object loading.",
        "Check the supported PyTorch versions, weights_only and pickle_module; verify checkpoint provenance.",
    ),
    "NUMPY": (
        "NumPy pickle loading",
        "HIGH",
        "MEDIUM",
        "NumPy loading enables pickle, or its options cannot be resolved statically.",
        "Trusted object arrays may require pickle support.",
        "Check allow_pickle and positional options; verify the array source before loading object arrays.",
    ),
    "NETWORK": (
        "Network capability",
        "INFO",
        "HIGH",
        "Imports a networking library or makes an outbound call.",
        "API clients, dataset downloads and telemetry clients need networking.",
        "Inspect destinations and transmitted fields; check whether calls occur during import.",
    ),
    "ENV": (
        "Environment access",
        "INFO",
        "HIGH",
        "Reads environment configuration that may contain credentials.",
        "Cloud SDKs and applications commonly read configuration and tokens from the environment.",
        "Check which values are read and where they are subsequently passed; access alone is not exfiltration.",
    ),
    "IMPORT": (
        "Noteworthy capability",
        "INFO",
        "HIGH",
        "Imports a library with dynamic loading, serialization or process capabilities.",
        "These libraries are routinely used by legitimate developer and scientific tools.",
        "Inspect actual calls and input provenance; an import does not establish unsafe behavior.",
    ),
    "PTH": (
        "Python startup hook",
        "HIGH",
        "HIGH",
        "An import line in a .pth file can execute at Python startup when processed by site.",
        "Namespace-package support and editable installations sometimes use startup hooks.",
        "Inspect the full hook and imported module; check why startup execution is required.",
    ),
    "SECRET": (
        "Potential hardcoded secret",
        "HIGH",
        "MEDIUM",
        "Source matches a configured credential pattern.",
        "Documentation, test fixtures and placeholder credentials can resemble live secrets.",
        "Determine whether it is a real credential without posting it publicly; revoke and rotate if exposed.",
    ),
    "ENTROPY": (
        "Encoded or high-entropy literal",
        "LOW",
        "LOW",
        "A literal has unusually high entropy or contains a recognized encoding.",
        "Hashes, embedded assets, compressed datasets and certificates are often high entropy.",
        "Inspect the decoded content and how it is used; encoding alone is not malicious.",
    ),
    "KEYWORD": (
        "Configured source pattern",
        "LOW",
        "LOW",
        "Source contains a configured review keyword or pattern.",
        "Comments and examples often describe risks without performing them.",
        "Review the matching context and determine whether executable code is affected.",
    ),
    "DEPENDENCY": (
        "Dependency policy violation",
        "HIGH",
        "HIGH",
        "A declared dependency conflicts with the configured dependency policy.",
        "The policy may be outdated or unsuitable for this project.",
        "Review the full requirement, environment marker, extras and policy rationale.",
    ),
    "BUILD": (
        "Custom build configuration",
        "MEDIUM",
        "MEDIUM",
        "The project declares custom build behavior.",
        "Compiled extensions and generated source often require custom build hooks.",
        "Inspect the declared backend and hooks in isolation before invoking a build.",
    ),
}


def redact(text: str) -> str:
    """Conservatively remove literal values from displayed source and payloads."""
    return re.sub(r"""("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')""", '"[REDACTED]"', text)


def redact_url_credentials(text: str) -> str:
    text = re.sub(r"(https?://)[^/@\s]+@", r"\1[REDACTED]@", text)
    return re.sub(
        r"(?i)([?&](?:token|key|password|secret|signature|credential)=)[^&#\s]+", r"\1[REDACTED]", text
    )


def make_finding(
    kind,
    path,
    line,
    snippet,
    *,
    detail="",
    severity=None,
    confidence=None,
    context="UNKNOWN",
    suffix="",
    evidence=None,
):
    title, level, certainty, why, legitimate, investigate = GUIDANCE[kind]
    rule = f"SHLK-{kind}" + (f"-{suffix}" if suffix else "")
    # Hash original evidence internally, never place literal secrets in reports.
    normalized = " ".join(snippet.split())
    identity = f"{rule}\0{path}\0{normalized}"
    fingerprint = hashlib.sha256(identity.encode()).hexdigest()
    return {
        "rule_id": rule,
        "type": title,
        "severity": severity or level,
        "confidence": confidence or certainty,
        "file_path": path,
        "line_number": line,
        "code_snippet": redact_url_credentials(redact(snippet))[:1000],
        "message": why + (" " + detail if detail else ""),
        "why_flagged": why,
        "legitimate_uses": legitimate,
        "investigation": investigate,
        "execution_context": context,
        "fingerprint": fingerprint,
        "suppressed": False,
        "evidence": evidence or {},
    }


def summary(findings):
    return {
        "total_findings": len(findings),
        "by_severity": {level: sum(f["severity"] == level for f in findings) for level in SEVERITIES},
    }
