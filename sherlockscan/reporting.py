"""JSON, Markdown and SARIF 2.1.0 from one versioned finding model."""

from __future__ import annotations
import copy
import json
from urllib.parse import quote
from .findings import SEVERITIES, summary


def filtered_report(report, minimum="INFO"):
    data = copy.deepcopy(report)
    data["findings"] = [
        f for f in data["findings"] if SEVERITIES.index(f["severity"]) <= SEVERITIES.index(minimum)
    ]
    data["summary"] = summary(data["findings"])
    return data


def sarif(report):
    rules, results = {}, []
    levels = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
    for f in report["findings"]:
        rule_id = f["rule_id"]
        rules[rule_id] = {
            "id": rule_id,
            "shortDescription": {"text": f["type"]},
            "fullDescription": {"text": f["why_flagged"]},
            "help": {"text": f["legitimate_uses"] + "\n" + f["investigation"]},
        }
        result = {
            "ruleId": rule_id,
            "level": levels[f["severity"]],
            "message": {"text": f["message"] + "\nInvestigate: " + f["investigation"]},
            "partialFingerprints": {"sherlockscan/v1": f["fingerprint"]},
            "properties": {"confidence": f["confidence"], "context": f["execution_context"]},
        }
        if f.get("line_number"):
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": quote(f["file_path"], safe="/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {"startLine": f["line_number"], "snippet": {"text": f["code_snippet"]}},
                    }
                }
            ]
        if f["suppressed"]:
            result["suppressions"] = [
                {"kind": "external", "status": "accepted", "justification": f["suppression"]["reason"]}
            ]
        results.append(result)
    notifications = [{"level": "warning", "message": {"text": s}} for s in report["coverage"]["limitations"]]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SherlockScan",
                        "version": report["scanner_version"],
                        "informationUri": "https://github.com/itsual/sherlockscan",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": report["coverage"]["complete"],
                        "toolExecutionNotifications": notifications,
                    }
                ],
                "properties": {
                    "disclaimer": report["disclaimer"],
                    "status": report["status"],
                    "artifact": report["artifact"],
                },
            }
        ],
    }


def markdown(report):
    def escape(value):
        return str(value).replace("<", "&lt;").replace(">", "&gt;").replace("`", "&#96;")

    lines = [
        f"# SherlockScan Report: {escape(report['package_name'])}",
        "",
        report["disclaimer"],
        "",
        f"Status: **{report['status']}**",
        f"Overall detected risk: {report['overall_risk_level']}",
        f"Detected: {report['full_summary']['total_findings']}; actionable: {report['actionable_summary']['total_findings']}; displayed: {report['summary']['total_findings']}",
        "",
        "## Coverage",
        report["coverage"]["dependency_scope"],
    ]
    lines += ["- " + escape(s) for s in report["coverage"]["limitations"]]
    if report["coverage"]["excluded_files"]:
        lines.append(f"Excluded test/docs/example files: {len(report['coverage']['excluded_files'])}")
    lines += ["", "## Findings"]
    for f in report["findings"]:
        lines += [
            "",
            f"### {f['rule_id']}: {escape(f['type'])} ({f['severity']})",
            f"Location: {escape(f['file_path'])}:{f['line_number'] or 'metadata'}",
            f"Confidence: {f['confidence']}; context: {f['execution_context']}",
            f"Suppressed: {f['suppressed']}",
            f"Trigger: {escape(f['message'])}",
            f"Legitimate uses: {escape(f['legitimate_uses'])}",
            f"Investigate: {escape(f['investigation'])}",
            f"Fingerprint: {f['fingerprint']}",
            "",
            "    " + escape(f["code_snippet"]).replace("\n", "\n    "),
        ]
        if f.get("suppression"):
            lines.append("Suppression reason: " + escape(f["suppression"]["reason"]))
    lines += ["", "## Review correlations"]
    lines += [escape(c["file_path"] + ": " + c["message"]) for c in report["correlations"]]
    lines += ["", "## Policy warnings"] + [escape(w) for w in report["warnings"]]
    return "\n".join(lines) + "\n"


def render(report, format="json", minimum="INFO"):
    data = filtered_report(report, minimum)
    if format == "md":
        return markdown(data)
    return json.dumps(sarif(data) if format == "sarif" else data, indent=2, ensure_ascii=False)
