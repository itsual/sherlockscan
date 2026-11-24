"""JSON, Markdown, HTML and SARIF reports from one finding model."""

from __future__ import annotations
import copy
import json
from html import escape as html_escape
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
        if f.get("cell_index"):
            # Notebook lines are cell-relative, so a SARIF region would imply the wrong JSON line.
            result["properties"].update(cell_index=f["cell_index"], cell_line=f["line_number"])
            result["message"]["text"] += f" (notebook cell {f['cell_index']}, line {f['line_number']})"
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": quote(f["file_path"], safe="/"),
                            "uriBaseId": "%SRCROOT%",
                        }
                    }
                }
            ]
        elif f.get("line_number"):
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


def _location(finding):
    if "cell_index" in finding:
        return f"{finding['file_path']} (cell {finding['cell_index']}, line {finding['line_number']})"
    return f"{finding['file_path']}:{finding['line_number'] or 'metadata'}"


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
            f"Location: {escape(_location(f))}",
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


def html_report(report):
    def esc(value):
        return html_escape(str(value))

    def items(values):
        return "<ul>" + "".join(f"<li>{esc(value)}</li>" for value in values) + "</ul>" if values else ""

    sections = []
    for finding in report["findings"]:
        title = f"{finding['severity']} · {finding['rule_id']} · {_location(finding)}"
        if finding["suppressed"]:
            title += " · Suppressed"
        rows = [
            ("Finding", finding["type"]),
            ("Trigger", finding["message"]),
            ("Context", finding["execution_context"]),
            ("Confidence", finding["confidence"]),
            ("Legitimate uses", finding["legitimate_uses"]),
            ("Investigate", finding["investigation"]),
            ("Fingerprint", finding["fingerprint"]),
        ]
        if finding.get("suppression"):
            rows.append(("Suppression reason", finding["suppression"]["reason"]))
        body = "".join(f"<dt>{esc(label)}</dt><dd>{esc(value)}</dd>" for label, value in rows)
        sections.append(
            f"<details><summary>{esc(title)}</summary><dl>{body}</dl>"
            f"<pre>{esc(finding['code_snippet'])}</pre></details>"
        )
    coverage = report["coverage"]
    correlations = [f"{value['file_path']}: {value['message']}" for value in report["correlations"]]
    return f"""<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>SherlockScan — {esc(report["package_name"])}</title>
<style>
body {{ font: 1rem/1.55 system-ui, sans-serif; color: #18263a; background: #f5f7fb;
        max-width: 64rem; margin: 2rem auto; padding: 0 1rem; overflow-wrap: anywhere; }}
details {{ background: white; border: 1px solid #ccd5e1; border-radius: .5rem;
           padding: .75rem 1rem; margin: .5rem 0; }}
summary {{ cursor: pointer; font-weight: 600; }}
dt {{ font-weight: 600; }}
dd {{ margin: 0 0 .45rem; }}
pre {{ white-space: pre-wrap; background: #edf1f7; padding: .75rem; }}
</style>
<main>
<h1>SherlockScan — {esc(report["package_name"])}</h1>
<p>{esc(report["disclaimer"])}</p>
<p><strong>{esc(report["status"])}</strong> · Detected {report["full_summary"]["total_findings"]}
 · Actionable {report["actionable_summary"]["total_findings"]} · Shown {report["summary"]["total_findings"]}</p>
<h2>Coverage</h2>
<p>{esc(coverage["dependency_scope"])} Files scanned: {coverage["files_scanned"]}.
 Excluded: {len(coverage["excluded_files"])}.</p>
{items(coverage["limitations"])}
<h2>Findings</h2>
{"".join(sections) or "<p>No findings matched the display criteria.</p>"}
<h2>Review notes</h2>
{items(report["warnings"] + correlations) or "<p>No review notes.</p>"}
</main>
</html>
"""


def render(report, format="json", minimum="INFO"):
    data = filtered_report(report, minimum)
    if format == "md":
        return markdown(data)
    if format == "html":
        return html_report(data)
    return json.dumps(sarif(data) if format == "sarif" else data, indent=2, ensure_ascii=False)
