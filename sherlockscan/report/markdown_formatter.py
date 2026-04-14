#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# sherlockscan/report/markdown_formatter.py

import logging
from typing import List, Dict, Any, Optional
import datetime # Used only in test block

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define severity order for sorting findings
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]

def _format_summary_table(summary: Dict[str, Any]) -> str:
    """Formats the summary counts into a Markdown table."""
    if not summary or "by_severity" not in summary:
        return "No summary data available.\n"
        
    table = "| Severity   | Count |\n"
    table += "|------------|-------|\n"
    
    # Ensure all defined severities are present in the summary dict for consistent table rows
    severity_counts = summary.get("by_severity", {})
    total = 0
    for severity in SEVERITY_ORDER:
        count = severity_counts.get(severity, 0)
        if isinstance(count, int) and count >= 0: # Basic validation
             table += f"| {severity:<10} | {count:<5} |\n"
             total += count
        else:
             table += f"| {severity:<10} | {'N/A':<5} |\n" # Handle unexpected data

    # Add total row
    table += "| **Total** | **{:<5}** |\n".format(summary.get("total_findings", total)) # Use provided total if available
    
    return table

def _format_finding(finding: Dict[str, Any]) -> str:
    """Formats a single finding into a Markdown list item."""
    details = []
    severity = finding.get('severity', 'UNKNOWN')
    f_type = finding.get('type', 'Unknown Finding')
    message = finding.get('message', 'No details provided.')
    file_path = finding.get('file_path', 'N/A')
    line_number = finding.get('line_number')
    code_snippet = (finding.get('code_snippet') or '').strip()

    # Header for the finding
    details.append(f"### {f_type} (`{severity}`)")
    
    # Location
    location = f"`{file_path}`"
    if line_number:
        location += f":{line_number}"
    details.append(f"- **Location:** {location}")
    
    # Message
    details.append(f"- **Details:** {message}")
    
    # Code Snippet (if available)
    if code_snippet:
        # Basic language hinting for Python snippets
        lang_hint = "python" if file_path.endswith(".py") else ""
        details.append(f"- **Code Snippet:**\n  ``` {lang_hint}\n  {code_snippet}\n  ```")
        
    return "\n".join(details) + "\n" # Add extra newline for spacing


def format_report_markdown(
    package_name: str,
    package_version: Optional[str],
    findings: List[Dict[str, Any]],
    summary: Dict[str, Any], # Expects {'total_findings': int, 'by_severity': {'CRITICAL': int, ...}}
    overall_risk_level: str, # e.g., "HIGH", "CRITICAL"
    explanation: str
) -> str:
    """
    Formats the scan results into a Markdown string.

    Args:
        package_name: The name of the scanned package.
        package_version: The version of the scanned package (if available).
        findings: The list of individual finding dictionaries.
        summary: A dictionary summarizing finding counts.
        overall_risk_level: The calculated overall risk level string.
        explanation: The generated overall explanation string.

    Returns:
        A Markdown string representing the report.
    """
    logging.debug(f"Formatting report to Markdown for package: {package_name}")
    
    md_parts = []

    # --- Header ---
    md_parts.append(f"# SherlockScan Report: `{package_name}`")
    if package_version:
        md_parts.append(f"**Version:** {package_version}")
    # Consider adding timestamp here too
    # scan_timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    # md_parts.append(f"**Scan Time:** {scan_timestamp}")
    md_parts.append("\n---\n") # Separator

    # --- Overall Assessment ---
    md_parts.append("## Overall Risk Assessment")
    md_parts.append(f"**Risk Level:** `{overall_risk_level}`")
    md_parts.append(f"\n**Summary:**\n{explanation}")
    md_parts.append("\n---\n")

    # --- Summary Table ---
    md_parts.append("## Findings Summary")
    md_parts.append(_format_summary_table(summary))
    md_parts.append("\n---\n")

    # --- Detailed Findings ---
    md_parts.append("## Detailed Findings")
    if not findings:
        md_parts.append("No findings detected based on current rules.")
    else:
        # Sort findings by severity order
        try:
            sorted_findings = sorted(
                findings,
                key=lambda f: SEVERITY_ORDER.index(f.get('severity', 'UNKNOWN'))
            )
        except ValueError as e:
             logging.warning(f"Encountered unknown severity while sorting findings: {e}. Using original order.")
             sorted_findings = findings # Fallback to original order if sorting fails

        for finding in sorted_findings:
            md_parts.append(_format_finding(finding))
            
    return "\n".join(md_parts)


# Example Usage (for testing purposes)
if __name__ == '__main__':
    # Use the same sample data as in json_formatter.py test
    sample_package_name = "example-package"
    sample_package_version = "1.0.1-beta"
    sample_findings = [
        {
            "type": "Hardcoded Secret",
            "severity": "CRITICAL",
            "file_path": "example_package/secrets.py",
            "line_number": 10,
            "code_snippet": "API_KEY = \"sk_live_...\"",
            "message": "Hardcoded Stripe API Key detected."
        },
        {
            "type": "Risky Call",
            "severity": "HIGH",
            "file_path": "example_package/utils.py",
            "line_number": 55,
            "code_snippet": "result = eval(user_input)",
            "message": "Use of 'eval' detected. Executing arbitrary strings as code is highly dangerous."
        },
         {
            "type": "Keyword Match",
            "severity": "LOW",
            "file_path": "example_package/comments.py",
            "line_number": 23,
            "code_snippet": "# TODO: security fix needed here",
            "message": "Comment indicates a potential security task."
        }
    ]
    sample_summary = {
        "total_findings": 3,
        "by_severity": {
            "CRITICAL": 1,
            "HIGH": 1,
            "MEDIUM": 0,
            "LOW": 1,
            "INFO": 0
        }
    }
    sample_risk_level = "CRITICAL"
    sample_explanation = (
        "Package 'example-package' analysis resulted in an overall risk level of CRITICAL. "
        "Critical issues found: Package contains hardcoded secrets (e.g., API keys, passwords), "
        "uses potentially dangerous functions like eval/exec. "
        "Strongly recommend avoiding use and performing an immediate, thorough code audit if usage is unavoidable."
    )

    print(f"--- Generating Markdown Report for: {sample_package_name} ---")

    # Generate the Markdown report string
    markdown_output = format_report_markdown(
        package_name=sample_package_name,
        package_version=sample_package_version,
        findings=sample_findings,
        summary=sample_summary,
        overall_risk_level=sample_risk_level,
        explanation=sample_explanation
    )

    # Print the result
    print("\nFormatted Markdown Output:\n")
    print(markdown_output)

