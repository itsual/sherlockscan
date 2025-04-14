#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# sherlockscan/scanner/explainer.py

import logging
from typing import List, Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Constants for Explanation Templates ---

# Mapping finding types to descriptive phrases (used for summarizing)
FINDING_TYPE_SUMMARY_PHRASES = {
    # Critical/High Severity Focus
    "Install Script Execution": "executes commands or code during installation",
    "Risky Call": "uses potentially dangerous functions like eval/exec",
    "Insecure Deserialization": "uses insecure deserialization methods (like pickle)",
    "Hardcoded Secret": "contains hardcoded secrets (e.g., API keys, passwords)",
    "Blocked Dependency": "depends on explicitly blocked packages",
    "Subprocess Execution": "can execute external commands", # If not install script
    # Medium/Lower Severity Focus
    "Install Script Custom Command": "uses custom installation commands",
    "Install Script Network": "may perform network operations during installation",
    "Network Activity": "performs network operations",
    "High Entropy": "contains high entropy strings, possibly indicating obfuscation",
    "Dynamic Loading": "uses dynamic code loading features",
    "Unapproved Dependency": "depends on packages not in the allowlist",
    "Install Script Custom Build": "uses a custom build backend",
    "Keyword Match": "contains suspicious keywords",
    "Security Comment": "has comments indicating security tasks or concerns",
    # Add more as needed
}

# Recommendations based on overall risk level
RISK_LEVEL_RECOMMENDATIONS = {
    "CRITICAL": "Strongly recommend avoiding use and performing an immediate, thorough code audit if usage is unavoidable.",
    "HIGH": "Recommend performing a careful code audit before use, focusing on the high-severity findings. Avoid use in production without review.",
    "MEDIUM": "Recommend reviewing the findings, especially medium-severity ones. Assess the risks in the context of your usage.",
    "LOW": "Appears relatively low-risk based on static analysis, but review informational findings for context.",
    "INFO": "No significant risks detected based on current static analysis rules.",
    "UNKNOWN": "Risk level could not be determined.",
}

# --- Explanation Generation ---

def generate_overall_explanation(
    findings: List[Dict[str, Any]],
    summary: Dict[str, Any], # Expects {'total_findings': int, 'by_severity': {'CRITICAL': int, ...}}
    package_name: str,
    overall_risk_level: str # e.g., "HIGH", "CRITICAL"
) -> str:
    """
    Generates a human-readable summary explanation based on scan findings.

    Args:
        findings: The list of individual finding dictionaries.
        summary: A dictionary summarizing finding counts by severity.
        package_name: The name of the scanned package.
        overall_risk_level: The calculated overall risk level string.

    Returns:
        A summary explanation string.
    """
    if not findings:
        return f"Package '{package_name}' analysis completed with no findings based on current rules. Risk level: LOW. {RISK_LEVEL_RECOMMENDATIONS['LOW']}"

    explanation_parts = []
    explanation_parts.append(f"Package '{package_name}' analysis resulted in an overall risk level of {overall_risk_level}.")

    # Summarize key issue types, prioritizing higher severity
    critical_issues = set()
    high_issues = set()
    medium_issues = set()

    for f in findings:
        severity = f.get("severity")
        f_type = f.get("type")
        phrase = FINDING_TYPE_SUMMARY_PHRASES.get(f_type)
        if not phrase: continue # Skip if no summary phrase defined

        if severity == "CRITICAL":
            critical_issues.add(phrase)
        elif severity == "HIGH":
            high_issues.add(phrase)
        elif severity == "MEDIUM":
            medium_issues.add(phrase)
            
    summary_statements = []
    if critical_issues:
        summary_statements.append(f"Critical issues found: Package {', '.join(sorted(critical_issues))}.")
    if high_issues:
        summary_statements.append(f"High severity issues found: Package {', '.join(sorted(high_issues))}.")
    if medium_issues and not critical_issues and not high_issues: # Only mention medium if no higher issues
         summary_statements.append(f"Medium severity issues found: Package {', '.join(sorted(medium_issues))}.")

    if summary_statements:
        explanation_parts.append(" ".join(summary_statements))
    else:
         # If only LOW/INFO findings exist
         explanation_parts.append("Main findings are informational or low severity.")

    # Add recommendation
    recommendation = RISK_LEVEL_RECOMMENDATIONS.get(overall_risk_level, RISK_LEVEL_RECOMMENDATIONS["UNKNOWN"])
    explanation_parts.append(recommendation)

    return " ".join(explanation_parts)


# --- (Optional) Refinement Function ---
# For MVP, messages from scanners might be sufficient.
# This could be expanded later for more nuanced explanations.
# def refine_finding_message(finding: Dict[str, Any]) -> str:
#     """ Refines the message of a single finding (potential future enhancement). """
#     return finding.get("message", "No details provided.")


# Example Usage (for testing purposes)
if __name__ == '__main__':

    # Scenario 1: High Risk
    findings_high = [
        {"type": "Hardcoded Secret", "severity": "CRITICAL", "message": "..."},
        {"type": "Install Script Execution", "severity": "CRITICAL", "message": "..."},
        {"type": "Network Activity", "severity": "MEDIUM", "message": "..."},
    ]
    summary_high = {"total_findings": 3, "by_severity": {"CRITICAL": 2, "HIGH": 0, "MEDIUM": 1, "LOW": 0, "INFO": 0}}
    explanation_high = generate_overall_explanation(findings_high, summary_high, "bad-package", "CRITICAL")
    print("--- Scenario: High Risk ---")
    print(explanation_high)
    print("-" * 25)

    # Scenario 2: Medium Risk (Unapproved Dep, High Entropy)
    findings_medium = [
        {"type": "Unapproved Dependency", "severity": "MEDIUM", "message": "..."},
        {"type": "High Entropy", "severity": "MEDIUM", "message": "..."},
        {"type": "Keyword Match", "severity": "LOW", "message": "..."},
    ]
    summary_medium = {"total_findings": 3, "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 2, "LOW": 1, "INFO": 0}}
    explanation_medium = generate_overall_explanation(findings_medium, summary_medium, "maybe-ok-package", "MEDIUM")
    print("--- Scenario: Medium Risk ---")
    print(explanation_medium)
    print("-" * 25)

    # Scenario 3: Low Risk
    findings_low = [
        {"type": "Install Script Custom Build", "severity": "INFO", "message": "..."},
    ]
    summary_low = {"total_findings": 1, "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 1}}
    explanation_low = generate_overall_explanation(findings_low, summary_low, "clean-package", "INFO") # Assuming INFO maps to LOW for overall message
    print("--- Scenario: Low Risk ---")
    print(explanation_low)
    print("-" * 25)
    
    # Scenario 4: No Findings
    findings_none = []
    summary_none = {"total_findings": 0, "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}}
    explanation_none = generate_overall_explanation(findings_none, summary_none, "empty-package", "LOW") # Assuming no findings -> LOW
    print("--- Scenario: No Findings ---")
    print(explanation_none)
    print("-" * 25)


